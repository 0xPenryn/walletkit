//! `IDKit` Wallet Bridge transport for proof requests and responses.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::time::Duration;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose, Engine as _};
use eyre::{bail, ensure, Context as _, Result};
use reqwest::{redirect::Policy, Client, Response};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::{Host, Url};
use world_id_core::requests::ProofRequest as CoreProofRequest;
use zeroize::Zeroizing;

const DEFAULT_BRIDGE_URL: &str = "https://bridge.worldcoin.org";
const MAX_BRIDGE_BODY_BYTES: usize = 16 * 1024 * 1024;
const MAX_CONNECTOR_URL_BYTES: usize = 16 * 1024;
const MAX_REQUEST_ID_BYTES: usize = 128;
const MAX_EXTENSION_NAME_BYTES: usize = 256;
const MAX_MEDIA_TYPE_BYTES: usize = 256;

/// One opaque, versioned extension transported beside a stock World proof.
///
/// `payload_json` remains a string so neither `IDKit` nor `WalletKit` rounds
/// large JSON integers or changes the bytes consumed by an extension prover.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BridgeExtension {
    /// Globally unique extension name.
    pub(super) name: String,
    /// Extension wire version.
    pub(super) version: u32,
    /// Media type of the JSON payload.
    pub(super) media_type: String,
    /// Exact JSON payload bytes represented as a UTF-8 string.
    pub(super) payload_json: String,
}

impl BridgeExtension {
    fn validate(&self) -> Result<()> {
        ensure!(
            !self.name.is_empty()
                && self.name.len() <= MAX_EXTENSION_NAME_BYTES
                && self.name.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')
                }),
            "invalid bridge extension name"
        );
        ensure!(self.version > 0, "bridge extension version must be nonzero");
        ensure!(
            !self.media_type.is_empty()
                && self.media_type.len() <= MAX_MEDIA_TYPE_BYTES
                && self.media_type.bytes().all(|byte| byte.is_ascii_graphic()),
            "invalid bridge extension media type"
        );
        ensure!(
            self.payload_json.len() <= MAX_BRIDGE_BODY_BYTES,
            "bridge extension payload is too large"
        );
        let _: Value = serde_json::from_str(&self.payload_json)
            .context("bridge extension payload_json is not valid JSON")?;
        Ok(())
    }
}

fn validate_extensions(extensions: &[BridgeExtension]) -> Result<()> {
    let mut names = BTreeSet::new();
    for extension in extensions {
        extension.validate()?;
        ensure!(
            names.insert(extension.name.as_str()),
            "duplicate bridge extension name: {}",
            extension.name
        );
    }
    Ok(())
}

pub(super) struct BridgeConnection {
    request_id: String,
    bridge_url: Url,
    key: Zeroizing<Vec<u8>>,
}

impl BridgeConnection {
    pub(super) fn parse(raw: &str) -> Result<Self> {
        ensure!(
            raw.len() <= MAX_CONNECTOR_URL_BYTES,
            "IDKit connector URL is too large"
        );
        let parsed = Url::parse(raw.trim()).context("parse IDKit connector URL")?;
        let mut request_type = None;
        let mut request_id = None;
        let mut bridge_url = None;
        let mut key = None;

        for (name, value) in parsed.query_pairs() {
            let destination = match name.as_ref() {
                "t" => &mut request_type,
                "i" => &mut request_id,
                "b" => &mut bridge_url,
                "k" => &mut key,
                _ => continue,
            };
            ensure!(
                destination.is_none(),
                "duplicate IDKit connector parameter: {name}"
            );
            *destination = Some(value.into_owned());
        }

        ensure!(
            request_type.as_deref() == Some("wld"),
            "connector URL is not a World ID request"
        );
        let request_id =
            request_id.ok_or_else(|| eyre::eyre!("missing bridge request ID"))?;
        ensure!(
            !request_id.is_empty()
                && request_id.len() <= MAX_REQUEST_ID_BYTES
                && request_id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric()
                        || matches!(byte, b'-' | b'_')),
            "invalid bridge request ID"
        );

        let bridge_url =
            Url::parse(bridge_url.as_deref().unwrap_or(DEFAULT_BRIDGE_URL))
                .context("parse bridge origin")?;
        validate_bridge_url(&bridge_url)?;

        let key = decode_base64(
            key.as_deref()
                .ok_or_else(|| eyre::eyre!("missing bridge encryption key"))?,
        )
        .context("decode bridge encryption key")?;
        ensure!(key.len() == 32, "bridge encryption key must be 32 bytes");

        Ok(Self {
            request_id,
            bridge_url,
            key: Zeroizing::new(key),
        })
    }

    pub(super) fn request_id(&self) -> &str {
        &self.request_id
    }

    fn endpoint(&self, kind: &str) -> Result<Url> {
        self.bridge_url
            .join(&format!("{kind}/{}", self.request_id))
            .context("build bridge endpoint")
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum BridgeEnvironment {
    Production,
    Staging,
    Sandbox,
}

impl BridgeEnvironment {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Production => "production",
            Self::Staging => "staging",
            Self::Sandbox => "sandbox",
        }
    }
}

#[derive(Deserialize)]
pub(super) struct BridgeRequest {
    proof_request: Option<Value>,
    world_request_json: Option<String>,
    #[serde(default)]
    request_extensions: Vec<BridgeExtension>,
    identity_attributes: Option<Vec<Value>>,
    #[serde(default)]
    require_user_presence: bool,
    environment: Option<BridgeEnvironment>,
}

impl BridgeRequest {
    pub(super) fn ensure_supported(
        &self,
        configured_environment: Option<&str>,
        mock_identity_attestation: bool,
        mock_user_presence: bool,
    ) -> Result<()> {
        ensure!(
            self.proof_request.is_some(),
            "bridge request does not contain a World ID 4 proof_request"
        );
        ensure!(
            self.request_extensions.is_empty(),
            "bridge request contains request_extensions; use `walletkit proof bridge-export`"
        );
        if self.has_identity_attributes() {
            ensure!(
                mock_identity_attestation,
                "bridge request contains identity attributes; pass --mock-identity-attestation to submit a development-only mock"
            );
        }
        if self.requires_user_presence() {
            ensure!(
                mock_user_presence,
                "bridge request requires user presence; pass --mock-user-presence to submit a development-only mock"
            );
        }
        self.ensure_environment(configured_environment)?;
        Ok(())
    }

    pub(super) fn ensure_composition_supported(
        &self,
        configured_environment: Option<&str>,
    ) -> Result<()> {
        ensure!(
            !self.has_identity_attributes(),
            "composition bridge requests cannot contain identity attributes"
        );
        ensure!(
            !self.requires_user_presence(),
            "composition bridge requests cannot require user presence"
        );
        ensure!(
            !self.request_extensions.is_empty(),
            "composition bridge request contains no request_extensions"
        );
        validate_extensions(&self.request_extensions)?;
        self.ensure_environment(configured_environment)?;
        self.exact_world_request_json()?;
        Ok(())
    }

    fn ensure_environment(&self, configured_environment: Option<&str>) -> Result<()> {
        if let Some(request_environment) = self.environment {
            ensure!(
                request_environment != BridgeEnvironment::Sandbox,
                "IDKit sandbox bridge requests are not supported by walletkit-cli"
            );
            if let Some(configured_environment) = configured_environment {
                ensure!(
                    request_environment
                        .as_str()
                        .eq_ignore_ascii_case(configured_environment),
                    "bridge request targets {} but walletkit-cli is configured for {}; rerun with --environment {}",
                    request_environment.as_str(),
                    configured_environment,
                    request_environment.as_str()
                );
            }
        }
        Ok(())
    }

    pub(super) const fn has_identity_attributes(&self) -> bool {
        self.identity_attributes.is_some()
    }

    pub(super) const fn requires_user_presence(&self) -> bool {
        self.require_user_presence
    }

    pub(super) fn proof_request(&self) -> Result<&Value> {
        self.proof_request.as_ref().ok_or_else(|| {
            eyre::eyre!("bridge request does not contain a proof_request")
        })
    }

    pub(super) fn exact_world_request_json(&self) -> Result<&str> {
        let exact = self.world_request_json.as_deref().ok_or_else(|| {
            eyre::eyre!("bridge request does not contain world_request_json")
        })?;
        ensure!(
            exact.len() <= MAX_BRIDGE_BODY_BYTES,
            "world_request_json is too large"
        );
        let parsed: Value =
            serde_json::from_str(exact).context("parse exact world_request_json")?;
        ensure!(
            &parsed == self.proof_request()?,
            "world_request_json does not semantically match proof_request"
        );
        Ok(exact)
    }

    pub(super) fn request_extensions(&self) -> Result<&[BridgeExtension]> {
        validate_extensions(&self.request_extensions)?;
        Ok(&self.request_extensions)
    }

    pub(super) fn bound_request_extension(
        &self,
        proof_request: &CoreProofRequest,
    ) -> Result<&BridgeExtension> {
        ensure!(
            proof_request.requests.len() == 1,
            "composition bridge request must contain exactly one proof request item"
        );
        let signal = proof_request.requests[0].signal.as_deref().ok_or_else(|| {
            eyre::eyre!(
                "composition bridge request item must bind an extension in its signal"
            )
        })?;
        let mut matching = self
            .request_extensions()?
            .iter()
            .filter(|extension| extension.payload_json.as_bytes() == signal);
        let extension = matching.next().ok_or_else(|| {
            eyre::eyre!(
                "no request extension payload_json exactly matches the proof request signal"
            )
        })?;
        ensure!(
            matching.next().is_none(),
            "multiple request extension payloads match the proof request signal"
        );
        Ok(extension)
    }

    pub(super) fn response_payload(
        &self,
        mut proof_response: Value,
        mock_identity_attestation: bool,
        mock_user_presence: bool,
    ) -> Result<Value> {
        let identity_attested =
            self.has_identity_attributes() && mock_identity_attestation;
        let user_presence_completed =
            self.requires_user_presence() && mock_user_presence;

        if self.has_identity_attributes() {
            ensure!(
                identity_attested,
                "identity attestation mock was not enabled"
            );
            let mut payload = serde_json::json!({
                "proof_response": proof_response,
                "identity_attested": true,
            });
            if user_presence_completed {
                payload
                    .as_object_mut()
                    .expect("bridge response envelope is an object")
                    .insert("user_presence_completed".to_string(), Value::Bool(true));
            }
            return Ok(payload);
        }

        if self.requires_user_presence() {
            ensure!(
                user_presence_completed,
                "user-presence mock was not enabled"
            );
            proof_response
                .as_object_mut()
                .ok_or_else(|| eyre::eyre!("proof response must be a JSON object"))?
                .insert("user_presence_completed".to_string(), Value::Bool(true));
        }

        Ok(proof_response)
    }
}

pub(super) fn extension_response_payload(
    proof_response: &Value,
    extension_responses: &[BridgeExtension],
) -> Result<Value> {
    validate_extensions(extension_responses)?;
    Ok(serde_json::json!({
        "proof_response": proof_response,
        "extension_responses": extension_responses,
    }))
}

pub(super) fn validate_extension_responses(
    request_extensions: &[BridgeExtension],
    response_extensions: &[BridgeExtension],
) -> Result<()> {
    validate_extensions(request_extensions)?;
    validate_extensions(response_extensions)?;
    ensure!(
        request_extensions.len() == response_extensions.len(),
        "extension response names do not exactly match the request"
    );
    for requested in request_extensions {
        let response = response_extensions
            .iter()
            .find(|candidate| candidate.name == requested.name)
            .ok_or_else(|| {
                eyre::eyre!(
                    "missing response for requested extension {}",
                    requested.name
                )
            })?;
        ensure!(
            response.version == requested.version,
            "extension response version mismatch for {}",
            requested.name
        );
        ensure!(
            response.media_type == requested.media_type,
            "extension response media type mismatch for {}",
            requested.name
        );
    }
    Ok(())
}

#[derive(Debug, Deserialize, Serialize)]
struct EncryptedBridgeMessage {
    iv: String,
    payload: String,
}

pub(super) fn http_client() -> Result<Client> {
    Client::builder()
        .redirect(Policy::none())
        .timeout(Duration::from_secs(30))
        .user_agent(concat!("walletkit-cli/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("build bridge HTTP client")
}

pub(super) async fn fetch_request(
    client: &Client,
    connection: &BridgeConnection,
) -> Result<BridgeRequest> {
    let response = client
        .get(connection.endpoint("request")?)
        .send()
        .await
        .context("fetch encrypted bridge request")?;
    let raw = response_body(response, "bridge request").await?;
    let encrypted: EncryptedBridgeMessage =
        serde_json::from_slice(&raw).context("parse encrypted bridge request")?;
    let plaintext =
        decrypt_message(connection.key.as_slice(), &encrypted.iv, &encrypted.payload)?;
    serde_json::from_slice(plaintext.as_slice())
        .context("parse decrypted bridge request")
}

pub(super) async fn send_response(
    client: &Client,
    connection: &BridgeConnection,
    payload: &Value,
) -> Result<()> {
    let plaintext = Zeroizing::new(
        serde_json::to_vec(payload).context("serialize bridge proof response")?,
    );
    ensure!(
        plaintext.len() <= MAX_BRIDGE_BODY_BYTES,
        "bridge proof response is too large"
    );
    let encrypted = encrypt_message(connection.key.as_slice(), plaintext.as_slice())?;
    let response = client
        .put(connection.endpoint("response")?)
        .json(&encrypted)
        .send()
        .await
        .context("submit encrypted bridge response")?;
    ensure!(
        response.status().is_success(),
        "bridge submission failed with HTTP {}",
        response.status()
    );
    Ok(())
}

async fn response_body(
    mut response: Response,
    operation: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(
        response.status().is_success(),
        "{operation} failed with HTTP {}",
        response.status()
    );
    if let Some(length) = response.content_length() {
        ensure!(
            length <= MAX_BRIDGE_BODY_BYTES as u64,
            "{operation} response is too large"
        );
    }
    let mut raw = Zeroizing::new(Vec::new());
    while let Some(chunk) = response.chunk().await.context("read bridge response")? {
        ensure!(
            chunk.len() <= MAX_BRIDGE_BODY_BYTES - raw.len(),
            "{operation} response is too large"
        );
        raw.extend_from_slice(&chunk);
    }
    Ok(raw)
}

fn validate_bridge_url(url: &Url) -> Result<()> {
    let is_loopback_http = url.scheme() == "http"
        && match url.host() {
            Some(Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
            Some(Host::Ipv4(address)) => IpAddr::V4(address).is_loopback(),
            Some(Host::Ipv6(address)) => IpAddr::V6(address).is_loopback(),
            None => false,
        };
    ensure!(
        url.scheme() == "https" || is_loopback_http,
        "bridge URL must use HTTPS; HTTP is allowed only for loopback"
    );
    ensure!(url.host_str().is_some(), "bridge URL must include a host");
    ensure!(
        url.username().is_empty() && url.password().is_none(),
        "bridge URL must not contain credentials"
    );
    if url.scheme() == "https" {
        ensure!(
            url.port().is_none(),
            "HTTPS bridge URL must use the default port"
        );
    }
    ensure!(
        matches!(url.path(), "" | "/"),
        "bridge URL must not contain a path"
    );
    ensure!(url.query().is_none(), "bridge URL must not contain a query");
    ensure!(
        url.fragment().is_none(),
        "bridge URL must not contain a fragment"
    );
    Ok(())
}

fn decrypt_message(key: &[u8], iv: &str, payload: &str) -> Result<Zeroizing<Vec<u8>>> {
    let iv = decode_base64(iv).context("decode bridge IV")?;
    ensure!(iv.len() == 12, "bridge IV must be 12 bytes");
    let ciphertext =
        Zeroizing::new(decode_base64(payload).context("decode bridge payload")?);
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| eyre::eyre!("invalid AES key"))?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&iv), ciphertext.as_slice())
        .map_err(|_| eyre::eyre!("bridge request authentication failed"))?;
    Ok(Zeroizing::new(plaintext))
}

fn encrypt_message(key: &[u8], plaintext: &[u8]) -> Result<EncryptedBridgeMessage> {
    use aes_gcm::aead::rand_core::RngCore;
    use aes_gcm::aead::OsRng;

    let mut iv = [0_u8; 12];
    OsRng.fill_bytes(&mut iv);
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| eyre::eyre!("invalid AES key"))?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&iv), plaintext)
        .map_err(|_| eyre::eyre!("encrypt bridge response"))?;
    Ok(EncryptedBridgeMessage {
        iv: general_purpose::STANDARD.encode(iv),
        payload: general_purpose::STANDARD.encode(ciphertext),
    })
}

fn decode_base64(value: &str) -> Result<Vec<u8>> {
    for engine in [
        &general_purpose::STANDARD,
        &general_purpose::STANDARD_NO_PAD,
        &general_purpose::URL_SAFE,
        &general_purpose::URL_SAFE_NO_PAD,
    ] {
        if let Ok(decoded) = engine.decode(value) {
            return Ok(decoded);
        }
    }
    bail!("invalid base64 encoding")
}

#[cfg(test)]
mod tests {
    use super::*;
    use walletkit_testkit::{env::TestEnv, proof::build_test_request};
    use world_id_core::{primitives::SessionRef, requests::ProofType};

    const LARGE_SCHEMA: u64 = 879_789_934_843_693_818;

    fn connector_url(bridge_url: Option<&str>) -> String {
        let key = general_purpose::STANDARD.encode([0xab; 32]);
        let bridge = bridge_url.map_or_else(String::new, |bridge_url| {
            format!(
                "&b={}",
                url::form_urlencoded::byte_serialize(bridge_url.as_bytes())
                    .collect::<String>()
            )
        });
        format!("https://world.org/verify?t=wld&i=request-id&k={key}{bridge}")
    }

    fn extension(name: &str, payload_json: String) -> BridgeExtension {
        BridgeExtension {
            name: name.to_owned(),
            version: 1,
            media_type: "application/json".to_owned(),
            payload_json,
        }
    }

    fn composition_request(
        payload_json: &str,
        extensions: &[BridgeExtension],
    ) -> (BridgeRequest, CoreProofRequest) {
        let core = build_test_request(
            &TestEnv::default_staging(),
            LARGE_SCHEMA,
            payload_json,
            300,
            ProofType::Uniqueness,
            SessionRef::None,
        )
        .unwrap();
        let exact = serde_json::to_string_pretty(&core).unwrap();
        let request = serde_json::from_value(serde_json::json!({
            "proof_request": serde_json::to_value(&core).unwrap(),
            "world_request_json": exact,
            "request_extensions": extensions,
            "environment": "staging"
        }))
        .unwrap();
        (request, core)
    }

    #[test]
    fn parses_current_connector_and_loopback_http() {
        let connection = BridgeConnection::parse(&connector_url(None)).unwrap();
        assert_eq!(connection.request_id(), "request-id");
        assert_eq!(
            connection.endpoint("request").unwrap().as_str(),
            "https://bridge.worldcoin.org/request/request-id"
        );
        let loopback =
            BridgeConnection::parse(&connector_url(Some("http://127.0.0.1:8787")))
                .unwrap();
        assert_eq!(
            loopback.endpoint("response").unwrap().as_str(),
            "http://127.0.0.1:8787/response/request-id"
        );
    }

    #[test]
    fn rejects_non_loopback_http_and_ambiguous_urls() {
        assert!(
            BridgeConnection::parse(&connector_url(Some("http://bridge.example")))
                .is_err()
        );
        assert!(
            BridgeConnection::parse(&format!("{}&i=second", connector_url(None)))
                .is_err()
        );
        assert!(BridgeConnection::parse(&connector_url(Some(
            "https://bridge.example/unexpected"
        )))
        .is_err());
    }

    #[test]
    fn bridge_encryption_round_trips_large_presentation() {
        let key = [0x42; 32];
        let plaintext = vec![0x5a; 1_500_000];
        let encrypted = encrypt_message(&key, &plaintext).unwrap();
        assert!(encrypted.payload.len() > 1_900_000);
        let decrypted =
            decrypt_message(&key, &encrypted.iv, &encrypted.payload).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn preserves_exact_request_and_arbitrary_u64_schema() {
        let exact = format!(
            "{{\n  \"id\": \"request-id\",\n  \"proof_requests\": [{{\"issuer_schema_id\": {LARGE_SCHEMA}}}]\n}}"
        );
        let proof_request: Value = serde_json::from_str(&exact).unwrap();
        let request: BridgeRequest = serde_json::from_value(serde_json::json!({
            "proof_request": proof_request,
            "world_request_json": exact,
            "request_extensions": [extension(
                "org.worldcoin.passport.selective_disclosure.v1",
                format!("{{\"issuer_schema_id\":{LARGE_SCHEMA}}}")
            )],
            "environment": "staging"
        }))
        .unwrap();
        request
            .ensure_composition_supported(Some("staging"))
            .unwrap();
        let preserved = request.exact_world_request_json().unwrap();
        assert!(preserved.contains("\n  \"id\""));
        let value: Value = serde_json::from_str(preserved).unwrap();
        assert_eq!(
            value["proof_requests"][0]["issuer_schema_id"].as_u64(),
            Some(LARGE_SCHEMA)
        );
        assert!(request.request_extensions().unwrap()[0]
            .payload_json
            .contains(&LARGE_SCHEMA.to_string()));
    }

    #[test]
    fn rejects_semantic_request_mismatch_and_duplicate_extensions() {
        let mismatch: BridgeRequest = serde_json::from_value(serde_json::json!({
            "proof_request": {"id": "one"},
            "world_request_json": "{\"id\":\"two\"}",
            "request_extensions": [extension("example.one", "{}".to_owned())]
        }))
        .unwrap();
        assert!(mismatch.ensure_composition_supported(None).is_err());

        let duplicate: BridgeRequest = serde_json::from_value(serde_json::json!({
            "proof_request": {"id": "one"},
            "world_request_json": "{\"id\":\"one\"}",
            "request_extensions": [
                extension("example.one", "{}".to_owned()),
                extension("example.one", "[]".to_owned())
            ]
        }))
        .unwrap();
        assert!(duplicate.ensure_composition_supported(None).is_err());
    }

    #[test]
    fn binds_exact_extension_payload_bytes_to_request_signal() {
        let payload = format!("{{\"issuer_schema_id\":{LARGE_SCHEMA}}}");
        let expected = extension(
            "org.worldcoin.passport.selective_disclosure.v1",
            payload.clone(),
        );
        let (request, core) = composition_request(
            &payload,
            &[
                extension("example.unrelated", "{}".to_owned()),
                expected.clone(),
            ],
        );
        assert_eq!(request.bound_request_extension(&core).unwrap(), &expected);

        let semantically_equal_but_not_exact =
            format!("{{ \"issuer_schema_id\" : {LARGE_SCHEMA} }}");
        let (request, core) = composition_request(
            &payload,
            &[extension(
                "org.worldcoin.passport.selective_disclosure.v1",
                semantically_equal_but_not_exact,
            )],
        );
        assert!(request.bound_request_extension(&core).is_err());

        let (request, core) = composition_request(
            &payload,
            &[
                extension("example.one", payload.clone()),
                extension("example.two", payload.clone()),
            ],
        );
        assert!(request.bound_request_extension(&core).is_err());
    }

    #[test]
    fn extension_responses_must_exactly_cover_names_and_metadata() {
        let requested = vec![extension("example.one", "{}".to_owned())];
        let matching = vec![extension("example.one", "{\"proof\":1}".to_owned())];
        validate_extension_responses(&requested, &matching).unwrap();

        let mut wrong_version = matching;
        wrong_version[0].version = 2;
        assert!(validate_extension_responses(&requested, &wrong_version).is_err());

        let wrong_name = vec![extension("example.two", "{}".to_owned())];
        assert!(validate_extension_responses(&requested, &wrong_name).is_err());
        assert!(validate_extension_responses(&requested, &[]).is_err());
    }

    #[test]
    fn shapes_named_extension_response() {
        let proof = serde_json::json!({"id": "request-id", "responses": []});
        let extension = extension(
            "org.worldcoin.passport.selective_disclosure.v1",
            format!("{{\"issuer_schema_id\":{LARGE_SCHEMA}}}"),
        );
        let payload =
            extension_response_payload(&proof, std::slice::from_ref(&extension))
                .unwrap();
        assert_eq!(payload["proof_response"], proof);
        assert_eq!(payload["extension_responses"][0]["name"], extension.name);
        assert_eq!(
            payload["extension_responses"][0]["payload_json"],
            extension.payload_json
        );
    }

    #[tokio::test]
    async fn fetches_request_and_posts_response_to_bridge_endpoints() {
        let key = [0x11; 32];
        let request_plaintext = serde_json::to_vec(&serde_json::json!({
            "proof_request": {"id": "request-id"},
            "environment": "staging"
        }))
        .unwrap();
        let encrypted_request = encrypt_message(&key, &request_plaintext).unwrap();

        let mut server = mockito::Server::new_async().await;
        let request_mock = server
            .mock("GET", "/request/request-id")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_vec(&encrypted_request).unwrap())
            .create_async()
            .await;
        let response_mock = server
            .mock("PUT", "/response/request-id")
            .match_header("content-type", "application/json")
            .with_status(200)
            .create_async()
            .await;

        let connection = BridgeConnection {
            request_id: "request-id".to_owned(),
            bridge_url: Url::parse(&format!("{}/", server.url())).unwrap(),
            key: Zeroizing::new(key.to_vec()),
        };
        let client = http_client().unwrap();
        let request = fetch_request(&client, &connection).await.unwrap();
        assert_eq!(request.proof_request().unwrap()["id"], "request-id");
        let large_extension_proof = "a".repeat(1_500_000);
        send_response(
            &client,
            &connection,
            &serde_json::json!({
                "proof_response": {"id": "request-id", "responses": []},
                "extension_responses": [{
                    "name": "org.worldcoin.passport.selective_disclosure.v1",
                    "version": 1,
                    "media_type": "application/json",
                    "payload_json": large_extension_proof,
                }]
            }),
        )
        .await
        .unwrap();

        request_mock.assert_async().await;
        response_mock.assert_async().await;
        drop(server);
    }
}
