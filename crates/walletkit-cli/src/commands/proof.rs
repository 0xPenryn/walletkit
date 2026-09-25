//! `walletkit proof` subcommands — proof generation, inspection, and on-chain verification.

use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io::{Read, Write as _};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;

use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine as _};
use clap::Subcommand;
use eyre::WrapErr as _;
use walletkit_core::requests::ProofRequest;
use walletkit_testkit::env::TestEnv;
use walletkit_testkit::issuer::issue_faux_credential;
use walletkit_testkit::proof::{
    build_test_request, verify_proof_onchain, VerifyItemResult,
};
use walletkit_testkit::storage::create_artifact_source;
use walletkit_testkit::utils::now_secs;
use world_id_core::primitives::{FieldElement, OwnershipProof, SessionId, SessionRef};
use world_id_core::requests::{
    ProofRequest as CoreProofRequest, ProofResponse as CoreProofResponse, ProofType,
};
use world_id_proof::ownership_proof::verify_ownership_proof;

use crate::commands::resolve_root;
use crate::output;

use super::{
    bridge::{self, BridgeConnection},
    init_authenticator, resolve_built_config, resolve_test_rpc_url,
    resolve_verifier_address, Cli,
};

const MAX_INPUT_BYTES: u64 = 16 * 1024 * 1024; // 16 MiB

/// Builds a [`TestEnv`] from the CLI flags for on-chain operations.
///
/// Uses the same World ID [`Config`] resolution as authenticator init
/// (`--authenticator-config` / `--environment` / `--region` / `--ohttp-defaults` /
/// `--rpc-url`). The verifier comes from `--verifier-address` or a known
/// staging/production registry mapping. RP id/key and faux issuer stay on the
/// staging fixtures.
fn cli_test_env(cli: &Cli, verifier_address: Option<&str>) -> eyre::Result<TestEnv> {
    let config = resolve_built_config(cli)?;
    let verifier = resolve_verifier_address(verifier_address, &config)?;
    let mut env = TestEnv::default_with_config_and_verifier(config, verifier);
    env.rpc_url = resolve_test_rpc_url(cli, &env.world_id_config);
    Ok(env)
}

#[derive(Subcommand)]
pub enum ProofCommand {
    /// Generate a proof from request JSON or a stock encrypted bridge request.
    Generate {
        /// Path to proof request JSON, or `-` for stdin.
        #[arg(
            long,
            required_unless_present = "bridge_url",
            conflicts_with = "bridge_url"
        )]
        request: Option<String>,
        /// `IDKit` connector URL whose encrypted request should be fulfilled.
        #[arg(long, required_unless_present = "request", conflicts_with = "request")]
        bridge_url: Option<String>,
        /// Mock a successful Identity Check attestation (development only).
        #[arg(long, requires = "bridge_url", conflicts_with = "request")]
        mock_identity_attestation: bool,
        /// Mock successful user-presence completion (development only).
        #[arg(long, requires = "bridge_url", conflicts_with = "request")]
        mock_user_presence: bool,
        /// Override current time (unix seconds) for deterministic testing.
        #[arg(long)]
        now: Option<u64>,
    },
    /// Fetch a composed bridge request and atomically export its World proof and private witness.
    BridgeExport {
        /// `IDKit` connector URL whose encrypted request should be fetched.
        #[arg(long)]
        bridge_url: String,
        /// New owner-only file for the exact `world_request_json` bytes.
        #[arg(long)]
        request_out: PathBuf,
        /// New owner-only file for the stock World proof response.
        #[arg(long)]
        proof_out: PathBuf,
        /// New owner-only file for the private composition witness.
        #[arg(long)]
        witness_out: PathBuf,
        /// New owner-only file for the opaque request-extension array.
        #[arg(long)]
        extensions_out: PathBuf,
        /// Override current time (unix seconds) for deterministic testing.
        #[arg(long)]
        now: Option<u64>,
    },
    /// Submit a stock World proof and opaque extension responses to the same bridge request.
    BridgeSubmit {
        /// Original `IDKit` connector URL used by `bridge-export`.
        #[arg(long)]
        bridge_url: String,
        /// Owner-only exact request file written by `bridge-export`.
        #[arg(long)]
        request: PathBuf,
        /// Owner-only request-extension array written by `bridge-export`.
        #[arg(long)]
        request_extensions: PathBuf,
        /// Owner-only stock proof file written by `bridge-export`.
        #[arg(long)]
        proof: PathBuf,
        /// JSON array of named extension responses to encrypt and submit.
        #[arg(long)]
        extension_responses: PathBuf,
    },
    /// Generate a signed test proof request using hardcoded staging RP keys.
    GenerateTestRequest {
        /// Issuer schema ID to request a proof for.
        #[arg(long)]
        issuer_schema_id: u64,
        /// Signal string for the proof request.
        #[arg(long, default_value = "test_signal")]
        signal: String,
        /// Seconds from now until the request expires.
        #[arg(long, default_value = "300")]
        expires_in: u64,
        /// Proof type to generate.
        #[arg(long, value_parser = parse_proof_type_arg, default_value = "uniqueness")]
        proof_type: ProofType,
        /// Existing session ID for `--proof-type session`; omit to create a session.
        #[arg(long, value_parser = parse_session_id_arg)]
        session_id: Option<SessionId>,
    },
    /// Verify a previously generated proof on-chain via the `WorldIDVerifier` contract.
    Verify {
        /// Path to the original proof request JSON, or `-` for stdin.
        #[arg(long)]
        request: String,
        /// Path to the proof response JSON, or `-` for stdin.
        #[arg(long)]
        response: String,
        /// Override the `WorldID` verifier contract address (defaults from the
        /// known staging/production registry in the resolved authenticator config).
        #[arg(long)]
        verifier_address: Option<String>,
    },
    /// End-to-end test: issue a test credential, generate a proof, and verify it on-chain.
    Test {
        /// Signal string for the proof request.
        #[arg(long, default_value = "test_signal")]
        signal: String,
        /// Override the `WorldID` verifier contract address (defaults from the
        /// known staging/production registry in the resolved authenticator config).
        #[arg(long)]
        verifier_address: Option<String>,
    },
    /// Verify a WIP-103 ownership proof from a base64-encoded file.
    VerifyOwnership {
        /// Path to a file containing the base64url-encoded ownership proof, or `-` for stdin.
        #[arg(long)]
        proof: String,
        /// Nonce used when generating the proof, as a 32-byte hex field element (with optional `0x` prefix).
        #[arg(long)]
        nonce: String,
        /// Credential `sub` (commitment) the proof claims ownership of, as a 32-byte hex field element.
        #[arg(long)]
        sub: String,
        /// Context bound to the ownership proof, as a 32-byte hex field element.
        #[arg(long)]
        context: String,
    },
}

fn read_file_or_stdin(path: &str) -> eyre::Result<String> {
    if path == "-" {
        let mut buf = String::new();
        std::io::stdin()
            .take(MAX_INPUT_BYTES)
            .read_to_string(&mut buf)?;
        Ok(buf)
    } else {
        let meta =
            std::fs::metadata(path).wrap_err_with(|| format!("cannot read {path}"))?;
        eyre::ensure!(
            meta.len() <= MAX_INPUT_BYTES,
            "input file too large (max 16 MiB)"
        );
        Ok(std::fs::read_to_string(path)?)
    }
}

fn parse_proof_type_arg(value: &str) -> Result<ProofType, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "uniqueness" => Ok(ProofType::Uniqueness),
        "session" => Ok(ProofType::Session),
        _ => Err("expected one of: uniqueness, session".to_string()),
    }
}

fn parse_session_id_arg(session_id: &str) -> Result<SessionId, String> {
    serde_json::from_value(serde_json::Value::String(session_id.to_string()))
        .map_err(|err| format!("invalid session id: {err}"))
}

async fn generate_proof(
    cli: &Cli,
    request_json: &str,
    now: Option<u64>,
) -> eyre::Result<walletkit_core::requests::ProofResponse> {
    let (authenticator, _store) = init_authenticator(cli).await?;
    let ts = now.unwrap_or_else(now_secs);
    let proof_request =
        ProofRequest::from_json(request_json).wrap_err("invalid proof request")?;

    authenticator
        .generate_proof(&proof_request, Some(ts))
        .await
        .wrap_err("proof generation failed")
}

async fn run_generate_file(
    cli: &Cli,
    request: &str,
    now: Option<u64>,
) -> eyre::Result<()> {
    let request_json = read_file_or_stdin(request)?;
    let response = generate_proof(cli, &request_json, now).await?;

    let response_json = response
        .to_json()
        .wrap_err("response serialization failed")?;

    if cli.json {
        let parsed: serde_json::Value = serde_json::from_str(&response_json)?;
        output::print_json_data(&parsed, true);
    } else {
        println!("{response_json}");
    }
    Ok(())
}

async fn run_generate_bridge(
    cli: &Cli,
    bridge_url: &str,
    mock_identity_attestation: bool,
    mock_user_presence: bool,
    now: Option<u64>,
) -> eyre::Result<()> {
    let connection = BridgeConnection::parse(bridge_url)?;
    let client = bridge::http_client()?;
    let request = bridge::fetch_request(&client, &connection).await?;
    let configured_environment = cli
        .authenticator_config
        .is_none()
        .then_some(cli.environment.as_str());
    request.ensure_supported(
        configured_environment,
        mock_identity_attestation,
        mock_user_presence,
    )?;

    let mocked_identity_attestation =
        request.has_identity_attributes() && mock_identity_attestation;
    let mocked_user_presence = request.requires_user_presence() && mock_user_presence;
    if !cli.json && (mocked_identity_attestation || mocked_user_presence) {
        eprintln!("Warning: submitting mocked bridge assertions for development only.");
    }

    let request_json = serde_json::to_string(request.proof_request()?)
        .wrap_err("serialize bridge proof request")?;
    let response = generate_proof(cli, &request_json, now).await?;
    let response_json = response
        .to_json()
        .wrap_err("response serialization failed")?;
    let response_value: serde_json::Value = serde_json::from_str(&response_json)
        .wrap_err("parse generated proof response")?;
    let response_payload = request.response_payload(
        response_value,
        mock_identity_attestation,
        mock_user_presence,
    )?;

    bridge::send_response(&client, &connection, &response_payload).await?;

    if cli.json {
        output::print_json_data(
            &serde_json::json!({
                "submitted": true,
                "request_id": connection.request_id(),
                "mocked_identity_attestation": mocked_identity_attestation,
                "mocked_user_presence": mocked_user_presence,
            }),
            true,
        );
    } else {
        println!("Proof generated and submitted to the IDKit bridge.");
    }
    Ok(())
}

fn read_path(path: &Path) -> eyre::Result<String> {
    let display = path.display();
    let meta =
        std::fs::metadata(path).wrap_err_with(|| format!("cannot read {display}"))?;
    eyre::ensure!(meta.is_file(), "input is not a regular file: {display}");
    eyre::ensure!(
        meta.len() <= MAX_INPUT_BYTES,
        "input file too large (max 16 MiB): {display}"
    );
    std::fs::read_to_string(path)
        .wrap_err_with(|| format!("failed to read UTF-8 input {display}"))
}

fn write_private_file(path: &Path, bytes: &[u8]) -> eyre::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(path)
        .wrap_err_with(|| format!("failed to create {}", path.display()))?;
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(error)
            .wrap_err_with(|| format!("failed to write {}", path.display()));
    }
    Ok(())
}

fn write_private_outputs(outputs: &[(&Path, &[u8])]) -> eyre::Result<()> {
    let mut distinct = BTreeSet::new();
    for (path, _) in outputs {
        eyre::ensure!(
            distinct.insert((*path).to_path_buf()),
            "bridge export output paths must be distinct: {}",
            path.display()
        );
    }

    let mut created = Vec::new();
    for (path, bytes) in outputs {
        if let Err(error) = write_private_file(path, bytes) {
            for created_path in created {
                let _ = std::fs::remove_file(created_path);
            }
            return Err(error);
        }
        created.push((*path).to_path_buf());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn run_bridge_export(
    cli: &Cli,
    bridge_url: &str,
    request_out: &Path,
    proof_out: &Path,
    witness_out: &Path,
    extensions_out: &Path,
    now: Option<u64>,
) -> eyre::Result<()> {
    let connection = BridgeConnection::parse(bridge_url)?;
    let client = bridge::http_client()?;
    let bridge_request = bridge::fetch_request(&client, &connection).await?;
    let configured_environment = cli
        .authenticator_config
        .is_none()
        .then_some(cli.environment.as_str());
    bridge_request.ensure_composition_supported(configured_environment)?;

    let exact_request = bridge_request.exact_world_request_json()?.to_owned();
    let core_request = CoreProofRequest::from_json(&exact_request)
        .wrap_err("invalid exact World proof request")?;
    let bound_extension = bridge_request
        .bound_request_extension(&core_request)?
        .clone();
    let request_item = core_request
        .requests
        .first()
        .ok_or_else(|| eyre::eyre!("composition bridge request has no request item"))?;
    let issuer_schema_id = request_item.issuer_schema_id;
    let walletkit_request = ProofRequest::from_json(&exact_request)
        .wrap_err("invalid exact WalletKit proof request")?;

    let (authenticator, _store) = init_authenticator(cli).await?;
    let generated_at = now.unwrap_or_else(now_secs);
    let result = authenticator
        .generate_proof_with_world_composition_witness(
            exact_request.as_bytes(),
            &walletkit_request,
            issuer_schema_id,
            generated_at,
        )
        .await
        .wrap_err("atomic proof/composition witness generation failed")?;
    core_request
        .validate_response(&result.proof_response.0)
        .wrap_err("generated stock proof does not match the exact request")?;

    let proof_json = result
        .proof_response
        .to_json()
        .wrap_err("stock proof response serialization failed")?;
    let witness_json = serde_json::to_vec(&result.witness)
        .wrap_err("composition witness serialization failed")?;
    let extensions_json = serde_json::to_vec(bridge_request.request_extensions()?)
        .wrap_err("request extensions serialization failed")?;
    write_private_outputs(&[
        (request_out, exact_request.as_bytes()),
        (proof_out, proof_json.as_bytes()),
        (witness_out, &witness_json),
        (extensions_out, &extensions_json),
    ])?;

    let witness = result.witness;
    let metadata = serde_json::json!({
        "exported": true,
        "bridge_request_id": connection.request_id(),
        "request_id": witness.request.request_id,
        "issuer_schema_id": witness.request.issuer_schema_id,
        "request_item_identifier": witness.request.identifier,
        "bound_extension_name": bound_extension.name,
        "raw_request_sha256": witness.request.raw_request_sha256,
        "request_path": request_out,
        "proof_path": proof_out,
        "witness_path": witness_out,
        "extensions_path": extensions_out,
        "contains_authenticator_seed": false,
        "contains_private_signing_key": false,
        "contains_credential_blinding_factor": true,
        "sensitive_linkable_witness": true,
    });
    if cli.json {
        output::print_json_data(&metadata, true);
    } else {
        println!(
            "Exported the exact request, stock proof, private composition witness, and request extensions."
        );
        println!("  request: {}", request_out.display());
        println!("  proof: {}", proof_out.display());
        println!("  witness: {}", witness_out.display());
        println!("  extensions: {}", extensions_out.display());
        println!(
            "Keep the witness local: it contains the credential blinding factor and linkable account/OPRF material."
        );
    }
    Ok(())
}

async fn run_bridge_submit(
    json_output: bool,
    bridge_url: &str,
    request_path: &Path,
    request_extensions_path: &Path,
    proof_path: &Path,
    extension_responses_path: &Path,
) -> eyre::Result<()> {
    let exact_request = read_path(request_path)?;
    let request_extensions_json = read_path(request_extensions_path)?;
    let proof_json = read_path(proof_path)?;
    let extension_responses_json = read_path(extension_responses_path)?;
    let core_request = CoreProofRequest::from_json(&exact_request)
        .wrap_err("invalid exact World proof request")?;
    let proof_response = CoreProofResponse::from_json(&proof_json)
        .wrap_err("invalid stock World proof response")?;
    core_request
        .validate_response(&proof_response)
        .wrap_err("stock proof response does not match the exact request")?;
    let request_extensions = bridge::parse_extensions_json(&request_extensions_json)
        .wrap_err("invalid request extension array")?;
    let extension_responses = bridge::parse_extensions_json(&extension_responses_json)
        .wrap_err("invalid extension response array")?;

    let connection = BridgeConnection::parse(bridge_url)?;
    let bound_extension =
        bridge::bound_request_extension(&request_extensions, &core_request)?;
    bridge::validate_extension_responses(&request_extensions, &extension_responses)?;
    eyre::ensure!(
        extension_responses
            .iter()
            .any(|response| response.name == bound_extension.name),
        "missing response for the signal-bound request extension"
    );

    let proof_value = serde_json::to_value(&proof_response)
        .wrap_err("serialize validated stock proof response")?;
    let response_payload =
        bridge::extension_response_payload(&proof_value, &extension_responses)?;
    let client = bridge::http_client()?;
    bridge::send_response(&client, &connection, &response_payload).await?;

    let response_names: Vec<&str> = extension_responses
        .iter()
        .map(|extension| extension.name.as_str())
        .collect();
    if json_output {
        output::print_json_data(
            &serde_json::json!({
                "submitted": true,
                "bridge_request_id": connection.request_id(),
                "request_id": core_request.id,
                "extension_names": response_names,
            }),
            true,
        );
    } else {
        println!(
            "Submitted the stock World proof and {} extension response(s) to the IDKit bridge.",
            response_names.len()
        );
    }
    Ok(())
}

fn print_verify_items_human(results: &[VerifyItemResult]) {
    for r in results {
        if r.result.is_ok() {
            println!(
                "  {} {} (issuer_schema_id={})",
                output::pass_label(),
                r.identifier,
                r.issuer_schema_id
            );
        } else {
            println!(
                "  {} {} (issuer_schema_id={}): {}",
                output::fail_label(),
                r.identifier,
                r.issuer_schema_id,
                r.result.as_ref().err().map_or("unknown", String::as_str)
            );
        }
    }
}

fn verify_items_to_json(results: &[VerifyItemResult]) -> Vec<serde_json::Value> {
    results
        .iter()
        .map(|r| {
            serde_json::json!({
                "issuer_schema_id": r.issuer_schema_id,
                "identifier": r.identifier,
                "verified": r.result.is_ok(),
                "error": r.result.as_ref().err(),
            })
        })
        .collect()
}

async fn run_verify(
    cli: &Cli,
    request_path: &str,
    response_path: &str,
    verifier_address: Option<&str>,
) -> eyre::Result<()> {
    let request_json = read_file_or_stdin(request_path)?;
    let response_json = read_file_or_stdin(response_path)?;

    let proof_request: CoreProofRequest =
        CoreProofRequest::from_json(&request_json).wrap_err("invalid proof request")?;
    let proof_response: CoreProofResponse =
        serde_json::from_str(&response_json).wrap_err("invalid proof response")?;

    let env = cli_test_env(cli, verifier_address)?;
    let results = verify_proof_onchain(&env, &proof_request, &proof_response).await?;
    let all_passed = results.iter().all(|r| r.result.is_ok());

    if cli.json {
        output::print_json_data(
            &serde_json::json!({
                "verified": all_passed,
                "results": verify_items_to_json(&results),
            }),
            true,
        );
    } else {
        print_verify_items_human(&results);
        if all_passed {
            println!("All proofs verified on-chain.");
        }
    }

    if !all_passed {
        std::process::exit(1);
    }
    Ok(())
}

fn run_generate_test_request(
    cli: &Cli,
    issuer_schema_id: u64,
    signal: &str,
    expires_in: u64,
    proof_type: ProofType,
    session_id: Option<SessionId>,
) -> eyre::Result<()> {
    let (proof_type, session_ref) = match (proof_type, session_id) {
        (ProofType::Uniqueness, Some(_)) => {
            eyre::bail!("--session-id is only valid with --proof-type session");
        }
        (ProofType::Uniqueness, None) => (ProofType::Uniqueness, SessionRef::None),
        (ProofType::Session, None) => (ProofType::Session, SessionRef::Create),
        (ProofType::Session, Some(session_id)) => {
            (ProofType::Session, SessionRef::Existing(session_id))
        }
    };
    let request = build_test_request(
        &TestEnv::default_staging(),
        issuer_schema_id,
        signal,
        expires_in,
        proof_type,
        session_ref,
    )?;
    let json = serde_json::to_string_pretty(&request)?;

    if cli.json {
        let parsed: serde_json::Value = serde_json::from_str(&json)?;
        output::print_json_data(&parsed, true);
    } else {
        println!("{json}");
    }

    Ok(())
}

/// End-to-end test: issue a test credential, generate a proof, and verify it on-chain.
async fn run_test(
    cli: &Cli,
    signal: &str,
    verifier_address: Option<&str>,
) -> eyre::Result<()> {
    let (authenticator, store) = init_authenticator(cli).await?;
    let env = cli_test_env(cli, verifier_address)?;

    if !cli.json {
        eprintln!("Issuing test credential from faux issuer...");
    }
    let issued = issue_faux_credential(&env, &authenticator, &store).await?;
    let issuer_schema_id = issued.credential.issuer_schema_id();

    if !cli.json {
        eprintln!("Generating test proof request...");
    }
    let proof_request = build_test_request(
        &env,
        issuer_schema_id,
        signal,
        300,
        ProofType::Uniqueness,
        SessionRef::None,
    )?;

    if !cli.json {
        eprintln!("Generating proof...");
    }
    let ts = now_secs();
    let walletkit_request =
        ProofRequest::from_json(&serde_json::to_string(&proof_request)?)
            .wrap_err("invalid proof request")?;
    let proof_response = authenticator
        .generate_proof(&walletkit_request, Some(ts))
        .await
        .wrap_err("proof generation failed")?;

    if !cli.json {
        eprintln!("Verifying proof on-chain...");
    }
    let results = verify_proof_onchain(&env, &proof_request, &proof_response.0).await?;
    let all_passed = results.iter().all(|r| r.result.is_ok());

    if cli.json {
        output::print_json_data(
            &serde_json::json!({
                "credential_id": issued.credential_id,
                "issuer_schema_id": issuer_schema_id,
                "blinding_factor": issued.blinding_factor.to_hex_string(),
                "verified": all_passed,
                "results": verify_items_to_json(&results),
            }),
            true,
        );
    } else {
        print_verify_items_human(&results);
        if all_passed {
            println!("End-to-end test passed.");
        }
    }

    if !all_passed {
        std::process::exit(1);
    }
    Ok(())
}

fn parse_field_element(value: &str, label: &str) -> eyre::Result<FieldElement> {
    value.trim().parse::<FieldElement>().wrap_err_with(|| {
        format!("invalid {label}: expected 32-byte hex field element")
    })
}

fn run_verify_ownership(
    cli: &Cli,
    proof_path: &str,
    nonce: &str,
    sub: &str,
    context: &str,
) -> eyre::Result<()> {
    let b64 = read_file_or_stdin(proof_path)?;
    let bytes = BASE64_URL_SAFE_NO_PAD
        .decode(b64.trim())
        .wrap_err("invalid base64 ownership proof")?;
    let proof: OwnershipProof = ciborium::from_reader(&bytes[..])
        .wrap_err("failed to decode ownership proof CBOR")?;

    let nonce_fe = parse_field_element(nonce, "--nonce")?;
    let sub_fe = parse_field_element(sub, "--sub")?;
    let context_fe = parse_field_element(context, "--context")?;

    let root = resolve_root(cli)?;
    let artifacts = create_artifact_source(&root);

    let result = verify_ownership_proof(
        &proof,
        nonce_fe,
        sub_fe,
        context_fe,
        artifacts.as_ref(),
    );
    let merkle_root = proof.merkle_root.to_string();

    if cli.json {
        output::print_json_data(
            &serde_json::json!({
                "verified": result.is_ok(),
                "merkle_root": merkle_root,
                "error": result.as_ref().err().map(|e| format!("{e:#}")),
            }),
            true,
        );
    } else if let Err(ref err) = result {
        println!(
            "{} ownership proof verification failed: {err:#}",
            output::fail_label()
        );
        println!("  merkle_root: {merkle_root}");
    } else {
        println!("{} ownership proof verified", output::pass_label());
        println!("  merkle_root: {merkle_root}");
    }

    if result.is_err() {
        std::process::exit(1);
    }
    Ok(())
}

pub async fn run(cli: &Cli, action: &ProofCommand) -> eyre::Result<()> {
    match action {
        ProofCommand::Generate {
            request,
            bridge_url,
            mock_identity_attestation,
            mock_user_presence,
            now,
        } => match (request.as_deref(), bridge_url.as_deref()) {
            (Some(request), None) => run_generate_file(cli, request, *now).await,
            (None, Some(bridge_url)) => {
                run_generate_bridge(
                    cli,
                    bridge_url,
                    *mock_identity_attestation,
                    *mock_user_presence,
                    *now,
                )
                .await
            }
            _ => eyre::bail!("exactly one of --request or --bridge-url is required"),
        },
        ProofCommand::BridgeExport {
            bridge_url,
            request_out,
            proof_out,
            witness_out,
            extensions_out,
            now,
        } => {
            run_bridge_export(
                cli,
                bridge_url,
                request_out,
                proof_out,
                witness_out,
                extensions_out,
                *now,
            )
            .await
        }
        ProofCommand::BridgeSubmit {
            bridge_url,
            request,
            request_extensions,
            proof,
            extension_responses,
        } => {
            run_bridge_submit(
                cli.json,
                bridge_url,
                request,
                request_extensions,
                proof,
                extension_responses,
            )
            .await
        }
        ProofCommand::GenerateTestRequest {
            issuer_schema_id,
            signal,
            expires_in,
            proof_type,
            session_id,
        } => run_generate_test_request(
            cli,
            *issuer_schema_id,
            signal,
            *expires_in,
            *proof_type,
            *session_id,
        ),
        ProofCommand::Verify {
            request,
            response,
            verifier_address,
        } => run_verify(cli, request, response, verifier_address.as_deref()).await,
        ProofCommand::Test {
            signal,
            verifier_address,
        } => run_test(cli, signal, verifier_address.as_deref()).await,
        ProofCommand::VerifyOwnership {
            proof,
            nonce,
            sub,
            context,
        } => run_verify_ownership(cli, proof, nonce, sub, context),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use world_id_core::primitives::{Nullifier, ZeroKnowledgeProof};
    use world_id_core::requests::ResponseItem;

    #[test]
    fn private_bridge_outputs_are_exact_and_create_new() {
        let directory = tempfile::tempdir().unwrap();
        let request_path = directory.path().join("request.json");
        let proof_path = directory.path().join("proof.json");
        let exact_request = b"{\n  \"issuer_schema_id\": 879789934843693818\n}";
        let proof = b"{\"id\":\"request-id\"}";

        write_private_outputs(&[(&request_path, exact_request), (&proof_path, proof)])
            .unwrap();
        assert_eq!(std::fs::read(&request_path).unwrap(), exact_request);
        assert_eq!(std::fs::read(&proof_path).unwrap(), proof);

        let error = write_private_file(&request_path, b"replacement")
            .expect_err("existing output must not be overwritten");
        assert!(error.to_string().contains("failed to create"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&request_path)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn bridge_output_paths_must_be_distinct() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("same.json");
        let error = write_private_outputs(&[(&path, b"one"), (&path, b"two")])
            .expect_err("duplicate path must fail before writing");
        assert!(error.to_string().contains("must be distinct"));
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn bridge_submit_uses_saved_extensions_without_refetching() {
        let payload_json = r#"{"policy":"age_at_least"}"#;
        let request = build_test_request(
            &TestEnv::default_staging(),
            879_789_934_843_693_818,
            payload_json,
            300,
            ProofType::Uniqueness,
            SessionRef::None,
        )
        .unwrap();
        let request_item = &request.requests[0];
        let proof_response = CoreProofResponse {
            id: request.id.clone(),
            version: request.version,
            session_id: None,
            error: None,
            responses: vec![ResponseItem::new_uniqueness(
                request_item.identifier.clone(),
                request_item.issuer_schema_id,
                ZeroKnowledgeProof::default(),
                Nullifier::from(FieldElement::ZERO),
                request_item.effective_expires_at_min(request.created_at),
            )],
        };
        request.validate_response(&proof_response).unwrap();

        let directory = tempfile::tempdir().unwrap();
        let request_path = directory.path().join("request.json");
        let request_extensions_path = directory.path().join("request-extensions.json");
        let proof_path = directory.path().join("proof.json");
        let extension_responses_path =
            directory.path().join("extension-responses.json");
        write_private_outputs(&[
            (&request_path, request.to_json().unwrap().as_bytes()),
            (
                &request_extensions_path,
                serde_json::to_string(&serde_json::json!([{
                    "name": "org.worldcoin.passport.selective_disclosure.v1",
                    "version": 1,
                    "media_type": "application/json",
                    "payload_json": payload_json,
                }]))
                .unwrap()
                .as_bytes(),
            ),
            (
                &proof_path,
                serde_json::to_string(&proof_response).unwrap().as_bytes(),
            ),
            (
                &extension_responses_path,
                serde_json::to_string(&serde_json::json!([{
                    "name": "org.worldcoin.passport.selective_disclosure.v1",
                    "version": 1,
                    "media_type": "application/json",
                    "payload_json": "{\"proof\":\"opaque\"}",
                }]))
                .unwrap()
                .as_bytes(),
            ),
        ])
        .unwrap();

        let key = STANDARD.encode([0x22; 32]);
        let mut server = mockito::Server::new_async().await;
        let bridge_origin =
            url::form_urlencoded::byte_serialize(server.url().as_bytes())
                .collect::<String>();
        let connector_key =
            url::form_urlencoded::byte_serialize(key.as_bytes()).collect::<String>();
        let connector_url = format!(
            "https://world.org/verify?t=wld&i=request-id&b={bridge_origin}&k={connector_key}"
        );
        let no_second_fetch = server
            .mock("GET", "/request/request-id")
            .with_status(500)
            .expect(0)
            .create_async()
            .await;
        let response_mock = server
            .mock("PUT", "/response/request-id")
            .match_header("content-type", "application/json")
            .with_status(200)
            .expect(1)
            .create_async()
            .await;

        run_bridge_submit(
            false,
            &connector_url,
            &request_path,
            &request_extensions_path,
            &proof_path,
            &extension_responses_path,
        )
        .await
        .unwrap();

        no_second_fetch.assert_async().await;
        response_mock.assert_async().await;
        drop(server);
    }
}
