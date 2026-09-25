//! Native-only witness contract for composing `WalletKit`'s canonical OPRF flow
//! with an external proving system.
//!
//! This deliberately exports the already-generated query signature, account
//! inclusion path, and verifiable OPRF transcript. It never exports an
//! authenticator seed or private signing key. The witness is nevertheless
//! sensitive and linkable: callers must keep it local and short-lived.

use ark_ff::PrimeField;
use ruint::aliases::U256;
use serde::{Deserialize, Serialize};
use world_id_core::{
    requests::{ProofRequest, RequestItem},
    Credential as CoreCredential, CredentialInput,
};
use world_id_proof::FullOprfOutput;

/// Affine `BabyJubJub` point encoded as canonical decimal field elements.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompositionPointV1 {
    /// X coordinate.
    pub x: String,
    /// Y coordinate.
    pub y: String,
}

/// RP request metadata needed to select and constrain the credential proof.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompositionRequestV1 {
    /// RP request identifier.
    pub request_id: String,
    /// SHA-256 of the exact UTF-8 request bytes accepted by `WalletKit`.
    pub raw_request_sha256: String,
    /// Only `uniqueness` is exported by this first bridge.
    pub proof_type: String,
    /// Signed request creation time.
    pub created_at: u64,
    /// Signed request expiry time.
    pub expires_at: u64,
    /// Timestamp supplied to `WalletKit` for request validation.
    pub generated_at: u64,
    /// Selected request-item identifier.
    pub identifier: String,
    /// Independently registered issuer/schema identifier.
    pub issuer_schema_id: u64,
    /// OPRF registry key identifier selected by the signed RP request.
    pub oprf_key_id: String,
    /// Canonical World signal hash for the selected request item.
    pub signal_hash: String,
    /// Effective lower bound on credential issuance, or zero.
    pub genesis_issued_at_min: u64,
    /// Effective lower bound on credential expiration.
    pub expires_at_min: u64,
}

/// Private OPRF query and World account-membership witness.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompositionQueryV1 {
    /// Full registered authenticator public-key set.
    pub user_public_keys: [CompositionPointV1; 7],
    /// Key-set position used to sign the query.
    pub public_key_index: String,
    /// Query `EdDSA` signature response.
    pub query_signature_s: String,
    /// Query `EdDSA` signature point.
    pub query_signature_r: CompositionPointV1,
    /// Accepted World account root.
    pub merkle_root: String,
    /// Actual World account-tree depth.
    pub merkle_depth: String,
    /// Private account leaf index.
    pub merkle_index: String,
    /// Account inclusion siblings, padded to the protocol depth.
    pub merkle_siblings: [String; 30],
    /// Private OPRF query blinding scalar.
    pub beta: String,
    /// Registered relying-party identifier.
    pub rp_id: String,
    /// RP-scoped uniqueness action.
    pub action: String,
    /// RP request nonce.
    pub nonce: String,
}

/// Verifiable distributed-OPRF transcript used by the canonical nullifier circuit.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompositionOprfV1 {
    /// Fiat-Shamir challenge for the DLog-equality proof.
    pub dlog_e: String,
    /// DLog-equality proof response.
    pub dlog_s: String,
    /// Registered RP OPRF public key.
    pub public_key: CompositionPointV1,
    /// Aggregated blinded OPRF response.
    pub response_blinded: CompositionPointV1,
    /// Unblinded OPRF response.
    pub response: CompositionPointV1,
    /// Canonical World nullifier output.
    pub nullifier: String,
}

/// Exact stored credential selected by `WalletKit` for this request item.
///
/// This is a private circuit witness. In particular, the subject blinding
/// factor must never be logged or sent to an RP. It is exported so the
/// composed circuit can authenticate the credential against the same World
/// account leaf that produced [`CompositionQueryV1`], rather than trusting an
/// externally supplied credential JSON document.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompositionCredentialV1 {
    /// Credential reference identifier.
    pub id: u64,
    /// Credential structure version.
    pub version: u8,
    /// Issuer-defined credential version packed with `id` by the circuit.
    pub issuer_version: u8,
    /// Registered issuer/schema identifier.
    pub issuer_schema_id: u64,
    /// Credential subject commitment.
    pub subject: String,
    /// Timestamp of first issuance.
    pub genesis_issued_at: u64,
    /// Credential expiration timestamp.
    pub expires_at: u64,
    /// All fifteen credential claim elements in canonical schema order.
    pub claims: [String; CoreCredential::MAX_CLAIMS],
    /// Issuer-defined associated-data commitment.
    pub associated_data_commitment: String,
    /// Issuer public key carried by the signed credential.
    pub issuer_public_key: CompositionPointV1,
    /// Credential `EdDSA` signature response scalar.
    pub signature_s: String,
    /// Credential `EdDSA` signature nonce point.
    pub signature_r: CompositionPointV1,
    /// Exact stored blinding factor used to derive `subject` from the account leaf.
    pub subject_blinding_factor: String,
}

/// Exact private inputs needed to re-prove `WalletKit`'s canonical World account
/// membership and OPRF nullifier in a `ProveKit` circuit.
///
/// The object contains no authenticator seed or private key. It does disclose
/// the account leaf index, account path, public-key set, randomized query
/// transcript, and linkable nullifier, so it must not be logged or sent to an
/// issuer/verifier.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldIdCompositionWitnessV1 {
    /// Contract version. Must be one.
    pub version: u8,
    /// Exact request item and timing bound to the witness.
    pub request: CompositionRequestV1,
    /// Exact WalletKit-selected credential and its subject blinding factor.
    pub credential: CompositionCredentialV1,
    /// Account membership and signed OPRF query witness.
    pub query: CompositionQueryV1,
    /// Verifiable OPRF transcript and resulting nullifier.
    pub oprf: CompositionOprfV1,
}

/// Atomic result produced from one credential snapshot and one canonical OPRF
/// execution.
pub struct WorldIdCompositionResultV1 {
    /// Stock `WalletKit` proof response generated from this exact witness.
    pub proof_response: crate::requests::ProofResponse,
    /// Private fused-circuit witness.
    pub witness: WorldIdCompositionWitnessV1,
}

impl std::fmt::Debug for WorldIdCompositionWitnessV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WorldIdCompositionWitnessV1")
            .field("version", &self.version)
            .field("request_id", &self.request.request_id)
            .field("issuer_schema_id", &self.request.issuer_schema_id)
            .field("private_witness", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl WorldIdCompositionWitnessV1 {
    pub(crate) fn from_full_oprf_output(
        output: &FullOprfOutput,
        request: &ProofRequest,
        item: &RequestItem,
        credential_input: &CredentialInput,
        raw_request_sha256: [u8; 32],
        generated_at: u64,
    ) -> Result<Self, String> {
        fn decimal(value: impl Into<U256>) -> String {
            Into::<U256>::into(value).to_string()
        }

        fn scalar_decimal(value: impl PrimeField) -> String {
            value.into_bigint().to_string()
        }

        let query = &output.query_proof_input;
        let oprf = &output.verifiable_oprf_output;
        let oprf_public_key = oprf.oprf_public_key.inner();
        let credential = &credential_input.credential;
        let signature = credential
            .signature
            .as_ref()
            .ok_or_else(|| "selected credential is unsigned".to_owned())?;
        let mut claims = std::array::from_fn(|_| "0".to_owned());
        if credential.claims.len() > CoreCredential::MAX_CLAIMS {
            return Err("selected credential has more than fifteen claims".to_owned());
        }
        for (output, claim) in claims.iter_mut().zip(&credential.claims) {
            *output = decimal(**claim);
        }

        Ok(Self {
            version: 1,
            request: CompositionRequestV1 {
                request_id: request.id.clone(),
                raw_request_sha256: hex::encode(raw_request_sha256),
                proof_type: "uniqueness".to_owned(),
                created_at: request.created_at,
                expires_at: request.expires_at,
                generated_at,
                identifier: item.identifier.clone(),
                issuer_schema_id: item.issuer_schema_id,
                oprf_key_id: request.oprf_key_id.into_inner().to_string(),
                signal_hash: decimal(*item.signal_hash()),
                genesis_issued_at_min: item.genesis_issued_at_min.unwrap_or(0),
                expires_at_min: item.effective_expires_at_min(request.created_at),
            },
            credential: CompositionCredentialV1 {
                id: credential.id,
                version: credential.version as u8,
                issuer_version: credential.issuer_version,
                issuer_schema_id: credential.issuer_schema_id,
                subject: decimal(*credential.sub),
                genesis_issued_at: credential.genesis_issued_at,
                expires_at: credential.expires_at,
                claims,
                associated_data_commitment: decimal(
                    *credential.associated_data_commitment,
                ),
                issuer_public_key: CompositionPointV1 {
                    x: decimal(credential.issuer.pk.x),
                    y: decimal(credential.issuer.pk.y),
                },
                signature_s: scalar_decimal(signature.s),
                signature_r: CompositionPointV1 {
                    x: decimal(signature.r.x),
                    y: decimal(signature.r.y),
                },
                subject_blinding_factor: decimal(credential_input.blinding_factor),
            },
            query: CompositionQueryV1 {
                user_public_keys: query.pk.map(|point| CompositionPointV1 {
                    x: decimal(point.x),
                    y: decimal(point.y),
                }),
                public_key_index: decimal(query.pk_index),
                query_signature_s: decimal(query.s),
                query_signature_r: CompositionPointV1 {
                    x: decimal(query.r.x),
                    y: decimal(query.r.y),
                },
                merkle_root: decimal(query.merkle_root),
                merkle_depth: decimal(query.depth),
                merkle_index: decimal(query.mt_index),
                merkle_siblings: query.siblings.map(decimal),
                beta: decimal(query.beta),
                rp_id: decimal(query.rp_id),
                action: decimal(query.action),
                nonce: decimal(query.nonce),
            },
            oprf: CompositionOprfV1 {
                dlog_e: decimal(oprf.dlog_proof.e()),
                dlog_s: decimal(oprf.dlog_proof.s()),
                public_key: CompositionPointV1 {
                    x: decimal(oprf_public_key.x),
                    y: decimal(oprf_public_key.y),
                },
                response_blinded: CompositionPointV1 {
                    x: decimal(oprf.blinded_response.x),
                    y: decimal(oprf.blinded_response.y),
                },
                response: CompositionPointV1 {
                    x: decimal(oprf.unblinded_response.x),
                    y: decimal(oprf.unblinded_response.y),
                },
                nullifier: decimal(oprf.output),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialized_contract_has_no_seed_or_private_key_field() {
        let value = serde_json::json!({
            "version": 1,
            "request": {
                "request_id": "request-1", "proof_type": "uniqueness",
                "raw_request_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
                "created_at": 1, "expires_at": 2, "generated_at": 1,
                "identifier": "passport", "issuer_schema_id": 42,
                "oprf_key_id": "23",
                "signal_hash": "0", "genesis_issued_at_min": 0,
                "expires_at_min": 1
            },
            "credential": {
                "id": 9, "version": 1, "issuer_version": 2,
                "issuer_schema_id": 42, "subject": "8",
                "genesis_issued_at": 1, "expires_at": 2,
                "claims": (0..15).map(|value| value.to_string()).collect::<Vec<_>>(),
                "associated_data_commitment": "10",
                "issuer_public_key": {"x":"11","y":"12"},
                "signature_s": "13", "signature_r": {"x":"14","y":"15"},
                "subject_blinding_factor": "16"
            },
            "query": {
                "user_public_keys": (0..7).map(|_| serde_json::json!({"x":"0","y":"1"})).collect::<Vec<_>>(),
                "public_key_index": "0", "query_signature_s": "1",
                "query_signature_r": {"x":"0","y":"1"},
                "merkle_root": "1", "merkle_depth": "30", "merkle_index": "1",
                "merkle_siblings": (0..30).map(|_| "0").collect::<Vec<_>>(),
                "beta": "1", "rp_id": "2", "action": "3", "nonce": "4"
            },
            "oprf": {
                "dlog_e": "1", "dlog_s": "1",
                "public_key": {"x":"1","y":"2"},
                "response_blinded": {"x":"3","y":"4"},
                "response": {"x":"5","y":"6"}, "nullifier": "7"
            }
        });
        let witness: WorldIdCompositionWitnessV1 =
            serde_json::from_value(value).expect("strict witness contract");
        let encoded = serde_json::to_string(&witness).expect("serialize witness");
        assert!(!encoded.contains("seed"));
        assert!(!encoded.contains("private_key"));
        assert!(encoded.contains("subject_blinding_factor"));
        assert!(format!("{witness:?}").contains("[REDACTED]"));
    }
}
