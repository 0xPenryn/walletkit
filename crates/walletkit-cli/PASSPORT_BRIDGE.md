# Passport presentation bridge

This fork adds a two-phase `IDKit` bridge flow for composing WalletKit's stock
World ID proof with an opaque selective-disclosure proof. WalletKit still owns
the account, credential selection, OPRF call, nullifier, and stock proof. The
external prover receives a private witness for the same execution and returns
a named extension response.

The decrypted bridge request is:

```json
{
  "proof_request": {},
  "world_request_json": "{...exact JSON bytes...}",
  "request_extensions": [
    {
      "name": "org.worldcoin.passport.selective_disclosure.v1",
      "version": 1,
      "media_type": "application/json",
      "payload_json": "{...exact JSON bytes...}"
    }
  ],
  "environment": "staging"
}
```

`world_request_json` is kept as a string so an arbitrary `u64` schema ID is
never routed through JavaScript's lossy number representation. It must parse to
the same JSON value as `proof_request`. Composition v1 requires exactly one
World proof request item. The raw bytes of that item's `signal` must equal the
`payload_json` bytes of exactly one request extension; zero or multiple matches
are rejected.

Fetch the request and generate both WalletKit outputs atomically:

```sh
walletkit --root .walletkit --json proof bridge-export \
  --bridge-url "$CONNECTOR_URL" \
  --request-out request.json \
  --proof-out world-proof.json \
  --witness-out composition-witness.json \
  --extensions-out request-extensions.json
```

All four paths are new files created with mode `0600` on Unix. Existing files
are never overwritten. `request.json` is byte-for-byte `world_request_json`;
the other three are compact JSON. The witness includes the selected credential
and blinding factor plus linkable account-path and OPRF material. It contains no
authenticator seed or private signing key, but must stay local.

After the external prover writes an extension-response array with the same
names, versions, and media types as the request extensions, submit both proofs:

```sh
walletkit --environment staging --json proof bridge-submit \
  --bridge-url "$CONNECTOR_URL" \
  --request request.json \
  --proof world-proof.json \
  --extension-responses extension-responses.json
```

WalletKit fetches the connector request again, requires an exact byte match
with `request.json`, structurally validates the stock response against that
request, and rejects missing, extra, duplicate, or metadata-mismatched
extensions. The encrypted response is:

```json
{
  "proof_response": {},
  "extension_responses": [
    {
      "name": "org.worldcoin.passport.selective_disclosure.v1",
      "version": 1,
      "media_type": "application/json",
      "payload_json": "{...opaque response JSON...}"
    }
  ]
}
```

Bridge traffic uses AES-256-GCM. HTTPS is required except for loopback HTTP
used by local development, redirects are disabled, and encrypted payloads are
bounded. A stock request without extensions can still be fulfilled in one step
with `walletkit proof generate --bridge-url "$CONNECTOR_URL"`.
