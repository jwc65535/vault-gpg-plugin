# Vault Plugin: GPG Secret Backend [![Build Status](https://github.com/LeSuisse/vault-gpg-plugin/workflows/CI/badge.svg)](https://github.com/LeSuisse/vault-gpg-plugin/actions?query=workflow%3ACI) [![Code coverage](https://codecov.io/gh/LeSuisse/vault-gpg-plugin/branch/master/graph/badge.svg)](https://codecov.io/gh/LeSuisse/vault-gpg-plugin)

This is a standalone plugin for [HashiCorp Vault](https://www.github.com/hashicorp/vault).
This plugin handles GPG operations on data-in-transit in a similar fashion to what the
[transit secret backend](https://www.vaultproject.io/docs/secrets/transit) proposes.
Data sent to the backend are not stored.

As of today, the backend does not support encrypting data.

This backend has similar use cases with the [transit secret backend](https://www.vaultproject.io/docs/secrets/transit)
and the latter should be preferred if you do not need to interact with existing tools that are only GPG-aware.

## Features

- **Sign** data with a stored GPG key (detached signature, SHA-2 family hash algorithms)
- **Verify** detached signatures
- **Decrypt** GPG-encrypted messages, with optional signer verification
- **Show session key** — extract the symmetric session key from an encrypted message
- **Batch operations** — all four operations accept a `batch_input` array to process
  multiple items in a single API call, following the same conventions as the Vault
  transit secret backend

## Usage & setup

This is a [Vault plugin](https://www.vaultproject.io/docs/internals/plugins.html), you need to have a working installation
of Vault to use it.

To learn how to use plugins with Vault, see the [documentation on plugin backends](https://www.vaultproject.io/docs/plugin)
on the official Vault website. You can download and decompress the pre-compiled plugin binary for your architecture
from the [latest release on GitHub](https://github.com/LeSuisse/vault-gpg-plugin/releases). SHA256 checksum for the
pre-compiled plugin binary is also provided in the archive so it can be registered to your Vault plugin catalog.

All archives available from the [release tab on GitHub](https://github.com/LeSuisse/vault-gpg-plugin/releases).
All archives are signed using [Cosign](https://docs.sigstore.dev/cosign/verify/):

```
$ cosign verify-blob <file> --bundle <file>.bundle \
    --certificate-oidc-issuer='https://token.actions.githubusercontent.com' \
    --certificate-identity-regexp='https://github.com/LeSuisse/vault-gpg-plugin/\.github/workflows/Release\.yml'
```

Once mounted in Vault, this plugin exposes [this HTTP API](docs/http-api.md).

## Batch operations

The `sign`, `verify`, `decrypt`, and `show-session-key` endpoints each accept an
optional `batch_input` array. When present, the endpoint processes all items in a
single request and returns a `batch_results` array at the same index positions.

- A successful item carries its result field (`signature`, `valid`, `plaintext`, or
  `session_key`).
- A failed item carries only an `"error"` string — one item failing does not affect
  the others.
- Top-level parameters (`format`, `algorithm`) apply to every item in the batch.
- Single-item requests are fully backward compatible; `batch_input` is optional.

**Example — batch sign:**

```
$ curl \
    --header "X-Vault-Token: ..." \
    --request POST \
    --data '{"batch_input":[{"input":"dGhlIHF1aWNrIGJyb3duIGZveA=="},{"input":"aGVsbG8gd29ybGQ="}]}' \
    https://vault.example.com/v1/gpg/sign/my-key
```

```json
{
  "data": {
    "batch_results": [
      { "signature": "wsBc..." },
      { "signature": "wsBc..." }
    ]
  }
}
```

See the [HTTP API documentation](docs/http-api.md) for the full batch request and
response schema for each operation.
