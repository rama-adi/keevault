# Releasing the keevault binary

CI builds static Linux amd64 and arm64 clients, uploads them and `SHA256SUMS`
to a GitHub release, then runs the built amd64 client to retrieve
`KEEVAULT_RELEASE_KEY` from keevault. After approval, the client launches the
registration script with that secret in its environment.

## Setup

Apply the vault D1 migrations before publishing:

```bash
vp run control-plane#db:migrate:remote
```

Store `KEEVAULT_RELEASE_KEY` as a Cloudflare Worker secret and store the same
value in keevault environment `env_01M24MPYYQWKX1WYK0H2V31F90`.
Create a bootstrap token for that environment and save it as
`VAULT_BOOTSTRAP_TOKEN` in the GitHub `releases` environment. The release key
itself stays in keevault and Cloudflare. The job waits up to 30 minutes for boot
approval. Its config is `scripts/release.keevault.json`.

The GitHub repository must be public for anonymous binary downloads. The job
uses its GitHub token with `contents: write` to upload assets. R2 credentials,
buckets, and bindings are no longer required.

## Publish

Push a SemVer tag such as `v1.0.0` or `v1.1.0-rc.1`. Build metadata is not
accepted. Approve the release job's boot in keevault when it appears. CI posts
both architectures to `/binary.json` using `Authorization: Bearer <release key>`.
The database registers both binaries in one transaction. Repeating the same
publication is safe; changing an existing version's URL or hash returns 409.

If registration fails after the GitHub release is published, rerun the job.
It checks existing assets against the build artifacts before registering them.
A partial GitHub upload requires repairing the release before retrying.
Never move a published tag or replace its binaries.

## Binary catalog

`GET https://vault.keevault.my.id/binary.json` is public and reads D1 directly:

```json
{
  "latest": "v1.0.0",
  "binaries": [
    {
      "id": "generated-uuid",
      "version": "v1.0.0",
      "arch": "amd64",
      "hash": "64-character-lowercase-sha256",
      "createdat": "2026-09-10T00:00:00.000Z",
      "url": "https://github.com/rama-adi/keevault/releases/download/v1.0.0/keevault-linux-amd64"
    }
  ]
}
```

The actual catalog includes both architectures for every published version.
`latest` is the highest SemVer, including prereleases, and is `null` before the
first publication. A stable version sorts above its own prereleases. Publishing
an older version later never moves latest backwards. Clients select their
architecture and the version matching `latest`, then download the direct URL.
The endpoint performs no GitHub API calls. Hashes are supplied by trusted CI;
the control plane does not independently download or attest the binaries.

## Build and consume

To build locally without publishing:

```bash
RELEASE_VERSION=v1.0.0 bash scripts/build-release.sh
```

The example in `examples/zeabur-node-app` downloads a pinned GitHub release at
image build time. Set `KEEVAULT_RELEASE_URL=https://github.com/rama-adi/keevault`,
`KEEVAULT_VERSION`, and the architecture-specific `KEEVAULT_SHA256_AMD64` and
`KEEVAULT_SHA256_ARM64` values from reviewed build artifacts. Pinning the hash
separately makes replacement binaries fail verification.

Deploy the updated control plane before distributing reporting clients. Older
clients remain accepted, but older servers may reject the `claims.client`
field. Client version and executable digest claims remain untrusted reports.
