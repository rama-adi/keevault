# Releasing the keevault binary

Build the client once in CI and let workload images download it from R2. This
keeps Go out of application builds and gives each deployment a version and
checksum it can review and pin. Download at image build time so a running
container does not depend on R2 being available when it boots.

## Set up distribution

Create a dedicated R2 bucket for public binaries, then attach a public custom
domain such as `downloads.example.com`. Cloudflare recommends the custom-domain
path for production rather than the rate-limited `r2.dev` development URL.
See [public bucket configuration](https://developers.cloudflare.com/r2/buckets/public-buckets/).

Create R2 S3 credentials scoped to this bucket with object read and write
permissions. The workflow uses the AWS CLI with the R2 S3 endpoint, as described
in [Cloudflare's S3 setup](https://developers.cloudflare.com/r2/get-started/s3/).

Create a GitHub environment named `releases`. Configure these values there:

| Kind     | Name                   | Value                   |
| -------- | ---------------------- | ----------------------- |
| Variable | `R2_ACCOUNT_ID`        | Cloudflare account ID   |
| Variable | `R2_BUCKET`            | Release bucket name     |
| Secret   | `R2_ACCESS_KEY_ID`     | R2 S3 access key ID     |
| Secret   | `R2_SECRET_ACCESS_KEY` | R2 S3 secret access key |

Protect release tags and restrict who can publish to this environment. No R2
credentials belong in Docker build arguments, workload variables, or the repo.
The workflow does not provision the bucket, credentials, or public domain.

## Publish

Push a version tag such as `v1.0.0`. Publication accepts `vMAJOR.MINOR.PATCH`
with an optional prerelease suffix containing letters, digits, dots, or hyphens.
Build metadata with `+` is not accepted. Other tags starting with `v` still trigger
the build job but fail version validation in the publish job. `.github/workflows/release-client.yml` runs Go
vet and tests, builds static Linux amd64 and arm64 clients, and retains them as
a GitHub Actions artifact before publishing to R2:

```text
releases/v1.0.0/keevault-linux-amd64
releases/v1.0.0/keevault-linux-arm64
releases/v1.0.0/SHA256SUMS
```

The workflow rejects a version prefix that already contains objects. A partial
upload therefore needs operator cleanup before retrying, or a new version tag.
This check prevents routine overwrites; bucket access policies still control
other writers. Never move a published tag or replace its binaries.

To build and inspect artifacts locally without publishing, run from the repository
root with Go 1.26 or newer. This script builds binaries and checksums; it does
not run vet or tests:

```bash
bash scripts/build-release.sh
cat apps/env-client/dist/SHA256SUMS
```

## Consume a release

Use the example Dockerfile in `examples/zeabur-node-app`. Set
`KEEVAULT_RELEASE_URL` to the HTTPS custom-domain origin and `KEEVAULT_VERSION`
to the version tag. Pin `KEEVAULT_SHA256_AMD64` and `KEEVAULT_SHA256_ARM64` in
reviewed build configuration using the CI artifact's checksum manifest.
Only the target platform's checksum is required for a single-platform build.

Do not fetch a checksum from R2 during the Docker build and trust it alongside
the binary. A pinned checksum makes a modified binary fail even if someone
replaces both the public binary and its checksum file. It does not establish
trust in the original build; protect CI and review releases before pinning.

The image build fails for missing checksums, unknown architectures, non-HTTPS
URLs, malformed versions, failed downloads, or checksum mismatches. The final
image copies only the client binary from the download stage alongside the Node
app. The Node base image still supplies its own utilities, including the `wget`
used by the Docker health check.
