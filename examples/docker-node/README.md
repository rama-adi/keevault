# Docker Node example

A Node HTTP server that starts after you approve its Keevault request.
Follow the [Docker guide](../../apps/keevault-marketing/content/docs/examples/docker.mdx)
for configuration, build, and run steps.

The Dockerfile downloads Keevault from
`https://vault.keevault.my.id/download.sh` inside a Linux build stage. The script
selects amd64 or arm64, checks SHA-256 against the release catalog, and saves the
executable before it is copied into the application image. You can build this
image from macOS too.

Edit `keevault.json` with your vault URL and environment ID, then build from the
repository root with this directory as the context:

```sh
docker build -t keevault-node-example examples/docker-node
```

By default, the download uses the latest release when its build layer runs. To
pin a published tag, replace `v1.0.0` with that tag:

```sh
docker build --build-arg KEEVAULT_VER=v1.0.0 \
  -t keevault-node-example examples/docker-node
```

Docker may reuse a cached download layer. Add `--no-cache` for a fresh lookup
of `latest`. Use `--platform=linux/amd64` or `--platform=linux/arm64` to select
the image architecture. The build stage runs on that target and may need
emulation when it differs from your host.

The script checks the hash supplied by the control plane. For a build with an
independently reviewed checksum, use the explicit release URL and checksum
arguments shown in the [Zeabur example](../zeabur-node-app/README.md).

Create `API_KEY` in your Keevault environment and export its bootstrap token
as `VAULT_BOOTSTRAP_TOKEN` in your shell. Run:

```sh
docker run --rm --name keevault-node-example \
  -p 127.0.0.1:3000:3000 \
  -e VAULT_BOOTSTRAP_TOKEN \
  keevault-node-example
```

Approve the request in the dashboard, then open `http://localhost:3000`.
The server checks that `API_KEY` exists but never prints or returns its value.
The application command lives in the JSON file; do not append a command to
`docker run` or set an application `CMD` in the Dockerfile.
