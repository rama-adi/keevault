# Docker Node example

A Node HTTP server that starts after you approve its Keevault request.
Follow the [Docker guide](../../apps/keevault-marketing/content/docs/examples/docker.mdx)
for configuration, build, and run steps.

Place a trusted Linux Keevault binary matching your image architecture in this
folder as `keevault`. The binary is ignored by Git. To build it from this checkout,
run from the repository root:

```sh
(cd apps/env-client && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o ../../examples/docker-node/keevault .)
```

Use `GOARCH=amd64` for an amd64 image. Edit `keevault.json` with your vault URL
and environment ID, then build with this directory as the context:

```sh
docker build -t keevault-node-example examples/docker-node
```

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
