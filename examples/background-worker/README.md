# Background heartbeat worker

A dependency-free Node.js 22+ worker that sends a heartbeat to an endpoint you
control. It uses `API_URL` and `API_KEY` from its environment, makes one request
at a time, and waits 60 seconds between attempts.

Configure your endpoint to accept `POST` requests with `Authorization: Bearer`
and a JSON body of `{"event":"heartbeat"}`. This is an example contract for your
own endpoint, not a Keevault API. Use HTTPS outside local testing.

1. Add `API_URL` and `API_KEY` to your Keevault environment.
2. Replace the vault URL and environment ID in `keevault.json`.
3. Set `VAULT_BOOTSTRAP_TOKEN` in the process environment.

From this directory on Linux amd64 or arm64, download and run the client:

```sh
curl -fsSL https://vault.keevault.my.id/download.sh | sh
./keevault
```

The downloader selects your architecture, verifies SHA-256 against the release
catalog, and saves executable `./keevault`. It requires `curl` and either
`sha256sum` or `shasum`. A failed download or hash check preserves an existing
binary. To select a published version, replace `v1.0.0` in this command:

```sh
curl -fsSL https://vault.keevault.my.id/download.sh | KEEVAULT_VER=v1.0.0 sh
```

Approve the boot in the dashboard to start the worker.

The worker reads secrets through `process.env`. It logs only success, HTTP status,
or a generic failure. It does not log the endpoint, credentials, response body,
or raw network errors. Requests time out after 10 seconds. SIGTERM and SIGINT
cancel the current request or wait and exit the loop.

A process restart needs another Keevault approval. This example retries failures
while running; it does not store work or provide guaranteed delivery.

See the [background worker guide](../../apps/keevault-marketing/content/docs/examples/background-worker.mdx).
