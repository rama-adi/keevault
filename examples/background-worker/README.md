# Background heartbeat worker

A dependency-free Node.js 22+ worker that sends a heartbeat to an endpoint you
control. It uses `API_URL` and `API_KEY` from its environment, makes one request
at a time, and waits 60 seconds between attempts.

Configure your endpoint to accept `POST` requests with `Authorization: Bearer`
and a JSON body of `{"event":"heartbeat"}`. This is an example contract for your
own endpoint, not a Keevault API. Use HTTPS outside local testing.

1. Add `API_URL` and `API_KEY` to your Keevault environment.
2. Replace the vault URL and environment ID in `keevault.json`.
3. Install the keevault client and set `VAULT_BOOTSTRAP_TOKEN` in the process environment.
4. Run `keevault` from this directory and approve the boot in the dashboard.

The worker reads secrets through `process.env`. It logs only success, HTTP status,
or a generic failure. It does not log the endpoint, credentials, response body,
or raw network errors. Requests time out after 10 seconds. SIGTERM and SIGINT
cancel the current request or wait and exit the loop.

A process restart needs another Keevault approval. This example retries failures
while running; it does not store work or provide guaranteed delivery.

See the [background worker guide](../../apps/keevault-marketing/content/docs/examples/background-worker.mdx).
