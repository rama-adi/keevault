// Tiny demo app for the env-vault Zeabur example. No dependencies.
//
// GET /healthz responds 200 "ok" once the process is up. This is a process
// liveness check, not proof that the vault has delivered secrets: the
// container is not considered ready by the deployment until an administrator
// approves the boot, and vault-bootstrap does not start this process at all
// until that happens. See docs/zeabur.md and spec section 33.
//
// GET / responds with JSON listing the NAMES (never values) of every
// environment variable that starts with APP_, plus the process uptime.

const http = require("node:http");

const PORT = Number(process.env.PORT) || 3000;

function appVariableNames() {
  return Object.keys(process.env)
    .filter((name) => name.startsWith("APP_"))
    .sort();
}

const server = http.createServer((req, res) => {
  if (req.method !== "GET") {
    res.writeHead(405, { "content-type": "text/plain" });
    res.end("method not allowed");
    return;
  }

  if (req.url === "/healthz") {
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("ok");
    return;
  }

  if (req.url === "/") {
    const body = JSON.stringify({
      appVariableNames: appVariableNames(),
      uptimeSeconds: process.uptime(),
    });
    res.writeHead(200, { "content-type": "application/json" });
    res.end(body);
    return;
  }

  res.writeHead(404, { "content-type": "text/plain" });
  res.end("not found");
});

server.listen(PORT, () => {
  console.log(`listening on ${PORT}`);
});
