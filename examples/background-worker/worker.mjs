import { setTimeout } from "node:timers/promises";

const { API_URL, API_KEY } = process.env;

if (!API_URL || !API_KEY) {
  throw new Error("API_URL and API_KEY are required");
}

const endpoint = new URL(API_URL);
if (!["https:", "http:"].includes(endpoint.protocol)) {
  throw new Error("API_URL must use HTTP or HTTPS");
}

const shutdown = new AbortController();
const stop = () => shutdown.abort();
process.once("SIGTERM", stop);
process.once("SIGINT", stop);

console.log("Heartbeat worker started");

while (!shutdown.signal.aborted) {
  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        authorization: `Bearer ${API_KEY}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ event: "heartbeat" }),
      signal: AbortSignal.any([shutdown.signal, AbortSignal.timeout(10_000)]),
    });
    await response.body?.cancel();
    console.log(response.ok ? "Heartbeat sent" : `Heartbeat rejected: ${response.status}`);
  } catch {
    if (shutdown.signal.aborted) break;
    console.error("Heartbeat failed; retrying in 60 seconds");
  }

  try {
    await setTimeout(60_000, undefined, { signal: shutdown.signal });
  } catch {
    break;
  }
}

console.log("Heartbeat worker stopped");
