/**
 * End to end harness: one real boot, from hello to exec.
 *
 * Run it with `vp run control-plane#e2e`. It applies both local D1 migrations,
 * starts `vp dev` with `VAULT_E2E=1` on a free port, builds the Go client, and
 * drives four scenarios against that stack. The approval comes from the harness
 * routes in `src/server/worker.e2e.ts`, because a passkey assertion cannot be
 * produced headlessly.
 *
 * Nothing here prints a secret value or a bootstrap token. The seeded secrets
 * are checked by length only, and the token is referred to by its `tok_` id.
 */

import { spawn, type ChildProcess } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { createServer, connect, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { argv, env as processEnv, exit, kill, stdout } from "node:process";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { z } from "zod";

const APP_DIRECTORY = dirname(dirname(fileURLToPath(import.meta.url)));
const REPO_ROOT = dirname(dirname(APP_DIRECTORY));
const GO_CLIENT_DIRECTORY = join(REPO_ROOT, "apps", "env-client");
const VP = join(REPO_ROOT, "node_modules", ".bin", "vp");
const WRANGLER = join(APP_DIRECTORY, "node_modules", ".bin", "wrangler");

/** How long the dev server may take to answer its first request. */
const DEV_READY_TIMEOUT_MS = 180_000;
/** How long one scenario may take from client start to final assertion. */
const SCENARIO_TIMEOUT_MS = 180_000;
/** Gap between polls of a boot's status. */
const POLL_INTERVAL_MS = 250;

// ------------------------------------------------------------------ output

let failures = 0;

function say(line: string): void {
  stdout.write(`${line}\n`);
}

function step(line: string): void {
  say(`  - ${line}`);
}

function check(passed: boolean, description: string): boolean {
  step(`${passed ? "pass" : "FAIL"}  ${description}`);
  if (!passed) failures += 1;
  return passed;
}

// ------------------------------------------------------------- child procs

interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
}

function run(
  command: string,
  args: readonly string[],
  cwd: string,
  extraEnv: ReadonlyMap<string, string> = new Map(),
): Promise<RunResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, [...args], {
      cwd,
      env: { ...processEnv, ...Object.fromEntries(extraEnv) },
    });
    let out = "";
    let err = "";
    child.stdout.on("data", (chunk: Buffer) => {
      out += chunk.toString("utf8");
    });
    child.stderr.on("data", (chunk: Buffer) => {
      err += chunk.toString("utf8");
    });
    child.on("error", reject);
    child.on("close", (code) => {
      resolve({ code: code ?? -1, stdout: out, stderr: err });
    });
  });
}

async function mustRun(
  command: string,
  args: readonly string[],
  cwd: string,
  what: string,
): Promise<RunResult> {
  const result = await run(command, args, cwd);
  if (result.code !== 0) {
    say(`${what} failed with exit ${result.code}`);
    say(result.stdout);
    say(result.stderr);
    throw new Error(what);
  }
  return result;
}

// ------------------------------------------------------------------ ports

/** What `server.address()` returns for a TCP listener. */
const listenAddressSchema = z.object({ port: z.number().int().positive() });

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.on("error", reject);
    // No host: the port must be free on every stack, because the dev server
    // binds the IPv6 loopback and the proxy binds whatever localhost resolves to.
    server.listen(0, () => {
      const address = listenAddressSchema.safeParse(server.address());
      if (!address.success) {
        server.close();
        reject(new Error("the probe socket reported no TCP port"));
        return;
      }
      const { port } = address.data;
      server.close(() => {
        resolve(port);
      });
    });
  });
}

/**
 * A TCP proxy in front of the dev server.
 *
 * The reconnect scenario needs the client's socket to die without the vault
 * losing its Durable Object state, which restarting the dev server would not
 * give. `dropAll` destroys every socket in flight; the client then reconnects
 * to the same still-running vault and resumes.
 */
interface Proxy {
  port: number;
  dropAll: () => void;
  close: () => Promise<void>;
}

async function startProxy(targetPort: number): Promise<Proxy> {
  const live = new Set<Socket>();
  const server = createServer((client: Socket) => {
    const upstream = connect(targetPort, "localhost");
    live.add(client);
    live.add(upstream);
    const drop = (): void => {
      live.delete(client);
      live.delete(upstream);
      client.destroy();
      upstream.destroy();
    };
    client.on("error", drop);
    upstream.on("error", drop);
    client.on("close", drop);
    upstream.on("close", drop);
    client.pipe(upstream);
    upstream.pipe(client);
  });
  const port = await freePort();
  await new Promise<void>((resolve) => {
    server.listen(port, "localhost", resolve);
  });
  return {
    port,
    dropAll(): void {
      for (const socket of live) socket.destroy();
      live.clear();
    },
    close(): Promise<void> {
      return new Promise((resolve) => {
        for (const socket of live) socket.destroy();
        server.close(() => {
          resolve();
        });
      });
    },
  };
}

// -------------------------------------------------------------- dev server

/** Signal a whole process group and ignore a group that is already gone. */
function killGroup(pid: number, signal: NodeJS.Signals): void {
  try {
    kill(-pid, signal);
  } catch {
    // Already gone.
  }
}

interface DevServer {
  origin: string;
  port: number;
  stop: () => Promise<void>;
  log: () => string;
}

async function startDevServer(secret: string): Promise<DevServer> {
  const port = await freePort();
  // Its own process group, so the whole dev server tree goes away on teardown.
  // `vp dev` starts workerd and a vite child, and killing only the parent would
  // leave those holding the port.
  const child: ChildProcess = spawn(VP, ["dev", "--port", String(port)], {
    cwd: APP_DIRECTORY,
    detached: true,
    env: { ...processEnv, VAULT_E2E: "1", VAULT_E2E_SECRET: secret },
  });
  let log = "";
  child.stdout?.on("data", (chunk: Buffer) => {
    log += chunk.toString("utf8");
  });
  child.stderr?.on("data", (chunk: Buffer) => {
    log += chunk.toString("utf8");
  });

  // The dev server binds the loopback under the name localhost, which on this
  // machine is the IPv6 address only, so every client uses the name.
  const origin = `http://localhost:${String(port)}`;
  const deadline = Date.now() + DEV_READY_TIMEOUT_MS;
  for (;;) {
    if (Date.now() > deadline) {
      child.kill("SIGKILL");
      say(log);
      throw new Error("the dev server never answered /api/auth/ok");
    }
    try {
      const response = await fetch(`${origin}/api/auth/ok`);
      if (response.ok) break;
    } catch {
      // Not listening yet.
    }
    await delay(500);
  }

  return {
    origin,
    port,
    log: () => log,
    async stop(): Promise<void> {
      const group = child.pid;
      if (group === undefined) return;
      const exited = new Promise<void>((resolve) => {
        if (child.exitCode !== null) {
          resolve();
          return;
        }
        child.on("exit", () => {
          resolve();
        });
      });
      killGroup(group, "SIGTERM");
      await Promise.race([exited, delay(5_000)]);
      killGroup(group, "SIGKILL");
      await Promise.race([exited, delay(2_000)]);
    },
  };
}

// ------------------------------------------------------------ harness API

const seedSchema = z.object({
  projectId: z.string(),
  environmentId: z.string(),
  tokenId: z.string(),
  token: z.string(),
  secrets: z.array(z.object({ name: z.string(), length: z.number() })),
});

const bootViewSchema = z.object({
  bootId: z.string(),
  status: z.string(),
  environmentId: z.string(),
});

const bootListSchema = z.array(bootViewSchema);

const actionSchema = z.object({
  ok: z.boolean(),
  status: z.string().nullable(),
  reason: z.string().nullable(),
  message: z.string().nullable(),
});

type SeedResult = z.infer<typeof seedSchema>;
type BootView = z.infer<typeof bootViewSchema>;
type ActionResult = z.infer<typeof actionSchema>;

class Harness {
  readonly #origin: string;
  readonly #secret: string;

  constructor(origin: string, secret: string) {
    this.#origin = origin;
    this.#secret = secret;
  }

  async #call(method: string, path: string): Promise<Response> {
    const response = await fetch(`${this.#origin}${path}`, {
      method,
      headers: { "x-vault-e2e-secret": this.#secret },
    });
    if (!response.ok) {
      throw new Error(`${method} ${path} answered ${String(response.status)}`);
    }
    return response;
  }

  async seed(): Promise<SeedResult> {
    const response = await this.#call("POST", "/__e2e/seed");
    return seedSchema.parse(await response.json());
  }

  async live(environmentId: string): Promise<BootView[]> {
    const response = await this.#call("GET", `/__e2e/boots/${environmentId}`);
    return bootListSchema.parse(await response.json());
  }

  async boot(bootId: string): Promise<BootView | null> {
    const response = await fetch(`${this.#origin}/__e2e/boot/${bootId}`, {
      headers: { "x-vault-e2e-secret": this.#secret },
    });
    if (!response.ok) return null;
    return bootListSchema.parse(await response.json())[0] ?? null;
  }

  async approve(bootId: string): Promise<ActionResult> {
    const response = await this.#call("POST", `/__e2e/approve/${bootId}`);
    return actionSchema.parse(await response.json());
  }

  async decline(bootId: string): Promise<ActionResult> {
    const response = await this.#call("POST", `/__e2e/decline/${bootId}`);
    return actionSchema.parse(await response.json());
  }

  async revoke(tokenId: string): Promise<ActionResult> {
    const response = await this.#call("POST", `/__e2e/revoke/${tokenId}`);
    return actionSchema.parse(await response.json());
  }
}

// ------------------------------------------------------------- the client

interface ClientRun {
  wait: Promise<RunResult>;
  kill: () => void;
}

function startClient(
  binary: string,
  vaultOrigin: string,
  token: string,
  command: readonly string[],
): ClientRun {
  const child = spawn(binary, ["--", ...command], {
    cwd: APP_DIRECTORY,
    env: {
      ...processEnv,
      VAULT_URL: vaultOrigin,
      VAULT_BOOTSTRAP_TOKEN: token,
      VAULT_PENDING_TIMEOUT: "3m",
      VAULT_LOG_LEVEL: "debug",
    },
  });
  let out = "";
  let err = "";
  child.stdout.on("data", (chunk: Buffer) => {
    out += chunk.toString("utf8");
  });
  child.stderr.on("data", (chunk: Buffer) => {
    err += chunk.toString("utf8");
  });
  const wait = new Promise<RunResult>((resolve, reject) => {
    child.on("error", reject);
    child.on("close", (code) => {
      resolve({ code: code ?? -1, stdout: out, stderr: err });
    });
  });
  return {
    wait,
    kill(): void {
      child.kill("SIGKILL");
    },
  };
}

/** Wait for a boot to appear on the environment and return its id. */
async function waitForFirstBoot(harness: Harness, environmentId: string): Promise<string> {
  const deadline = Date.now() + SCENARIO_TIMEOUT_MS;
  for (;;) {
    const live = await harness.live(environmentId);
    const first = live[0];
    if (first !== undefined) return first.bootId;
    if (Date.now() > deadline) throw new Error("no boot appeared on the environment");
    await delay(POLL_INTERVAL_MS);
  }
}

/**
 * Poll one boot until it reaches a wanted status, recording every distinct
 * status seen so the report can show the real transitions.
 */
async function waitForStatus(
  harness: Harness,
  bootId: string,
  wanted: readonly string[],
  seen: string[],
): Promise<string> {
  const deadline = Date.now() + SCENARIO_TIMEOUT_MS;
  for (;;) {
    const view = await harness.boot(bootId);
    if (view !== null && seen.at(-1) !== view.status) seen.push(view.status);
    if (view !== null && wanted.includes(view.status)) return view.status;
    if (Date.now() > deadline) {
      throw new Error(
        `boot ${bootId} never reached ${wanted.join(" or ")}, saw ${seen.join(" -> ")}`,
      );
    }
    await delay(POLL_INTERVAL_MS);
  }
}

/**
 * The audit actions written for one boot, in order.
 *
 * Polling the Durable Object misses APPROVED and DELIVERED when a client is
 * already attached, because delivery follows approval inside one call. The
 * audit log records every step, so the report shows it next to the polled
 * statuses.
 */
async function auditTrace(bootId: string): Promise<string[]> {
  const rows = await d1(
    `SELECT action FROM audit_events WHERE boot_id = '${bootId}' ORDER BY timestamp, id`,
  );
  return [...rows.matchAll(/"action":\s*"([a-z.-]+)"/g)].map((match) => match[1] ?? "");
}

/** Read one column from the local vault D1 through wrangler. */
async function d1(sql: string): Promise<string> {
  const result = await mustRun(
    WRANGLER,
    ["d1", "execute", "VAULT_DB", "--local", "--json", "--command", sql],
    APP_DIRECTORY,
    "wrangler d1 execute",
  );
  return result.stdout;
}

// ------------------------------------------------------------- scenarios

/** The command the client execs. It prints lengths, never values. */
const TARGET_COMMAND = [
  "sh",
  "-c",
  'echo "BOOTED ${#APP_DB_URL} ${#APP_API_KEY}"; sleep 1',
] as const;

function expectedBootedLine(seed: SeedResult): string {
  const lengths = seed.secrets.map((secret) => String(secret.length)).join(" ");
  return `BOOTED ${lengths}`;
}

async function scenarioApproval(harness: Harness, binary: string, origin: string): Promise<void> {
  say("\nScenario 1: approve a pending boot");
  const seed = await harness.seed();
  step(`seeded ${seed.environmentId} with token ${seed.tokenId}`);
  const client = startClient(binary, origin, seed.token, TARGET_COMMAND);
  const seen: string[] = [];
  try {
    const bootId = await waitForFirstBoot(harness, seed.environmentId);
    step(`boot ${bootId}`);
    await waitForStatus(harness, bootId, ["PENDING"], seen);
    const approved = await harness.approve(bootId);
    check(approved.ok, `approve returned ok (status ${approved.status ?? "none"})`);
    const result = await client.wait;
    check(result.code === 0, `client exited 0, got ${String(result.code)}`);
    check(
      result.stdout.includes(expectedBootedLine(seed)),
      `child printed ${expectedBootedLine(seed)}`,
    );
    await waitForStatus(harness, bootId, ["CONSUMED"], seen);
    step(`transitions: ${seen.join(" -> ")}`);

    const rows = await d1(`SELECT status FROM boot_requests WHERE id = '${bootId}'`);
    check(rows.includes('"status": "CONSUMED"'), "the D1 boot_requests row is CONSUMED");
    const audit = await auditTrace(bootId);
    step(`audit: ${audit.join(" -> ")}`);
    for (const action of ["boot.requested", "boot.approved", "boot.delivered", "boot.consumed"]) {
      check(audit.includes(action), `audit has ${action}`);
    }
  } finally {
    client.kill();
  }
}

async function scenarioReconnect(harness: Harness, binary: string, devPort: number): Promise<void> {
  say("\nScenario 2: drop the socket while pending, then approve");
  const proxy = await startProxy(devPort);
  const seed = await harness.seed();
  step(`seeded ${seed.environmentId} with token ${seed.tokenId}`);
  const client = startClient(
    binary,
    `http://localhost:${String(proxy.port)}`,
    seed.token,
    TARGET_COMMAND,
  );
  const seen: string[] = [];
  try {
    const bootId = await waitForFirstBoot(harness, seed.environmentId);
    step(`boot ${bootId}`);
    await waitForStatus(harness, bootId, ["PENDING"], seen);
    proxy.dropAll();
    step("dropped every proxied socket");
    // The client backs off from one second, so give it room to come back and
    // finish the resume handshake before the approval lands.
    await delay(6_000);
    const approved = await harness.approve(bootId);
    check(approved.ok, `approve returned ok (status ${approved.status ?? "none"})`);
    const result = await client.wait;
    check(result.code === 0, `client exited 0, got ${String(result.code)}`);
    check(result.stderr.includes("reconnecting"), "the client logged a reconnect");
    check(
      result.stdout.includes(expectedBootedLine(seed)),
      `child printed ${expectedBootedLine(seed)}`,
    );
    await waitForStatus(harness, bootId, ["CONSUMED"], seen);
    step(`transitions: ${seen.join(" -> ")}`);
    const audit = await auditTrace(bootId);
    step(`audit: ${audit.join(" -> ")}`);
    check(audit.includes("boot.reconnected"), "audit has boot.reconnected");
    check(audit.includes("boot.consumed"), "audit has boot.consumed");
  } finally {
    client.kill();
    await proxy.close();
  }
}

async function scenarioDecline(harness: Harness, binary: string, origin: string): Promise<void> {
  say("\nScenario 3: decline a pending boot");
  const seed = await harness.seed();
  const client = startClient(binary, origin, seed.token, TARGET_COMMAND);
  const seen: string[] = [];
  try {
    const bootId = await waitForFirstBoot(harness, seed.environmentId);
    step(`boot ${bootId}`);
    await waitForStatus(harness, bootId, ["PENDING"], seen);
    const declined = await harness.decline(bootId);
    check(declined.ok, "decline returned ok");
    const result = await client.wait;
    check(result.code === 3, `client exited 3, got ${String(result.code)}`);
    check(result.stdout.length === 0, "the child never ran");
    await waitForStatus(harness, bootId, ["DECLINED"], seen);
    step(`transitions: ${seen.join(" -> ")}`);
    step(`audit: ${(await auditTrace(bootId)).join(" -> ")}`);
  } finally {
    client.kill();
  }
}

async function scenarioRevoke(harness: Harness, binary: string, origin: string): Promise<void> {
  say("\nScenario 4: revoke the token while a boot is pending");
  const seed = await harness.seed();
  step(`seeded ${seed.environmentId} with token ${seed.tokenId}`);
  const client = startClient(binary, origin, seed.token, TARGET_COMMAND);
  const seen: string[] = [];
  try {
    const bootId = await waitForFirstBoot(harness, seed.environmentId);
    step(`boot ${bootId}`);
    await waitForStatus(harness, bootId, ["PENDING"], seen);
    await harness.revoke(seed.tokenId);
    step(`revoked ${seed.tokenId}`);
    const result = await client.wait;
    check(result.code === 4, `client exited 4, got ${String(result.code)}`);
    check(result.stderr.includes("boot canceled"), "the client reported the boot as canceled");
    await waitForStatus(harness, bootId, ["CANCELED"], seen);
    step(`transitions: ${seen.join(" -> ")}`);
    const audit = await auditTrace(bootId);
    step(`audit: ${audit.join(" -> ")}`);
    check(audit.includes("boot.canceled"), "audit has boot.canceled");
  } finally {
    client.kill();
  }
}

// ------------------------------------------------------------------ main

/**
 * The harness secret comes from `.dev.vars`, because that is the file the dev
 * server reads. Only the presence of the name is reported, never the value.
 */
async function harnessSecret(): Promise<string> {
  const path = join(APP_DIRECTORY, ".dev.vars");
  let contents = "";
  try {
    contents = await readFile(path, "utf8");
  } catch {
    throw new Error(`${path} is missing. Copy .dev.vars.example and fill it in.`);
  }
  for (const line of contents.split("\n")) {
    const match = /^VAULT_E2E_SECRET\s*=\s*"?([^"\r]+)"?\s*$/.exec(line);
    if (match?.[1] !== undefined) return match[1];
  }
  throw new Error("VAULT_E2E_SECRET is not set in .dev.vars. See .dev.vars.example.");
}

async function main(): Promise<number> {
  const only = argv[2] ?? "";
  const secret = await harnessSecret();

  say("Applying local D1 migrations");
  await mustRun(
    WRANGLER,
    ["d1", "migrations", "apply", "VAULT_DB", "--local"],
    APP_DIRECTORY,
    "vault migrations",
  );
  await mustRun(
    WRANGLER,
    ["d1", "migrations", "apply", "AUTH_DB", "--local"],
    APP_DIRECTORY,
    "auth migrations",
  );

  say("Building the Go client");
  const workspace = await mkdtemp(join(tmpdir(), "keevault-e2e-"));
  const binary = join(workspace, "keevault");
  await mustRun("go", ["build", "-o", binary, "."], GO_CLIENT_DIRECTORY, "go build");

  say("Starting the dev server with VAULT_E2E=1");
  const dev = await startDevServer(secret);
  say(`  dev server on ${dev.origin}`);
  const harness = new Harness(dev.origin, secret);

  try {
    if (only === "" || only === "approval") await scenarioApproval(harness, binary, dev.origin);
    if (only === "" || only === "reconnect") await scenarioReconnect(harness, binary, dev.port);
    if (only === "" || only === "decline") await scenarioDecline(harness, binary, dev.origin);
    if (only === "" || only === "revoke") await scenarioRevoke(harness, binary, dev.origin);
  } catch (error) {
    failures += 1;
    say(`\nharness error: ${error instanceof Error ? error.message : "unknown"}`);
    say(dev.log().slice(-4000));
  } finally {
    await dev.stop();
    await rm(workspace, { recursive: true, force: true });
  }

  say(failures === 0 ? "\nAll scenarios passed." : `\n${String(failures)} check(s) failed.`);
  return failures === 0 ? 0 : 1;
}

exit(await main());
