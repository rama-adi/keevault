import { DurableObject } from "cloudflare:workers";

/**
 * One instance per environment. It will own live boot state, hibernating
 * WebSocket connections and approval delivery (spec sections 14 to 17).
 *
 * This is a stub. The bootstrap WebSocket agent adds the real state machine,
 * the `/bootstrap/v1` upgrade handling and the SQLite-backed boot rows. Keep the
 * class name and the `new_sqlite_classes` migration tag in wrangler.jsonc stable
 * so the storage backend does not change under an existing deployment.
 */
export class EnvironmentSessionDO extends DurableObject<Env> {
  /** Liveness probe used by tests until the real RPC surface exists. */
  ping(): string {
    return "pong";
  }
}
