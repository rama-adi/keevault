/**
 * The boot state machine (spec sections 14 to 18, protocol/websocket-v1.md).
 *
 * This class holds every rule and every write. It is deliberately free of
 * Cloudflare types: storage, the clock, randomness, the socket registry, the
 * alarm scheduler and the key unwrapper all arrive as dependencies. The Durable
 * Object in environment-session.ts is a thin shell that wires the real
 * implementations in, and the tests wire `node:sqlite` and fakes in instead, so
 * every transition is testable without workerd.
 *
 * The Durable Object is authoritative. Every D1 write in here is an index
 * update for the dashboard and is never read back to decide a transition
 * (spec section 20).
 */

import {
  b64uDecode,
  createBootEnvelope,
  keyFingerprint,
  sha256HexOfText,
  verifyResume,
} from "@keevault/crypto";
import {
  CLOSE_CODES,
  DEFAULT_CHALLENGE_TTL_SECONDS,
  Evidence as EvidenceSchema,
  MAX_PENDING_BOOTS_PER_TOKEN,
  WorkloadClaims as WorkloadClaimsSchema,
  isTerminal,
  parseClientFrame,
  transition,
  type BootApproved,
  type BootEvent,
  type BootStatus,
  type CloseCode,
  type Evidence,
  type SecretRecord,
  type ServerMessage,
  type WorkloadClaims,
} from "@keevault/protocol";
import {
  appendAuditEvent,
  getBootstrapTokenByTokenId,
  getEnvironment,
  insertBootApproval,
  insertBootRequest,
  listSecretsForDelivery,
  updateBootRequestStatus,
  type VaultDatabase,
} from "@keevault/vault-store";
import { z } from "zod";

import {
  evaluatePolicy,
  loadProvenanceContext,
  parseSummary,
  runVerifiers,
  summaryDigest,
  type ProvenanceVerifier,
  type VerificationResult,
} from "../provenance/index.ts";
import type { AuditAction } from "../vault/audit.ts";
import type { UnwrappedEnvironmentDek } from "../vault/keys.ts";
import type { BootSqlStorage } from "./boot-storage.ts";

/** The largest text frame the server accepts, from the protocol document. */
export const MAX_FRAME_BYTES = 1024 * 1024;

/** Boot requests one source address may create per window (spec section 37). */
export const MAX_BOOTS_PER_SOURCE = 10;

/** The window the source-address limit is measured over, in seconds. */
export const BOOT_RATE_WINDOW_SECONDS = 60;

/** The reason recorded when a resume finds the boot's token revoked or expired. */
const TOKEN_REVOKED_REASON = "bootstrap token revoked";

/** One socket the core can write to. */
export interface BootSocket {
  send(text: string): void;
  close(code: number, reason: string): void;
}

/** The socket a frame arrived on. It can be bound to one boot. */
export interface BootConnection extends BootSocket {
  /** The boot this socket is bound to, from its serialized attachment. */
  attachedBootId(): string | null;
  /** Bind this socket to a boot. Only `{ bootId, generation }` is stored. */
  attach(bootId: string, generation: number): void;
}

/** Every socket currently bound to a boot, across hibernation. */
export interface BootSocketRegistry {
  forBoot(bootId: string): readonly BootSocket[];
}

/** Who the socket authenticated as, taken from the upgrade or the socket tags. */
export interface BootIdentity {
  /** The `tok_`-prefixed D1 row id. */
  readonly tokenId: string;
  readonly sourceIp: string;
  readonly maxPendingBoots: number;
}

export interface BootSessionDeps {
  readonly storage: BootSqlStorage;
  readonly db: VaultDatabase;
  readonly environmentId: string;
  /** Epoch milliseconds. */
  readonly now: () => number;
  readonly newBootId: () => string;
  readonly newAuditId: () => string;
  /** b64u of 32 random bytes. */
  readonly randomChallenge: () => string;
  readonly unwrapDek: (environmentId: string) => Promise<UnwrappedEnvironmentDek>;
  readonly sockets: BootSocketRegistry;
  /** Called with the next deadline in epoch milliseconds, or null to clear. */
  readonly scheduleAlarm: (at: number | null) => void;
  readonly verifiers: readonly ProvenanceVerifier[];
}

/** Why an administrative action on a boot did not happen. */
export const BOOT_ACTION_FAILURES = [
  "not_found",
  "conflict",
  "terminal",
  "expired",
  "token_invalid",
  "policy_blocked",
  "evidence_mismatch",
  "key_error",
] as const;

export type BootActionFailure = (typeof BOOT_ACTION_FAILURES)[number];

export type BootActionResult =
  | { readonly ok: true; readonly status: BootStatus }
  | { readonly ok: false; readonly reason: BootActionFailure; readonly message: string };

export interface ApproveBootInput {
  readonly bootId: string;
  readonly approverUserId: string;
  readonly approverCredentialId: string;
  /** Digest of the provenance summary the approver actually read. */
  readonly evidenceDigest: string;
}

export interface DeclineBootInput {
  readonly bootId: string;
  readonly approverUserId: string;
  readonly reason: string;
}

export interface CancelBootInput {
  readonly bootId: string;
  readonly actorUserId: string;
  readonly reason: string;
}

/** One boot as the dashboard sees it. Carries no key material and no payload. */
export interface BootView {
  readonly bootId: string;
  readonly environmentId: string;
  readonly projectId: string;
  readonly status: BootStatus;
  readonly tokenId: string;
  readonly sourceIp: string | null;
  readonly signingFingerprint: string;
  readonly encryptionFingerprint: string;
  readonly claims: WorkloadClaims;
  readonly evidenceCount: number;
  readonly provenance: readonly VerificationResult[];
  readonly createdAt: string;
  readonly pendingExpiresAt: string | null;
  readonly approvedAt: string | null;
  readonly payloadExpiresAt: string | null;
  readonly consumedAt: string | null;
  readonly terminalReason: string | null;
  readonly connected: boolean;
}

const bootStatusSchema = z.enum([
  "PENDING",
  "APPROVED",
  "DELIVERED",
  "CONSUMED",
  "DECLINED",
  "EXPIRED",
  "CANCELED",
]);

const bootRowSchema = z.object({
  id: z.string(),
  environment_id: z.string(),
  project_id: z.string(),
  status: bootStatusSchema,
  token_id: z.string(),
  source_ip: z.string().nullable(),
  signing_pk: z.string(),
  encryption_pk: z.string(),
  signing_fp: z.string(),
  encryption_fp: z.string(),
  claims_json: z.string(),
  evidence_json: z.string(),
  provenance_json: z.string().nullable(),
  created_at: z.number(),
  pending_expires_at: z.number().nullable(),
  approved_at: z.number().nullable(),
  payload_expires_at: z.number().nullable(),
  delivered_frame: z.string().nullable(),
  payload_digest: z.string().nullable(),
  consumed_at: z.number().nullable(),
  terminal_reason: z.string().nullable(),
});

type BootRow = z.infer<typeof bootRowSchema>;

const challengeRowSchema = z.object({
  boot_id: z.string(),
  challenge: z.string(),
  expires_at: z.number(),
  used: z.number(),
});

const countRowSchema = z.object({ total: z.number() });
const deadlineRowSchema = z.object({ deadline: z.number().nullable() });

const jsonText = z.string().transform((text, context) => {
  try {
    return JSON.parse(text);
  } catch {
    context.addIssue({ code: "custom", message: "stored JSON is unreadable" });
    return z.NEVER;
  }
});

const claimsSchema = jsonText.pipe(WorkloadClaimsSchema);

const evidenceSchema = jsonText.pipe(z.array(EvidenceSchema));

const SCHEMA_STATEMENTS: readonly string[] = [
  `CREATE TABLE IF NOT EXISTS boots (
     id TEXT PRIMARY KEY,
     environment_id TEXT NOT NULL,
     project_id TEXT NOT NULL,
     status TEXT NOT NULL,
     token_id TEXT NOT NULL,
     source_ip TEXT,
     signing_pk TEXT NOT NULL,
     encryption_pk TEXT NOT NULL,
     signing_fp TEXT NOT NULL,
     encryption_fp TEXT NOT NULL,
     claims_json TEXT NOT NULL,
     evidence_json TEXT NOT NULL,
     provenance_json TEXT,
     created_at INTEGER NOT NULL,
     pending_expires_at INTEGER,
     approved_at INTEGER,
     payload_expires_at INTEGER,
     delivered_frame TEXT,
     payload_digest TEXT,
     consumed_at INTEGER,
     terminal_reason TEXT
   )`,
  `CREATE INDEX IF NOT EXISTS boots_by_status ON boots (status, created_at)`,
  `CREATE INDEX IF NOT EXISTS boots_by_token ON boots (token_id, status)`,
  `CREATE INDEX IF NOT EXISTS boots_by_source ON boots (source_ip, created_at)`,
  `CREATE TABLE IF NOT EXISTS challenges (
     boot_id TEXT NOT NULL,
     challenge TEXT NOT NULL,
     expires_at INTEGER NOT NULL,
     used INTEGER NOT NULL DEFAULT 0,
     PRIMARY KEY (boot_id, challenge)
   )`,
];

const BOOT_COLUMNS = `id, environment_id, project_id, status, token_id, source_ip, signing_pk,
  encryption_pk, signing_fp, encryption_fp, claims_json, evidence_json, provenance_json,
  created_at, pending_expires_at, approved_at, payload_expires_at, delivered_frame,
  payload_digest, consumed_at, terminal_reason`;

const LIVE_STATUSES = "('PENDING', 'APPROVED', 'DELIVERED')";

function iso(epochMillis: number): string {
  return new Date(epochMillis).toISOString();
}

function isoOrNull(epochMillis: number | null): string | null {
  return epochMillis === null ? null : iso(epochMillis);
}

function frameText(message: ServerMessage): string {
  return JSON.stringify(message);
}

/** Every close code a boot.error frame may carry. 1000 is not an error. */
type ErrorCloseCode = Exclude<CloseCode, typeof CLOSE_CODES.NORMAL>;

/** The one place a socket is told about a refusal, so the close code always matches. */
function sendError(socket: BootSocket, code: ErrorCloseCode, message: string): void {
  socket.send(frameText({ type: "boot.error", code, message }));
  socket.close(code, message.slice(0, 100));
}

export class BootSessionCore {
  readonly #deps: BootSessionDeps;

  constructor(deps: BootSessionDeps) {
    this.#deps = deps;
    for (const statement of SCHEMA_STATEMENTS) {
      this.#deps.storage.exec(statement);
    }
  }

  // ---------------------------------------------------------------- storage

  #readBoot(bootId: string): BootRow | null {
    const rows = this.#deps.storage.exec(`SELECT ${BOOT_COLUMNS} FROM boots WHERE id = ?`, bootId);
    const first = rows[0];
    return first === undefined ? null : bootRowSchema.parse(first);
  }

  #readLive(): BootRow[] {
    const rows = this.#deps.storage.exec(
      `SELECT ${BOOT_COLUMNS} FROM boots WHERE status IN ${LIVE_STATUSES} ORDER BY created_at`,
    );
    return rows.map((row) => bootRowSchema.parse(row));
  }

  #countPending(tokenId: string): number {
    const rows = this.#deps.storage.exec(
      "SELECT COUNT(*) AS total FROM boots WHERE token_id = ? AND status = 'PENDING'",
      tokenId,
    );
    const first = rows[0];
    return first === undefined ? 0 : countRowSchema.parse(first).total;
  }

  /**
   * Boots this source address created inside the rate window (spec section 37).
   * Derived from `boots.created_at`, so it counts every request the address
   * made, not only the ones that are still pending.
   */
  #countRecentFromSource(sourceIp: string): number {
    const rows = this.#deps.storage.exec(
      "SELECT COUNT(*) AS total FROM boots WHERE source_ip = ? AND created_at > ?",
      sourceIp,
      this.#deps.now() - BOOT_RATE_WINDOW_SECONDS * 1000,
    );
    const first = rows[0];
    return first === undefined ? 0 : countRowSchema.parse(first).total;
  }

  /**
   * Apply one event through the shared transition table and write the new state.
   * Nothing else in this class writes `boots.status`.
   */
  #apply(boot: BootRow, event: BootEvent): BootStatus | null {
    const result = transition(boot.status, event);
    if (!result.ok) return null;
    this.#deps.storage.exec("UPDATE boots SET status = ? WHERE id = ?", result.to, boot.id);
    return result.to;
  }

  #recomputeAlarm(): void {
    const rows = this.#deps.storage.exec(
      `SELECT MIN(
         CASE WHEN status = 'PENDING' THEN pending_expires_at ELSE payload_expires_at END
       ) AS deadline
       FROM boots WHERE status IN ${LIVE_STATUSES}`,
    );
    const first = rows[0];
    const deadline = first === undefined ? null : deadlineRowSchema.parse(first).deadline;
    this.#deps.scheduleAlarm(deadline);
  }

  // ------------------------------------------------------------------ audit

  async #audit(
    action: AuditAction,
    boot: BootRow,
    actorType: "user" | "system" | "boot",
    actorId: string | null,
    metadata: ReadonlyMap<string, string | number | boolean | null>,
  ): Promise<void> {
    await appendAuditEvent(this.#deps.db, {
      id: this.#deps.newAuditId(),
      timestamp: iso(this.#deps.now()),
      actorType,
      actorId,
      action,
      projectId: boot.project_id,
      environmentId: boot.environment_id,
      bootId: boot.id,
      metadataJson: JSON.stringify(Object.fromEntries(metadata)),
    });
  }

  async #mirror(bootId: string, status: BootStatus, stamp: string | null): Promise<void> {
    const now = iso(this.#deps.now());
    await updateBootRequestStatus(this.#deps.db, {
      bootId,
      status,
      now,
      approvedAt: stamp === "approved" ? now : null,
      declinedAt: stamp === "declined" ? now : null,
      deliveredAt: stamp === "delivered" ? now : null,
      consumedAt: stamp === "consumed" ? now : null,
      expiredAt: stamp === "expired" ? now : null,
      canceledAt: stamp === "canceled" ? now : null,
    });
  }

  // ----------------------------------------------------------------- frames

  /** Handle one text frame. `identity` comes from the authenticated upgrade. */
  async handleFrame(
    connection: BootConnection,
    identity: BootIdentity,
    text: string,
  ): Promise<void> {
    if (new TextEncoder().encode(text).length > MAX_FRAME_BYTES) {
      sendError(connection, CLOSE_CODES.PROTOCOL_ERROR, "Frame exceeds the 1 MiB limit.");
      return;
    }
    const parsed = parseClientFrame(text);
    if (!parsed.ok) {
      sendError(connection, CLOSE_CODES.PROTOCOL_ERROR, "Frame did not match protocol v1.");
      return;
    }
    const message = parsed.message;
    switch (message.type) {
      case "boot.hello":
        await this.#handleHello(connection, identity, message);
        return;
      case "boot.resume":
        await this.#handleResume(connection, identity, message.bootId);
        return;
      case "boot.challenge-response":
        await this.#handleChallengeResponse(
          connection,
          identity,
          message.bootId,
          message.signature,
        );
        return;
      case "boot.received":
        await this.#handleReceived(connection, message.bootId, message.payloadDigest);
        return;
    }
  }

  async #handleHello(
    connection: BootConnection,
    identity: BootIdentity,
    hello: {
      readonly signingPublicKey: string;
      readonly encryptionPublicKey: string;
      readonly claims: WorkloadClaims;
      readonly evidence: readonly Evidence[];
    },
  ): Promise<void> {
    if (connection.attachedBootId() !== null) {
      sendError(
        connection,
        CLOSE_CODES.PROTOCOL_ERROR,
        "This connection already belongs to a boot.",
      );
      return;
    }

    // A boot whose pending TTL has passed is EXPIRED whether or not the alarm
    // ran, so it must not hold a slot in the count below (spec section 18).
    await this.#expireDue();

    if (
      identity.sourceIp.length > 0 &&
      this.#countRecentFromSource(identity.sourceIp) >= MAX_BOOTS_PER_SOURCE
    ) {
      sendError(
        connection,
        CLOSE_CODES.RATE_LIMITED,
        "This source address has created too many boot requests. Try again shortly.",
      );
      return;
    }

    // The token's own limit, falling back to the protocol default of 3.
    const limit =
      identity.maxPendingBoots > 0 ? identity.maxPendingBoots : MAX_PENDING_BOOTS_PER_TOKEN;
    if (this.#countPending(identity.tokenId) >= limit) {
      sendError(
        connection,
        CLOSE_CODES.CONFLICT,
        "This bootstrap token already has the maximum number of pending boots.",
      );
      return;
    }

    const environment = await getEnvironment(this.#deps.db, this.#deps.environmentId);
    if (environment === null) {
      sendError(connection, CLOSE_CODES.UNKNOWN_BOOT, "This environment no longer exists.");
      return;
    }

    const context = await loadProvenanceContext(
      this.#deps.db,
      this.#deps.environmentId,
      environment.provenanceMode,
    );
    const results = await runVerifiers(this.#deps.verifiers, {
      environmentId: this.#deps.environmentId,
      claims: hello.claims,
      evidence: hello.evidence,
      signers: context.signers,
    });
    const provenanceJson = JSON.stringify({ results });

    const bootId = this.#deps.newBootId();
    const createdAt = this.#deps.now();
    const pendingExpiresAt = createdAt + environment.pendingTtlSeconds * 1000;
    const signingFingerprint = await keyFingerprint(b64uDecode(hello.signingPublicKey));
    const encryptionFingerprint = await keyFingerprint(b64uDecode(hello.encryptionPublicKey));

    this.#deps.storage.exec(
      `INSERT INTO boots (${BOOT_COLUMNS})
       VALUES (?, ?, ?, 'PENDING', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, NULL, NULL)`,
      bootId,
      this.#deps.environmentId,
      environment.projectId,
      identity.tokenId,
      identity.sourceIp.length === 0 ? null : identity.sourceIp,
      hello.signingPublicKey,
      hello.encryptionPublicKey,
      signingFingerprint,
      encryptionFingerprint,
      JSON.stringify(hello.claims),
      JSON.stringify(hello.evidence),
      provenanceJson,
      createdAt,
      pendingExpiresAt,
    );

    await insertBootRequest(this.#deps.db, {
      id: bootId,
      environmentId: this.#deps.environmentId,
      bootstrapTokenId: identity.tokenId,
      status: "PENDING",
      sourceIp: identity.sourceIp.length === 0 ? null : identity.sourceIp,
      signingPublicKey: hello.signingPublicKey,
      encryptionPublicKey: hello.encryptionPublicKey,
      claimedGitRepository: hello.claims.git?.repository ?? null,
      claimedGitCommit: hello.claims.git?.commit ?? null,
      claimedOciRepository: hello.claims.oci?.repository ?? null,
      claimedOciDigest: hello.claims.oci?.digest ?? null,
      provenanceSummaryJson: provenanceJson,
      now: iso(createdAt),
    });

    const boot = this.#readBoot(bootId);
    if (boot !== null) {
      await this.#audit(
        "boot.requested",
        boot,
        "boot",
        bootId,
        new Map([["evidenceItems", hello.evidence.length]]),
      );
    }

    connection.attach(bootId, createdAt);
    connection.send(frameText({ type: "boot.pending", bootId, expiresAt: iso(pendingExpiresAt) }));
    this.#recomputeAlarm();
  }

  async #handleResume(
    connection: BootConnection,
    identity: BootIdentity,
    bootId: string,
  ): Promise<void> {
    const boot = this.#readBoot(bootId);
    if (boot === null) {
      sendError(connection, CLOSE_CODES.UNKNOWN_BOOT, "This environment has no such boot.");
      return;
    }
    if (identity.tokenId !== boot.token_id) {
      sendError(connection, CLOSE_CODES.FORBIDDEN, "This bootstrap token did not open that boot.");
      return;
    }
    const current = await this.#expireIfDue(boot);
    if (isTerminal(current.status)) {
      this.#sendTerminalOnce(current, connection);
      return;
    }
    const challenge = this.#deps.randomChallenge();
    const expiresAt = this.#deps.now() + DEFAULT_CHALLENGE_TTL_SECONDS * 1000;
    this.#deps.storage.exec("DELETE FROM challenges WHERE boot_id = ?", bootId);
    this.#deps.storage.exec(
      "INSERT INTO challenges (boot_id, challenge, expires_at, used) VALUES (?, ?, ?, 0)",
      bootId,
      challenge,
      expiresAt,
    );
    connection.send(frameText({ type: "boot.challenge", bootId, challenge }));
  }

  async #handleChallengeResponse(
    connection: BootConnection,
    identity: BootIdentity,
    bootId: string,
    signature: string,
  ): Promise<void> {
    const boot = this.#readBoot(bootId);
    if (boot === null) {
      sendError(connection, CLOSE_CODES.UNKNOWN_BOOT, "This environment has no such boot.");
      return;
    }
    const rows = this.#deps.storage.exec(
      "SELECT boot_id, challenge, expires_at, used FROM challenges WHERE boot_id = ? AND used = 0",
      bootId,
    );
    const first = rows[0];
    if (first === undefined) {
      sendError(connection, CLOSE_CODES.PROTOCOL_ERROR, "No challenge is outstanding.");
      return;
    }
    const challenge = challengeRowSchema.parse(first);
    // A challenge is good for one verification attempt, pass or fail.
    this.#deps.storage.exec("DELETE FROM challenges WHERE boot_id = ?", bootId);
    if (challenge.expires_at <= this.#deps.now()) {
      sendError(connection, CLOSE_CODES.PROTOCOL_ERROR, "The challenge expired.");
      return;
    }

    const valid = await verifyResume({
      publicKey: b64uDecode(boot.signing_pk),
      bootId,
      challenge: challenge.challenge,
      signature,
    });
    if (!valid) {
      sendError(connection, CLOSE_CODES.PROTOCOL_ERROR, "The resume proof did not verify.");
      return;
    }

    // Spec sections 17 and 38: the token that opened the boot must still be the
    // one on the wire, and it must still be valid. This is the administrator's
    // kill switch, and it has to hold here rather than only in the best-effort
    // cancel that runs at revocation time.
    if (identity.tokenId !== boot.token_id) {
      sendError(connection, CLOSE_CODES.FORBIDDEN, "This bootstrap token did not open that boot.");
      return;
    }
    if (!(await this.#tokenStillValid(boot.token_id))) {
      await this.#cancelOne(boot, TOKEN_REVOKED_REASON, null);
      this.#recomputeAlarm();
      sendError(
        connection,
        CLOSE_CODES.FORBIDDEN,
        "The bootstrap token for that boot is no longer valid.",
      );
      return;
    }

    const current = await this.#expireIfDue(boot);
    if (isTerminal(current.status)) {
      this.#sendTerminalOnce(current, connection);
      return;
    }

    connection.attach(bootId, this.#deps.now());
    await this.#audit("boot.reconnected", current, "boot", bootId, new Map());

    if (current.status === "PENDING") {
      connection.send(
        frameText({
          type: "boot.resumed",
          bootId,
          status: "PENDING",
          expiresAt: isoOrNull(current.pending_expires_at) ?? iso(this.#deps.now()),
        }),
      );
      return;
    }

    const status = current.status === "APPROVED" ? "APPROVED" : "DELIVERED";
    connection.send(
      frameText({
        type: "boot.resumed",
        bootId,
        status,
        expiresAt: isoOrNull(current.payload_expires_at) ?? iso(this.#deps.now()),
      }),
    );
    await this.#deliver(current, [connection]);
  }

  /** True when the boot's bootstrap token exists, is unrevoked and unexpired. */
  async #tokenStillValid(tokenId: string): Promise<boolean> {
    const token = await getBootstrapTokenByTokenId(this.#deps.db, tokenId.replace(/^tok_/, ""));
    if (token === null || token.revokedAt !== null) return false;
    return token.expiresAt === null || Date.parse(token.expiresAt) > this.#deps.now();
  }

  async #handleReceived(
    connection: BootConnection,
    bootId: string,
    payloadDigest: string,
  ): Promise<void> {
    if (connection.attachedBootId() !== bootId) {
      sendError(connection, CLOSE_CODES.UNKNOWN_BOOT, "This socket does not own that boot.");
      return;
    }
    const boot = this.#readBoot(bootId);
    if (boot === null) {
      sendError(connection, CLOSE_CODES.UNKNOWN_BOOT, "This environment has no such boot.");
      return;
    }
    if (boot.payload_digest === null || boot.payload_digest !== payloadDigest) {
      // The boot stays DELIVERED until it expires, so the client may retry with
      // the bytes it actually received.
      sendError(
        connection,
        CLOSE_CODES.PROTOCOL_ERROR,
        "The acknowledged payload digest does not match what was sent.",
      );
      return;
    }
    const next = this.#apply(boot, "consume");
    if (next === null) {
      const code = isTerminal(boot.status) ? CLOSE_CODES.TERMINAL : CLOSE_CODES.CONFLICT;
      sendError(connection, code, "This boot cannot be consumed in its current state.");
      return;
    }
    this.#deps.storage.exec(
      "UPDATE boots SET delivered_frame = NULL, consumed_at = ? WHERE id = ?",
      this.#deps.now(),
      bootId,
    );
    await this.#mirror(bootId, "CONSUMED", "consumed");
    await this.#audit("boot.consumed", boot, "boot", bootId, new Map());
    connection.send(frameText({ type: "boot.consumed", bootId }));
    connection.close(CLOSE_CODES.NORMAL, "boot consumed");
    this.#recomputeAlarm();
  }

  // -------------------------------------------------------------- delivery

  /**
   * Write the stored payload to sockets and record the transition. APPROVED
   * moves to DELIVERED; DELIVERED stays DELIVERED under `redeliver`, which
   * exists so a redelivery passes the same guard and lands in the audit log.
   */
  async #deliver(boot: BootRow, sockets: readonly BootSocket[]): Promise<void> {
    const payload = boot.delivered_frame;
    if (payload === null || sockets.length === 0) return;
    const event: BootEvent = boot.status === "APPROVED" ? "deliver" : "redeliver";
    const next = this.#apply(boot, event);
    if (next === null) return;
    for (const socket of sockets) socket.send(payload);
    if (event === "deliver") {
      await this.#mirror(boot.id, "DELIVERED", "delivered");
      await this.#audit("boot.delivered", boot, "system", null, new Map());
    } else {
      await this.#audit("boot.delivered", boot, "system", null, new Map([["redelivery", true]]));
    }
  }

  #sendTerminal(boot: BootRow, sockets: readonly BootSocket[]): void {
    const reason = boot.terminal_reason ?? "";
    for (const socket of sockets) {
      if (boot.status === "DECLINED") {
        socket.send(
          frameText(
            reason.length === 0
              ? { type: "boot.declined", bootId: boot.id }
              : { type: "boot.declined", bootId: boot.id, reason },
          ),
        );
      } else if (boot.status === "EXPIRED") {
        socket.send(frameText({ type: "boot.expired", bootId: boot.id }));
      } else if (boot.status === "CANCELED") {
        socket.send(
          frameText({
            type: "boot.canceled",
            bootId: boot.id,
            reason: reason.length === 0 ? "canceled" : reason,
          }),
        );
      } else {
        socket.send(
          frameText({
            type: "boot.error",
            code: CLOSE_CODES.TERMINAL,
            message: "This boot has already finished.",
          }),
        );
      }
      socket.close(CLOSE_CODES.TERMINAL, "boot is terminal");
    }
  }

  // --------------------------------------------------------------- expiry

  async #expire(boot: BootRow, event: BootEvent): Promise<void> {
    const next = this.#apply(boot, event);
    if (next === null) return;
    this.#deps.storage.exec(
      "UPDATE boots SET delivered_frame = NULL, terminal_reason = ? WHERE id = ?",
      event === "expirePending" ? "pending ttl elapsed" : "payload ttl elapsed",
      boot.id,
    );
    await this.#mirror(boot.id, "EXPIRED", "expired");
    await this.#audit("boot.expired", boot, "system", null, new Map());
    const expired = this.#readBoot(boot.id);
    if (expired !== null) this.#sendTerminal(expired, this.#deps.sockets.forBoot(boot.id));
  }

  /**
   * Expire one boot whose TTL has passed and hand back the current row. The
   * alarm is the normal way a boot expires, but a hibernated object handles an
   * incoming frame before the alarm runs, so every read path checks too.
   */
  async #expireIfDue(boot: BootRow): Promise<BootRow> {
    if (isTerminal(boot.status)) return boot;
    const now = this.#deps.now();
    const deadline = boot.status === "PENDING" ? boot.pending_expires_at : boot.payload_expires_at;
    if (deadline === null || deadline > now) return boot;
    await this.#expire(boot, boot.status === "PENDING" ? "expirePending" : "expirePayload");
    this.#recomputeAlarm();
    return this.#readBoot(boot.id) ?? boot;
  }

  /** Expire every live boot whose deadline has passed. */
  async #expireDue(): Promise<void> {
    const now = this.#deps.now();
    for (const boot of this.#readLive()) {
      if (boot.status === "PENDING") {
        if (boot.pending_expires_at !== null && boot.pending_expires_at <= now) {
          await this.#expire(boot, "expirePending");
        }
        continue;
      }
      if (boot.payload_expires_at !== null && boot.payload_expires_at <= now) {
        await this.#expire(boot, "expirePayload");
      }
    }
  }

  /**
   * Send the terminal frame to one socket, unless `#expire` or `#cancelOne`
   * already reached it through the registry because it was attached.
   */
  #sendTerminalOnce(boot: BootRow, connection: BootConnection): void {
    if (connection.attachedBootId() === boot.id) return;
    this.#sendTerminal(boot, [connection]);
  }

  /** Called by the Durable Object alarm. Expires whatever is due, then rearms. */
  async onAlarm(): Promise<void> {
    await this.#expireDue();
    this.#recomputeAlarm();
  }

  // ------------------------------------------------------------------ RPCs

  /**
   * Approve one boot and deliver the environment key to it.
   *
   * Everything is re-checked here, because the dashboard row that produced this
   * call is a projection and may be stale: the boot must still be PENDING and
   * unexpired, the bootstrap token must still be valid, the provenance policy
   * must still be satisfied by a fresh verifier run, and the digest of that run
   * must equal the one the approver read.
   */
  async approve(input: ApproveBootInput): Promise<BootActionResult> {
    const boot = this.#readBoot(input.bootId);
    if (boot === null) return failure("not_found", "That boot is unknown to this environment.");
    if (isTerminal(boot.status)) {
      return failure("terminal", `That boot is already ${boot.status.toLowerCase()}.`);
    }
    if (boot.status !== "PENDING") {
      return failure("conflict", `That boot is already ${boot.status.toLowerCase()}.`);
    }
    const now = this.#deps.now();
    if (boot.pending_expires_at !== null && boot.pending_expires_at <= now) {
      await this.#expire(boot, "expirePending");
      this.#recomputeAlarm();
      return failure("expired", "That boot request expired before it was approved.");
    }

    const token = await getBootstrapTokenByTokenId(
      this.#deps.db,
      boot.token_id.replace(/^tok_/, ""),
    );
    if (token === null || token.revokedAt !== null) {
      return failure("token_invalid", "The bootstrap token for that boot is no longer valid.");
    }
    if (token.expiresAt !== null && Date.parse(token.expiresAt) <= now) {
      return failure("token_invalid", "The bootstrap token for that boot has expired.");
    }

    const environment = await getEnvironment(this.#deps.db, boot.environment_id);
    if (environment === null) {
      return failure("not_found", "That environment no longer exists.");
    }
    const context = await loadProvenanceContext(
      this.#deps.db,
      boot.environment_id,
      environment.provenanceMode,
    );
    const claims = claimsSchema.safeParse(boot.claims_json);
    const evidence = evidenceSchema.safeParse(boot.evidence_json);
    const results = await runVerifiers(this.#deps.verifiers, {
      environmentId: boot.environment_id,
      claims: claims.success ? claims.data : {},
      evidence: evidence.success ? evidence.data : [],
      signers: context.signers,
    });
    const evaluation = evaluatePolicy(context.mode, results, context.policies);
    if (!evaluation.approvable) {
      return failure("policy_blocked", evaluation.blockers.join("; "));
    }
    const digest = await summaryDigest(results);
    if (digest !== input.evidenceDigest) {
      return failure(
        "evidence_mismatch",
        "The evidence changed since this screen was loaded. Review it again.",
      );
    }

    let unwrapped: UnwrappedEnvironmentDek;
    try {
      unwrapped = await this.#deps.unwrapDek(boot.environment_id);
    } catch {
      return failure("key_error", "The environment key could not be unwrapped.");
    }

    const secretRows = await listSecretsForDelivery(this.#deps.db, boot.environment_id);
    const secrets: SecretRecord[] = secretRows.map((row) => ({
      id: row.id,
      name: row.name,
      version: row.secretVersion,
      envKeyVersion: row.envKeyVersion,
      nonce: row.nonce,
      ciphertext: row.ciphertext,
    }));

    const payloadExpiresAt = now + environment.approvedTtlSeconds * 1000;
    const created = await createBootEnvelope({
      bootId: boot.id,
      environmentId: boot.environment_id,
      environmentKeyVersion: unwrapped.version,
      environmentKey: unwrapped.dek,
      clientPublicKey: b64uDecode(boot.encryption_pk),
    });
    const approved: BootApproved = {
      type: "boot.approved",
      bootId: boot.id,
      projectId: unwrapped.projectId,
      environmentId: boot.environment_id,
      environmentKeyVersion: unwrapped.version,
      payloadExpiresAt: iso(payloadExpiresAt),
      keyEnvelope: created.envelope,
      secrets,
    };
    const payload = frameText(approved);
    const payloadDigest = await sha256HexOfText(payload);

    // Critical section. Everything above awaited, so another approve for the
    // same boot may have run to completion in between: re-read the row and
    // write the transition and the payload with no await in between, which
    // JavaScript's single thread makes indivisible. The loser discards the
    // envelope it built and reports a conflict.
    const current = this.#readBoot(boot.id);
    if (current === null || current.status !== "PENDING") {
      return failure("conflict", "That boot changed state while it was being approved.");
    }
    const next = this.#apply(current, "approve");
    if (next === null) {
      return failure("conflict", "That boot changed state while it was being approved.");
    }
    this.#deps.storage.exec(
      `UPDATE boots SET approved_at = ?, payload_expires_at = ?, delivered_frame = ?,
         payload_digest = ?, provenance_json = ? WHERE id = ?`,
      now,
      payloadExpiresAt,
      payload,
      payloadDigest,
      JSON.stringify({ results }),
      boot.id,
    );
    await this.#mirror(boot.id, "APPROVED", "approved");
    await insertBootApproval(this.#deps.db, {
      bootId: boot.id,
      approverUserId: input.approverUserId,
      approverCredentialId: input.approverCredentialId,
      approvedAt: iso(now),
      clientSigningFingerprint: boot.signing_fp,
      clientEncryptionFingerprint: boot.encryption_fp,
      evidenceDigest: digest,
    });
    await this.#audit(
      "boot.approved",
      boot,
      "user",
      input.approverUserId,
      new Map<string, string | number | boolean | null>([
        ["environmentKeyVersion", unwrapped.version],
        ["secretCount", secrets.length],
        ["evidenceDigest", digest],
      ]),
    );

    const attached = this.#deps.sockets.forBoot(boot.id);
    const stored = this.#readBoot(boot.id);
    if (stored !== null && attached.length > 0) {
      await this.#deliver(stored, attached);
    }
    this.#recomputeAlarm();
    const final = this.#readBoot(boot.id);
    return { ok: true, status: final?.status ?? "APPROVED" };
  }

  async decline(input: DeclineBootInput): Promise<BootActionResult> {
    const boot = this.#readBoot(input.bootId);
    if (boot === null) return failure("not_found", "That boot is unknown to this environment.");
    const next = this.#apply(boot, "decline");
    if (next === null) {
      return failure(
        isTerminal(boot.status) ? "terminal" : "conflict",
        `That boot is already ${boot.status.toLowerCase()}.`,
      );
    }
    this.#deps.storage.exec(
      "UPDATE boots SET delivered_frame = NULL, terminal_reason = ? WHERE id = ?",
      input.reason,
      boot.id,
    );
    await this.#mirror(boot.id, "DECLINED", "declined");
    await this.#audit("boot.declined", boot, "user", input.approverUserId, new Map());
    const declined = this.#readBoot(boot.id);
    if (declined !== null) this.#sendTerminal(declined, this.#deps.sockets.forBoot(boot.id));
    this.#recomputeAlarm();
    return { ok: true, status: "DECLINED" };
  }

  /** Cancel one boot. Used by an administrator from the dashboard. */
  async cancelBoot(input: CancelBootInput): Promise<BootActionResult> {
    const boot = this.#readBoot(input.bootId);
    if (boot === null) return failure("not_found", "That boot is unknown to this environment.");
    const canceled = await this.#cancelOne(boot, input.reason, input.actorUserId);
    this.#recomputeAlarm();
    if (!canceled) {
      return failure(
        isTerminal(boot.status) ? "terminal" : "conflict",
        `That boot is already ${boot.status.toLowerCase()}.`,
      );
    }
    return { ok: true, status: "CANCELED" };
  }

  /**
   * Cancel every live boot in this environment. Used when the environment is
   * deleted: pending requests are canceled before key material is removed
   * (spec section 40).
   */
  async cancel(reason: string): Promise<number> {
    let canceled = 0;
    for (const boot of this.#readLive()) {
      if (await this.#cancelOne(boot, reason, null)) canceled += 1;
    }
    this.#recomputeAlarm();
    return canceled;
  }

  /** Cancel every live boot from one bootstrap token. Used on revocation. */
  async cancelForToken(tokenId: string, reason: string): Promise<number> {
    let canceled = 0;
    for (const boot of this.#readLive()) {
      if (boot.token_id !== tokenId) continue;
      if (await this.#cancelOne(boot, reason, null)) canceled += 1;
    }
    this.#recomputeAlarm();
    return canceled;
  }

  async #cancelOne(boot: BootRow, reason: string, actorId: string | null): Promise<boolean> {
    const next = this.#apply(boot, "cancel");
    if (next === null) return false;
    this.#deps.storage.exec(
      "UPDATE boots SET delivered_frame = NULL, terminal_reason = ? WHERE id = ?",
      reason,
      boot.id,
    );
    await this.#mirror(boot.id, "CANCELED", "canceled");
    await this.#audit(
      "boot.canceled",
      boot,
      actorId === null ? "system" : "user",
      actorId,
      new Map([["reason", reason]]),
    );
    const canceled = this.#readBoot(boot.id);
    if (canceled !== null) this.#sendTerminal(canceled, this.#deps.sockets.forBoot(boot.id));
    return true;
  }

  /** One boot, or null when this environment never saw it. */
  get(bootId: string): BootView | null {
    const boot = this.#readBoot(bootId);
    return boot === null ? null : this.#view(boot);
  }

  /** Every boot that is still PENDING, APPROVED or DELIVERED. */
  listLive(): BootView[] {
    return this.#readLive().map((boot) => this.#view(boot));
  }

  #view(boot: BootRow): BootView {
    const claims = claimsSchema.safeParse(boot.claims_json);
    const evidence = evidenceSchema.safeParse(boot.evidence_json);
    return {
      bootId: boot.id,
      environmentId: boot.environment_id,
      projectId: boot.project_id,
      status: boot.status,
      tokenId: boot.token_id,
      sourceIp: boot.source_ip,
      signingFingerprint: boot.signing_fp,
      encryptionFingerprint: boot.encryption_fp,
      claims: claims.success ? claims.data : {},
      evidenceCount: evidence.success ? evidence.data.length : 0,
      provenance: parseSummary(boot.provenance_json),
      createdAt: iso(boot.created_at),
      pendingExpiresAt: isoOrNull(boot.pending_expires_at),
      approvedAt: isoOrNull(boot.approved_at),
      payloadExpiresAt: isoOrNull(boot.payload_expires_at),
      consumedAt: isoOrNull(boot.consumed_at),
      terminalReason: boot.terminal_reason,
      connected: this.#deps.sockets.forBoot(boot.id).length > 0,
    };
  }
}

function failure(reason: BootActionFailure, message: string): BootActionResult {
  return { ok: false, reason, message };
}
