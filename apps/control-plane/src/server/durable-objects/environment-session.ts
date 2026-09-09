import { generatePrefixedUlid, generateResumeChallenge } from "@keevault/crypto";
import { CLOSE_CODES } from "@keevault/protocol";
import { fromD1 } from "@keevault/vault-store";
import { DurableObject } from "cloudflare:workers";
import { z } from "zod";

import {
  INTERNAL_ENVIRONMENT_HEADER,
  INTERNAL_MAX_PENDING_HEADER,
  INTERNAL_SOURCE_IP_HEADER,
  INTERNAL_TOKEN_HEADER,
} from "../bootstrap/headers.ts";
import { V1_VERIFIERS } from "../provenance/index.ts";
import { loadMasterKeys, unwrapEnvironmentDek } from "../vault/keys.ts";
import type { UnwrappedEnvironmentDek } from "../vault/keys.ts";
import { BootSessionCore } from "./boot-session-core.ts";
import type {
  ApproveBootInput,
  BootActionResult,
  BootConnection,
  BootIdentity,
  BootSocket,
  BootView,
  CancelBootInput,
  DeclineBootInput,
} from "./boot-session-core.ts";
import { fromSqlStorage } from "./boot-storage.ts";

/**
 * One Durable Object per environment (spec section 14).
 *
 * The class is deliberately thin. It wires the Cloudflare runtime into
 * `BootSessionCore`: SQLite storage, the hibernating WebSocket API, alarms, the
 * D1 binding and the master keyring. Every rule lives in the core, which is why
 * the tests can drive the same code over `node:sqlite`.
 *
 * Nothing here keeps state in instance fields between requests. A hibernated
 * Durable Object comes back with empty memory, and the only thing a woken
 * socket carries is its serialized attachment, `{ bootId, generation }`, plus
 * the tags it was accepted with.
 */

const TAG_TOKEN = "t:";
const TAG_SOURCE_IP = "i:";
const TAG_MAX_PENDING = "m:";

const attachmentSchema = z.object({ bootId: z.string(), generation: z.number() });

const identityHeadersSchema = z.object({
  tokenId: z.string().min(1),
  environmentId: z.string().min(1),
  sourceIp: z.string(),
  maxPendingBoots: z.coerce.number().int().min(1).max(64),
});

function socketConnection(socket: WebSocket): BootConnection {
  return {
    send(text: string): void {
      socket.send(text);
    },
    close(code: number, reason: string): void {
      socket.close(code, reason);
    },
    attachedBootId(): string | null {
      const parsed = attachmentSchema.safeParse(socket.deserializeAttachment());
      return parsed.success ? parsed.data.bootId : null;
    },
    attach(bootId: string, generation: number): void {
      socket.serializeAttachment({ bootId, generation });
    },
  };
}

export class EnvironmentSessionDO extends DurableObject<Env> {
  /**
   * Build a core over the live bindings. Called per entry point rather than
   * cached, so nothing survives hibernation in a field.
   */
  #core(environmentId: string): BootSessionCore {
    const db = fromD1(this.env.VAULT_DB);
    return new BootSessionCore({
      storage: fromSqlStorage(this.ctx.storage.sql),
      db,
      environmentId,
      now: () => Date.now(),
      newBootId: () => generatePrefixedUlid("boot"),
      newAuditId: () => generatePrefixedUlid("aud"),
      randomChallenge: () => generateResumeChallenge(),
      unwrapDek: async (id: string): Promise<UnwrappedEnvironmentDek> =>
        await unwrapEnvironmentDek(db, loadMasterKeys(this.env), id),
      sockets: {
        forBoot: (bootId: string): readonly BootSocket[] => this.#socketsFor(bootId),
      },
      scheduleAlarm: (at: number | null): void => {
        void this.#scheduleAlarm(at);
      },
      verifiers: V1_VERIFIERS,
    });
  }

  /** The environment this object belongs to, from the name it was created with. */
  #environmentId(): string {
    return this.ctx.id.name ?? "";
  }

  #socketsFor(bootId: string): BootSocket[] {
    const matching: BootSocket[] = [];
    for (const socket of this.ctx.getWebSockets()) {
      const parsed = attachmentSchema.safeParse(socket.deserializeAttachment());
      if (parsed.success && parsed.data.bootId === bootId) {
        matching.push(socketConnection(socket));
      }
    }
    return matching;
  }

  async #scheduleAlarm(at: number | null): Promise<void> {
    if (at === null) {
      await this.ctx.storage.deleteAlarm();
      return;
    }
    const current = await this.ctx.storage.getAlarm();
    if (current === null || current > at) {
      await this.ctx.storage.setAlarm(at);
    }
  }

  /**
   * Read the identity of a woken socket back from its tags. The attachment is
   * reserved for `{ bootId, generation }`, so the authenticated identity rides
   * on the tags the socket was accepted with, which also survive hibernation.
   */
  #identityFor(socket: WebSocket): BootIdentity | null {
    let tokenId: string | null = null;
    let sourceIp = "";
    let maxPendingBoots = 3;
    for (const tag of this.ctx.getTags(socket)) {
      if (tag.startsWith(TAG_TOKEN)) tokenId = tag.slice(TAG_TOKEN.length);
      else if (tag.startsWith(TAG_SOURCE_IP)) sourceIp = tag.slice(TAG_SOURCE_IP.length);
      else if (tag.startsWith(TAG_MAX_PENDING)) {
        const parsed = Number.parseInt(tag.slice(TAG_MAX_PENDING.length), 10);
        if (Number.isFinite(parsed) && parsed > 0) maxPendingBoots = parsed;
      }
    }
    return tokenId === null ? null : { tokenId, sourceIp, maxPendingBoots };
  }

  /** Accept the upgrade the Worker already authenticated. */
  override async fetch(request: Request): Promise<Response> {
    const identity = identityHeadersSchema.safeParse({
      tokenId: request.headers.get(INTERNAL_TOKEN_HEADER),
      environmentId: request.headers.get(INTERNAL_ENVIRONMENT_HEADER),
      sourceIp: request.headers.get(INTERNAL_SOURCE_IP_HEADER) ?? "",
      maxPendingBoots: request.headers.get(INTERNAL_MAX_PENDING_HEADER) ?? "3",
    });
    if (!identity.success) {
      return new Response("This endpoint is reached through the Worker only.", { status: 400 });
    }
    // Touch the core so the schema exists before the first frame arrives.
    this.#core(identity.data.environmentId);

    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    this.ctx.acceptWebSocket(server, [
      `${TAG_TOKEN}${identity.data.tokenId}`,
      `${TAG_SOURCE_IP}${identity.data.sourceIp}`,
      `${TAG_MAX_PENDING}${identity.data.maxPendingBoots}`,
    ]);
    return new Response(null, { status: 101, webSocket: client });
  }

  override async webSocketMessage(socket: WebSocket, message: string | ArrayBuffer): Promise<void> {
    if (message instanceof ArrayBuffer) {
      const reason = "Protocol v1 uses text frames only.";
      socket.send(
        JSON.stringify({ type: "boot.error", code: CLOSE_CODES.PROTOCOL_ERROR, message: reason }),
      );
      socket.close(CLOSE_CODES.PROTOCOL_ERROR, reason);
      return;
    }
    const identity = this.#identityFor(socket);
    if (identity === null) {
      socket.close(CLOSE_CODES.UNAUTHORIZED, "this socket has no identity");
      return;
    }
    await this.#core(this.#environmentId()).handleFrame(
      socketConnection(socket),
      identity,
      message,
    );
  }

  override webSocketClose(): void {
    // Boot state lives in storage, so a closed socket needs no bookkeeping. The
    // client may reconnect and resume while the boot is still live.
  }

  override webSocketError(): void {
    // Same as a close: nothing in memory to unwind.
  }

  override async alarm(): Promise<void> {
    await this.#core(this.#environmentId()).onAlarm();
  }

  // ------------------------------------------------------------------ RPCs

  async approve(input: ApproveBootInput): Promise<BootActionResult> {
    return await this.#core(this.#environmentId()).approve(input);
  }

  async decline(input: DeclineBootInput): Promise<BootActionResult> {
    return await this.#core(this.#environmentId()).decline(input);
  }

  async cancelBoot(input: CancelBootInput): Promise<BootActionResult> {
    return await this.#core(this.#environmentId()).cancelBoot(input);
  }

  /** Cancel every live boot. Used when the environment is deleted. */
  async cancel(reason: string): Promise<number> {
    return await this.#core(this.#environmentId()).cancel(reason);
  }

  /** Cancel every live boot from one token. Used when a token is revoked. */
  async cancelForToken(tokenId: string, reason: string): Promise<number> {
    return await this.#core(this.#environmentId()).cancelForToken(tokenId, reason);
  }

  get(bootId: string): BootView | null {
    return this.#core(this.#environmentId()).get(bootId);
  }

  listLive(): BootView[] {
    return this.#core(this.#environmentId()).listLive();
  }
}
