import type { VaultDatabase } from "@keevault/vault-store";
import type { KeyEnvelope } from "@keevault/protocol";

import type {
  ApproveBootInput,
  BootActionResult,
  CompleteBootApprovalInput,
  PrepareBootApprovalResult,
} from "../durable-objects/boot-session-core.ts";
import { createCloudKeyRelease, KeyReleaseError } from "./key-release.ts";
import type { MasterKeyring } from "./keys.ts";

/** RPC boundary shared by the real DO and in-process integration tests. */
export interface BootApprovalCoordinator {
  prepareApproval(input: ApproveBootInput): Promise<PrepareBootApprovalResult>;
  completeApproval(input: CompleteBootApprovalInput): Promise<BootActionResult>;
}

/** The cloud key holder takes the role a user's CLI will take in cold mode. */
export async function approveCloudBoot(
  coordinator: BootApprovalCoordinator,
  db: VaultDatabase,
  keyring: MasterKeyring,
  input: ApproveBootInput,
): Promise<BootActionResult> {
  const prepared = await coordinator.prepareApproval(input);
  if (!prepared.ok) return prepared;
  let keyEnvelope: KeyEnvelope;
  try {
    keyEnvelope = await createCloudKeyRelease(db, keyring, prepared.request);
  } catch (error) {
    if (error instanceof KeyReleaseError && error.code === "cold_key_required") {
      return {
        ok: false,
        reason: "cold_key_required",
        message: "Cold environments require local key approval, which is not available yet.",
      };
    }
    return {
      ok: false,
      reason: "key_error",
      message: "The environment key could not be released.",
    };
  }
  return await coordinator.completeApproval({
    ...input,
    contextId: prepared.request.contextId,
    contextDigest: prepared.contextDigest,
    keyEnvelope,
  });
}
