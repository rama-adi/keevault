import { b64uEncode, generateKey32 } from "@env-vault/crypto";
import { describe, expect, test } from "vite-plus/test";

import { loadMasterKeys, VaultKeyError, type MasterKeyEnv } from "./keys.ts";

function envFrom(entries: ReadonlyArray<readonly [string, string]>): MasterKeyEnv {
  const built = Object.fromEntries(entries);
  return {
    ...built,
    VAULT_MASTER_KEY_ACTIVE_VERSION: built["VAULT_MASTER_KEY_ACTIVE_VERSION"] ?? "1",
  };
}

describe("loadMasterKeys", () => {
  test("reads every version present and picks the active one", () => {
    const keyring = loadMasterKeys(
      envFrom([
        ["VAULT_MASTER_KEY_V1", b64uEncode(generateKey32())],
        ["VAULT_MASTER_KEY_V2", b64uEncode(generateKey32())],
        ["VAULT_MASTER_KEY_ACTIVE_VERSION", "2"],
        ["BETTER_AUTH_SECRET", "not a master key"],
      ]),
    );
    expect(keyring.versions).toEqual([1, 2]);
    expect(keyring.activeVersion).toBe(2);
    expect(keyring.key(1).length).toBe(32);
  });

  test("refuses a key that is not 32 bytes", () => {
    expect(() =>
      loadMasterKeys(
        envFrom([
          ["VAULT_MASTER_KEY_V1", b64uEncode(new Uint8Array(16))],
          ["VAULT_MASTER_KEY_ACTIVE_VERSION", "1"],
        ]),
      ),
    ).toThrow(VaultKeyError);
  });

  test("refuses an active version that is not configured", () => {
    expect(() =>
      loadMasterKeys(
        envFrom([
          ["VAULT_MASTER_KEY_V1", b64uEncode(generateKey32())],
          ["VAULT_MASTER_KEY_ACTIVE_VERSION", "3"],
        ]),
      ),
    ).toThrow(VaultKeyError);
  });

  test("refuses an environment with no master key at all", () => {
    expect(() => loadMasterKeys(envFrom([["VAULT_MASTER_KEY_ACTIVE_VERSION", "1"]]))).toThrow(
      VaultKeyError,
    );
  });

  test("asking for a version that is not present throws", () => {
    const keyring = loadMasterKeys(
      envFrom([
        ["VAULT_MASTER_KEY_V1", b64uEncode(generateKey32())],
        ["VAULT_MASTER_KEY_ACTIVE_VERSION", "1"],
      ]),
    );
    expect(() => keyring.key(2)).toThrow(VaultKeyError);
  });
});
