/**
 * Canonical strings signed by clients. These are UTF-8, joined with "\n", with
 * no trailing newline and no carriage returns. The crypto package deliberately
 * does not import this module, so keep every builder here small enough to
 * re-derive from protocol/websocket-v1.md.
 */

/**
 * The message a client signs with its boot Ed25519 key to prove it owns a boot
 * after reconnecting. Pass the challenge exactly as the server sent it.
 */
export function resumeMessage(bootId: string, challengeB64u: string): string {
  return `vault-resume:v1\n${bootId}\n${challengeB64u}`;
}
