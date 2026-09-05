/**
 * The setup ceremony's token comparison, kept free of Cloudflare imports so a
 * test can drive it (spec section 21).
 *
 * An unset `VAULT_SETUP_TOKEN` and a wrong token are the same answer: no. The
 * endpoint turns both into 404, so a prober cannot tell whether an operator has
 * configured the secret yet.
 */

/**
 * Compare two secrets without leaking their contents through timing. Length is
 * not secret here, but the comparison stays constant time across the shorter
 * of the two buffers and folds the length difference into the result.
 */
export function constantTimeEquals(left: string, right: string): boolean {
  const encoder = new TextEncoder();
  const leftBytes = encoder.encode(left);
  const rightBytes = encoder.encode(right);
  let difference = leftBytes.length ^ rightBytes.length;
  const length = Math.max(leftBytes.length, rightBytes.length);
  for (let index = 0; index < length; index += 1) {
    difference |= (leftBytes[index] ?? 0) ^ (rightBytes[index] ?? 0);
  }
  return difference === 0;
}

/**
 * True only when the vault has a setup token configured and the presented value
 * equals it. An absent binding, an empty secret and a wrong token all answer
 * false.
 */
export function setupTokenAccepted(configured: string | undefined, presented: string): boolean {
  const expected = configured ?? "";
  if (expected.length === 0) return false;
  return constantTimeEquals(presented, expected);
}
