/** Small formatting helpers shared by the vault pages. */

/** Render a stored RFC 3339 timestamp as `YYYY-MM-DD HH:MM` in UTC. */
export function formatDate(value: string | null): string {
  if (value === null) return "-";
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) return value;
  return new Date(parsed).toISOString().slice(0, 16).replace("T", " ");
}

/** Suggest a slug while the operator types a name. They can still edit it. */
export function toSlug(value: string): string {
  return value
    .toLowerCase()
    .replaceAll(/[^a-z0-9]+/g, "-")
    .replaceAll(/^-+|-+$/g, "")
    .slice(0, 63);
}

/** Split a textarea of CIDRs, one per line or comma separated. */
export function parseCidrList(value: string): string[] {
  return value
    .split(/[\n,]/)
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}
