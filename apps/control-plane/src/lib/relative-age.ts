/**
 * How long ago something happened, in words.
 *
 * The approval screen says "Requested 37 seconds ago" (spec section 34), which
 * a human reads faster than a timestamp when deciding whether a boot is the one
 * they just triggered.
 */
export function relativeAge(timestamp: string, now: number = Date.now()): string {
  const parsed = Date.parse(timestamp);
  if (!Number.isFinite(parsed)) return timestamp;
  const seconds = Math.max(0, Math.round((now - parsed) / 1000));
  if (seconds < 60) return `${seconds} second${seconds === 1 ? "" : "s"} ago`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes} minute${minutes === 1 ? "" : "s"} ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} hour${hours === 1 ? "" : "s"} ago`;
  const days = Math.round(hours / 24);
  return `${days} day${days === 1 ? "" : "s"} ago`;
}
