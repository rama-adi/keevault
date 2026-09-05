/** Every state a boot request can hold. CREATING is not here: it exists only
 * inside the hello handler, before the boot row is written. */
export const BOOT_STATUSES = [
  "PENDING",
  "APPROVED",
  "DELIVERED",
  "CONSUMED",
  "DECLINED",
  "EXPIRED",
  "CANCELED",
] as const;

/** A boot status. */
export type BootStatus = (typeof BOOT_STATUSES)[number];

/** Every event that can move a boot between states. */
export const BOOT_EVENTS = [
  "approve",
  "decline",
  "expirePending",
  "cancel",
  "deliver",
  "redeliver",
  "consume",
  "expirePayload",
] as const;

/** An event applied to a boot. */
export type BootEvent = (typeof BOOT_EVENTS)[number];

const TERMINAL_STATUSES: ReadonlySet<BootStatus> = new Set<BootStatus>([
  "CONSUMED",
  "DECLINED",
  "EXPIRED",
  "CANCELED",
]);

/** True when no event can move the boot out of this state. */
export function isTerminal(status: BootStatus): boolean {
  return TERMINAL_STATUSES.has(status);
}

const TRANSITIONS: ReadonlyMap<BootStatus, ReadonlyMap<BootEvent, BootStatus>> = new Map<
  BootStatus,
  ReadonlyMap<BootEvent, BootStatus>
>([
  [
    "PENDING",
    new Map<BootEvent, BootStatus>([
      ["approve", "APPROVED"],
      ["decline", "DECLINED"],
      ["expirePending", "EXPIRED"],
      ["cancel", "CANCELED"],
    ]),
  ],
  [
    "APPROVED",
    new Map<BootEvent, BootStatus>([
      ["deliver", "DELIVERED"],
      ["cancel", "CANCELED"],
      ["expirePayload", "EXPIRED"],
    ]),
  ],
  [
    "DELIVERED",
    new Map<BootEvent, BootStatus>([
      ["redeliver", "DELIVERED"],
      ["consume", "CONSUMED"],
      ["expirePayload", "EXPIRED"],
    ]),
  ],
  ["CONSUMED", new Map<BootEvent, BootStatus>()],
  ["DECLINED", new Map<BootEvent, BootStatus>()],
  ["EXPIRED", new Map<BootEvent, BootStatus>()],
  ["CANCELED", new Map<BootEvent, BootStatus>()],
]);

/** Why an event was rejected. "terminal" means the boot is already finished,
 * "conflict" means the event does not apply in this state. */
export type TransitionFailureReason = "conflict" | "terminal";

/** The outcome of applying an event to a state. */
export type TransitionResult =
  | { readonly ok: true; readonly to: BootStatus }
  | { readonly ok: false; readonly reason: TransitionFailureReason };

/**
 * Apply one event to one state. Pure: it reads the table above and returns the
 * next state or the reason the event does not apply. Callers write the new
 * state only when ok is true.
 */
export function transition(from: BootStatus, event: BootEvent): TransitionResult {
  const allowed = TRANSITIONS.get(from);
  const to = allowed?.get(event);
  if (to !== undefined) return { ok: true, to };
  return { ok: false, reason: isTerminal(from) ? "terminal" : "conflict" };
}
