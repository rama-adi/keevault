import { expect, test } from "vite-plus/test";

import {
  BOOT_EVENTS,
  BOOT_STATUSES,
  isTerminal,
  transition,
  type BootEvent,
  type BootStatus,
} from "../src/state.ts";

const EXPECTED: ReadonlyMap<string, BootStatus> = new Map([
  ["PENDING/approve", "APPROVED"],
  ["PENDING/decline", "DECLINED"],
  ["PENDING/expirePending", "EXPIRED"],
  ["PENDING/cancel", "CANCELED"],
  ["APPROVED/deliver", "DELIVERED"],
  ["APPROVED/cancel", "CANCELED"],
  ["APPROVED/expirePayload", "EXPIRED"],
  ["DELIVERED/redeliver", "DELIVERED"],
  ["DELIVERED/consume", "CONSUMED"],
  ["DELIVERED/expirePayload", "EXPIRED"],
]);

function pairs(): readonly (readonly [BootStatus, BootEvent])[] {
  return BOOT_STATUSES.flatMap((status) => BOOT_EVENTS.map((event) => [status, event] as const));
}

test("every state and event pair matches the brief", () => {
  for (const [status, event] of pairs()) {
    const result = transition(status, event);
    const expected = EXPECTED.get(`${status}/${event}`);
    if (expected === undefined) {
      expect(result, `${status} + ${event}`).toEqual({
        ok: false,
        reason: isTerminal(status) ? "terminal" : "conflict",
      });
    } else {
      expect(result, `${status} + ${event}`).toEqual({ ok: true, to: expected });
    }
  }
});

test("the pair table covers all 56 combinations", () => {
  expect(pairs()).toHaveLength(BOOT_STATUSES.length * BOOT_EVENTS.length);
  expect(BOOT_STATUSES.length * BOOT_EVENTS.length).toBe(56);
});

test("terminal states accept nothing", () => {
  for (const status of BOOT_STATUSES) {
    if (!isTerminal(status)) continue;
    for (const event of BOOT_EVENTS) {
      expect(transition(status, event)).toEqual({ ok: false, reason: "terminal" });
    }
  }
});

test("isTerminal marks the four finished states", () => {
  expect(BOOT_STATUSES.filter(isTerminal)).toEqual(["CONSUMED", "DECLINED", "EXPIRED", "CANCELED"]);
});

test("redelivery to the same key is a no-op that keeps DELIVERED", () => {
  expect(transition("DELIVERED", "redeliver")).toEqual({ ok: true, to: "DELIVERED" });
});

test("an approved payload cannot be consumed before it is delivered", () => {
  expect(transition("APPROVED", "consume")).toEqual({ ok: false, reason: "conflict" });
});
