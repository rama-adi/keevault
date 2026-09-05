import { expect, test } from "vite-plus/test";

import {
  CLOSE_CODES,
  CLOSE_CODE_VALUES,
  DEFAULT_CHALLENGE_TTL_SECONDS,
  DEFAULT_PAYLOAD_TTL_SECONDS,
  DEFAULT_PENDING_TTL_SECONDS,
  ERROR_CLOSE_CODE_VALUES,
  MAX_PENDING_BOOTS_PER_TOKEN,
  PROTOCOL_VERSION,
} from "../src/constants.ts";

test("close codes match the brief", () => {
  expect(CLOSE_CODE_VALUES).toEqual([1000, 4400, 4401, 4403, 4404, 4409, 4410, 4429]);
  expect(ERROR_CLOSE_CODE_VALUES).not.toContain(CLOSE_CODES.NORMAL);
});

test("timing defaults match the brief", () => {
  expect(PROTOCOL_VERSION).toBe(1);
  expect(DEFAULT_PENDING_TTL_SECONDS).toBe(1800);
  expect(DEFAULT_PAYLOAD_TTL_SECONDS).toBe(300);
  expect(DEFAULT_CHALLENGE_TTL_SECONDS).toBe(30);
  expect(MAX_PENDING_BOOTS_PER_TOKEN).toBe(3);
});
