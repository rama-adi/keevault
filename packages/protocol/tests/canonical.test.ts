import { expect, test } from "vite-plus/test";

import { resumeMessage } from "../src/canonical.ts";

test("the resume message is three lines with no trailing newline", () => {
  const message = resumeMessage("boot_01JQ8Z5K7N2P4R6T8V0X2Z4A6C", "Q0hBTExFTkdF");
  expect(message).toBe("vault-resume:v1\nboot_01JQ8Z5K7N2P4R6T8V0X2Z4A6C\nQ0hBTExFTkdF");
  expect(message.endsWith("\n")).toBe(false);
  expect(message.includes("\r")).toBe(false);
  expect(message.split("\n")).toHaveLength(3);
});
