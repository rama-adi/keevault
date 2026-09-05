import { describe, expect, test } from "vite-plus/test";

import { parseDotenv } from "./dotenv.ts";

describe("parseDotenv", () => {
  test("handles comments, blanks, export and quoting", () => {
    const result = parseDotenv(
      [
        "# a comment",
        "",
        "PLAIN=value",
        "export EXPORTED=value",
        'DOUBLE="a b\\nc"',
        "SINGLE='a b\\nc'",
        "SPACED  =  padded  ",
        "TRAILING=value # comment",
        "EMPTY=",
      ].join("\n"),
    );
    expect(result.problems).toEqual([]);
    expect(result.entries).toEqual([
      { name: "PLAIN", value: "value" },
      { name: "EXPORTED", value: "value" },
      { name: "DOUBLE", value: "a b\nc" },
      { name: "SINGLE", value: "a b\\nc" },
      { name: "SPACED", value: "padded" },
      { name: "TRAILING", value: "value" },
      { name: "EMPTY", value: "" },
    ]);
  });

  test("a later assignment wins", () => {
    const result = parseDotenv("A=1\nA=2\n");
    expect(result.entries).toEqual([{ name: "A", value: "2" }]);
  });

  test("reports invalid names, malformed lines and unterminated quotes without values", () => {
    const result = parseDotenv(["lower=1", "NO_EQUALS", 'OPEN="value'].join("\n"));
    expect(result.entries).toEqual([]);
    expect(result.problems).toEqual([
      { lineNumber: 1, reason: "invalid_name", name: "lower" },
      { lineNumber: 2, reason: "malformed_line", name: null },
      { lineNumber: 3, reason: "unterminated_quote", name: "OPEN" },
    ]);
  });

  test("a value containing a hash with no leading space is kept", () => {
    expect(parseDotenv("PASSWORD=p@ss#word").entries).toEqual([
      { name: "PASSWORD", value: "p@ss#word" },
    ]);
  });
});
