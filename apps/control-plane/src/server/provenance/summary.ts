import { sha256HexOfText } from "@keevault/crypto";
import { z } from "zod";

import { VERIFICATION_STATUSES } from "./types.ts";
import type { VerificationFact, VerificationResult } from "./types.ts";

/**
 * The canonical form of a provenance summary and its digest.
 *
 * The approver's decision is bound to a digest of exactly what they were shown
 * (spec section 22), so the serialisation has to be byte-stable. Keys are
 * written in sorted order by hand rather than walked generically, which keeps
 * the ordering visible in the source and rules out any dependency on property
 * insertion order.
 */

function canonicalFact(entry: VerificationFact): string {
  const key = JSON.stringify(entry.key);
  const matchesClaim = entry.matchesClaim === null ? "null" : String(entry.matchesClaim);
  const value = JSON.stringify(entry.value);
  return `{"key":${key},"matchesClaim":${matchesClaim},"value":${value}}`;
}

function canonicalResult(result: VerificationResult): string {
  const facts = result.facts.map(canonicalFact).join(",");
  const warnings = result.warnings.map((warning) => JSON.stringify(warning)).join(",");
  return (
    `{"facts":[${facts}],` +
    `"status":${JSON.stringify(result.status)},` +
    `"verifier":${JSON.stringify(result.verifier)},` +
    `"warnings":[${warnings}]}`
  );
}

/** Canonical JSON for a whole summary. Object keys are sorted at every level. */
export function canonicalSummary(results: readonly VerificationResult[]): string {
  return `{"results":[${results.map(canonicalResult).join(",")}]}`;
}

/** Lowercase hex SHA-256 of the canonical summary. Stored on the approval record. */
export async function summaryDigest(results: readonly VerificationResult[]): Promise<string> {
  return await sha256HexOfText(canonicalSummary(results));
}

const jsonText = z.string().transform((text, context) => {
  try {
    return JSON.parse(text);
  } catch {
    context.addIssue({ code: "custom", message: "summary is not valid JSON" });
    return z.NEVER;
  }
});

/** Schema for reading a stored summary back out of D1 or the Durable Object. */
export const provenanceSummarySchema = z.object({
  results: z.array(
    z.object({
      facts: z.array(
        z.object({
          key: z.string(),
          matchesClaim: z.boolean().nullable(),
          value: z.string(),
        }),
      ),
      status: z.enum(VERIFICATION_STATUSES),
      verifier: z.string(),
      warnings: z.array(z.string()),
    }),
  ),
});

/** Parse a stored summary. Returns an empty result list when the text is unusable. */
export function parseSummary(text: string | null): VerificationResult[] {
  if (text === null) return [];
  const parsed = jsonText.pipe(provenanceSummarySchema).safeParse(text);
  if (!parsed.success) return [];
  return parsed.data.results;
}
