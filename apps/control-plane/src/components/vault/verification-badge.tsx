import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "cn";

/**
 * Status pill for verifier output and boot state, copied from the shadcn
 * `badge` primitive and restyled here.
 *
 * FAILED and UNAVAILABLE must not look alike: one means evidence was supplied
 * and did not validate, the other means no attestation exists at all (spec
 * section 25).
 */

const verificationBadgeVariants = cva(
  "inline-flex h-5 w-fit shrink-0 items-center justify-center gap-1 rounded-4xl border px-2 py-0.5 font-mono text-xs font-medium tracking-tight whitespace-nowrap",
  {
    variants: {
      tone: {
        verified: "border-emerald-600/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
        failed: "border-destructive bg-destructive/15 text-destructive",
        unverified: "border-border bg-muted text-muted-foreground",
        unavailable: "border-dashed border-border bg-transparent text-muted-foreground",
        live: "border-primary/40 bg-primary/10 text-primary",
      },
    },
    defaultVariants: { tone: "unverified" },
  },
);

export type VerificationBadgeTone = NonNullable<
  VariantProps<typeof verificationBadgeVariants>["tone"]
>;

const TONE_FOR_STATUS: ReadonlyMap<string, VerificationBadgeTone> = new Map([
  ["VERIFIED", "verified"],
  ["FAILED", "failed"],
  ["UNVERIFIED", "unverified"],
  ["UNAVAILABLE", "unavailable"],
  ["PENDING", "live"],
  ["APPROVED", "verified"],
  ["DELIVERED", "verified"],
  ["CONSUMED", "unverified"],
  ["DECLINED", "failed"],
  ["EXPIRED", "unavailable"],
  ["CANCELED", "failed"],
]);

/** Pick the tone for a verifier status or a boot status. */
export function toneForStatus(status: string): VerificationBadgeTone {
  return TONE_FOR_STATUS.get(status) ?? "unverified";
}

export function VerificationBadge({
  className,
  tone,
  ...props
}: React.ComponentProps<"span"> & VariantProps<typeof verificationBadgeVariants>) {
  return (
    <span
      data-slot="badge"
      className={cn(verificationBadgeVariants({ tone }), className)}
      {...props}
    />
  );
}
