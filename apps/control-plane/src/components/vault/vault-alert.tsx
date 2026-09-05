import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "cn";

/**
 * The alert the approval screen uses, copied from the shadcn `alert` primitive
 * and restyled here rather than in `components/ui`, which every other consumer
 * shares.
 *
 * The `danger` tone is deliberately loud. Spec section 34 asks for failed
 * cryptographic evidence to be impossible to miss, not a subtle warning.
 */

const vaultAlertVariants = cva(
  "relative grid w-full gap-1 rounded-lg border px-3 py-2.5 text-left text-sm has-[>svg]:grid-cols-[auto_1fr] has-[>svg]:gap-x-2.5 *:[svg]:row-span-2 *:[svg]:translate-y-0.5 *:[svg:not([class*='size-'])]:size-4",
  {
    variants: {
      tone: {
        danger: "border-destructive bg-destructive/10 text-destructive font-medium",
        warning: "border-amber-500/50 bg-amber-500/10 text-amber-900 dark:text-amber-200",
        note: "bg-card text-card-foreground",
      },
    },
    defaultVariants: { tone: "note" },
  },
);

export function VaultAlert({
  className,
  tone,
  ...props
}: React.ComponentProps<"div"> & VariantProps<typeof vaultAlertVariants>) {
  return (
    <div
      data-slot="alert"
      role="alert"
      className={cn(vaultAlertVariants({ tone }), className)}
      {...props}
    />
  );
}

export function VaultAlertTitle({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="alert-title"
      className={cn("font-semibold tracking-tight", className)}
      {...props}
    />
  );
}

export function VaultAlertDescription({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div data-slot="alert-description" className={cn("text-sm opacity-90", className)} {...props} />
  );
}
