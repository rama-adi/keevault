import { cn } from "@/lib/utils";

/**
 * The stand-in for a secret value in the dashboard (spec section 23).
 *
 * There is no reveal control here and no server function that could feed one.
 * The mask is a fixed width so a reader cannot infer the length of the value.
 */

export interface MaskedSecretProps {
  className?: string;
}

const MASK = "••••••••••••";

export function MaskedSecret({ className }: MaskedSecretProps) {
  return (
    <span
      aria-label="value hidden"
      className={cn("text-muted-foreground font-mono tracking-widest select-none", className)}
    >
      {MASK}
    </span>
  );
}
