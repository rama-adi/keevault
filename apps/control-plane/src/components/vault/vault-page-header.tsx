import type { ReactNode } from "react";

import { Badge } from "@/components/ui/badge";
import { Card, CardAction, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";

/**
 * Product-facing page header, copied from the shadcn `card` primitive and
 * restyled here rather than in `components/ui`, which every other consumer
 * shares. New styled components in this directory follow the same shape:
 * import the primitive, wrap it, keep `className` for layout only.
 */

export type VaultRoleName = "owner" | "admin" | "viewer";

const ROLE_VARIANT: ReadonlyMap<VaultRoleName, "default" | "secondary" | "outline"> = new Map([
  ["owner", "default"],
  ["admin", "secondary"],
  ["viewer", "outline"],
]);

export interface VaultPageHeaderProps {
  title: string;
  description?: string;
  /** Rendered as a badge on the right, for the signed-in operator's role. */
  role?: VaultRoleName;
  /** Buttons or menus for the page. */
  actions?: ReactNode;
  className?: string;
}

export function VaultPageHeader({
  title,
  description,
  role,
  actions,
  className,
}: VaultPageHeaderProps) {
  return (
    <Card className={cn("vault-page-header mb-8", className)}>
      <CardHeader>
        <CardTitle>
          <h1>{title}</h1>
        </CardTitle>
        {description === undefined ? null : <CardDescription>{description}</CardDescription>}
        {role === undefined && actions === undefined ? null : (
          <CardAction className="flex items-center gap-2">
            {role === undefined ? null : (
              <Badge variant={ROLE_VARIANT.get(role) ?? "outline"}>{role}</Badge>
            )}
            {actions}
          </CardAction>
        )}
      </CardHeader>
    </Card>
  );
}
