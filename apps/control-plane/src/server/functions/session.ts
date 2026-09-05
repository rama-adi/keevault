/**
 * Who is looking at the page.
 *
 * Every vault page needs the operator's name and role to decide which controls
 * to render. The server still enforces the role on each mutation; this only
 * decides what is worth showing.
 */

import { createServerFn } from "@tanstack/react-start";

import type { Role } from "../../lib/roles.ts";
import { requireSession } from "../auth/guards.ts";
import { guarded } from "./guarded.ts";

export interface Viewer {
  name: string;
  email: string;
  role: Role;
}

export const getViewerFn = createServerFn({ method: "GET" }).handler(
  async (): Promise<Viewer> =>
    await guarded(async () => {
      const session = await requireSession();
      return { name: session.name, email: session.email, role: session.role };
    }),
);

/** True when the viewer may edit secrets, tokens and policy. */
export function canEdit(role: Role): boolean {
  return role === "admin" || role === "owner";
}

/** True when the viewer may rotate keys and manage administrators. */
export function isOwner(role: Role): boolean {
  return role === "owner";
}
