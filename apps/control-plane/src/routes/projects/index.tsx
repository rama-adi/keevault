import { createFileRoute, redirect } from "@tanstack/react-router";
import { createServerFn } from "@tanstack/react-start";

import { Card, CardContent } from "@/components/ui/card";
import { VaultPageHeader } from "@/components/vault/vault-page-header";
import { getVaultSession } from "@/server/auth/guards";
import type { Role } from "@/lib/roles";

interface ProjectsView {
  name: string;
  role: Role;
}

const loadProjectsView = createServerFn({ method: "GET" }).handler(
  async (): Promise<ProjectsView | null> => {
    const session = await getVaultSession();
    if (session === null) {
      return null;
    }
    return { name: session.name, role: session.role };
  },
);

export const Route = createFileRoute("/projects/")({
  async loader(): Promise<ProjectsView> {
    const view = await loadProjectsView();
    if (view === null) {
      throw redirect({ to: "/login" });
    }
    return view;
  },
  component: ProjectsPage,
});

/**
 * Placeholder. The vault agent replaces the body with the project list read
 * from VAULT_DB through packages/vault-store.
 */
function ProjectsPage() {
  const view = Route.useLoaderData();
  return (
    <div>
      <VaultPageHeader
        title="Projects"
        description={`Signed in as ${view.name}.`}
        role={view.role}
      />
      <Card>
        <CardContent className="text-muted-foreground text-sm">
          No projects yet. Project and environment management lands with the vault store work
          package.
        </CardContent>
      </Card>
    </div>
  );
}
