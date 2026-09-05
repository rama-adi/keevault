import { createFileRoute, Link } from "@tanstack/react-router";
import { Plus } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useVaultAction } from "@/components/vault/use-vault-action";
import { VaultDialog } from "@/components/vault/vault-dialog";
import { VaultPageHeader } from "@/components/vault/vault-page-header";
import { formatDate, toSlug } from "@/lib/format";
import { loadOrRedirect } from "@/lib/route-guards";
import { createProjectFn, listProjectsFn } from "@/server/functions/projects";
import { canEdit, getViewerFn, type Viewer } from "@/server/functions/session";
import type { ProjectSummary } from "@/server/vault/service";

interface ProjectsData {
  viewer: Viewer;
  projects: ProjectSummary[];
}

export const Route = createFileRoute("/projects/")({
  loader: async (): Promise<ProjectsData> =>
    await loadOrRedirect(async () => ({
      viewer: await getViewerFn(),
      projects: await listProjectsFn(),
    })),
  component: ProjectsPage,
});

function ProjectsPage() {
  const { viewer, projects } = Route.useLoaderData();
  const [open, setOpen] = useState(false);

  return (
    <div>
      <VaultPageHeader
        title="Projects"
        description={`Signed in as ${viewer.name}.`}
        role={viewer.role}
        actions={
          canEdit(viewer.role) ? (
            <Button
              size="sm"
              onClick={() => {
                setOpen(true);
              }}
            >
              <Plus className="size-4" />
              New project
            </Button>
          ) : undefined
        }
      />
      {projects.length === 0 ? (
        <Card>
          <CardContent className="text-muted-foreground text-sm">
            No projects yet. A project holds its own key, and every environment under it holds
            another.
          </CardContent>
        </Card>
      ) : (
        <Card className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Project</TableHead>
                <TableHead>Slug</TableHead>
                <TableHead className="text-right">Key version</TableHead>
                <TableHead className="text-right">Created</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {projects.map((project) => (
                <TableRow key={project.id}>
                  <TableCell className="font-medium">
                    <Link
                      to="/projects/$projectId"
                      params={{ projectId: project.id }}
                      className="hover:underline"
                    >
                      {project.name}
                    </Link>
                  </TableCell>
                  <TableCell className="text-muted-foreground font-mono text-xs">
                    {project.slug}
                  </TableCell>
                  <TableCell className="text-right tabular-nums">
                    {project.projectKeyVersion}
                  </TableCell>
                  <TableCell className="text-muted-foreground text-right text-xs">
                    {formatDate(project.createdAt)}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      )}
      <CreateProjectDialog open={open} onOpenChange={setOpen} />
    </div>
  );
}

interface CreateProjectDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

function CreateProjectDialog({ open, onOpenChange }: CreateProjectDialogProps) {
  const action = useVaultAction();
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");

  function submit() {
    void action
      .run(async () => {
        await createProjectFn({ data: { name: name.trim(), slug: slug.trim() } });
      })
      .then((done) => {
        if (done) {
          setName("");
          setSlug("");
          onOpenChange(false);
        }
      });
  }

  return (
    <>
      <VaultDialog
        open={open}
        onOpenChange={onOpenChange}
        title="New project"
        description="A project groups environments and owns the key that wraps their keys."
        submitLabel="Create project"
        pendingLabel="Creating"
        pending={action.pending}
        error={action.error}
        onSubmit={submit}
      >
        <FieldGroup>
          <Field>
            <FieldLabel htmlFor="project-name">Name</FieldLabel>
            <Input
              id="project-name"
              value={name}
              autoComplete="off"
              onChange={(event) => {
                setName(event.target.value);
                setSlug(toSlug(event.target.value));
              }}
            />
          </Field>
          <Field>
            <FieldLabel htmlFor="project-slug">Slug</FieldLabel>
            <Input
              id="project-slug"
              value={slug}
              autoComplete="off"
              onChange={(event) => {
                setSlug(event.target.value);
              }}
            />
          </Field>
        </FieldGroup>
      </VaultDialog>
      {action.stepUpDialog}
    </>
  );
}
