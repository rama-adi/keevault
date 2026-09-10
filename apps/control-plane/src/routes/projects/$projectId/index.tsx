import { createFileRoute, Link, useRouter } from "@tanstack/react-router";
import { Plus } from "lucide-react";
import { useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Field, FieldDescription, FieldGroup, FieldLabel } from "@/components/ui/field";
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
import {
  createEnvironmentFn,
  deleteProjectFn,
  getProjectDetailFn,
  rotateProjectKeyFn,
} from "@/server/functions/projects";
import { canEdit, getViewerFn, isOwner, type Viewer } from "@/server/functions/session";
import type { EnvironmentSummary, ProjectSummary } from "@/server/vault/service";

interface ProjectData {
  viewer: Viewer;
  project: ProjectSummary;
  environments: EnvironmentSummary[];
}

export const Route = createFileRoute("/projects/$projectId/")({
  loader: async ({ params }): Promise<ProjectData> =>
    await loadOrRedirect(async () => {
      const viewer = await getViewerFn();
      const detail = await getProjectDetailFn({ data: { projectId: params.projectId } });
      if (detail === null) throw new Error("That project does not exist.");
      return { viewer, project: detail.project, environments: detail.environments };
    }),
  component: ProjectPage,
});

function ProjectPage() {
  const { viewer, project, environments } = Route.useLoaderData();
  const [createOpen, setCreateOpen] = useState(false);

  return (
    <div className="flex flex-col gap-6">
      <VaultPageHeader
        title={project.name}
        description={project.slug}
        actions={
          canEdit(viewer.role) ? (
            <Button
              size="sm"
              onClick={() => {
                setCreateOpen(true);
              }}
            >
              <Plus data-icon="inline-start" />
              New environment
            </Button>
          ) : undefined
        }
      />

      <Card className="p-0">
        <CardHeader className="p-6 pb-0">
          <CardTitle>Environments · {environments.length}</CardTitle>
        </CardHeader>
        {environments.length === 0 ? (
          <CardContent className="text-muted-foreground p-6 text-sm">
            No environments yet.
          </CardContent>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Environment</TableHead>
                <TableHead>Provenance</TableHead>
                <TableHead className="text-right">Key version</TableHead>
                <TableHead className="text-right">Created</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {environments.map((environment) => (
                <TableRow key={environment.id}>
                  <TableCell className="font-medium">
                    <Link
                      to="/projects/$projectId/environments/$environmentId"
                      params={{ projectId: project.id, environmentId: environment.id }}
                      className="hover:underline"
                    >
                      {environment.name}
                    </Link>
                    <p className="text-muted-foreground mt-1 font-mono text-xs">
                      {environment.slug}
                    </p>
                  </TableCell>
                  <TableCell>
                    <Badge
                      variant={environment.provenanceMode === "REQUIRED" ? "default" : "outline"}
                    >
                      {environment.provenanceMode}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-right tabular-nums">
                    {environment.environmentKeyVersion}
                  </TableCell>
                  <TableCell className="text-muted-foreground text-right text-xs">
                    {formatDate(environment.createdAt)}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </Card>

      {canEdit(viewer.role) ? <DangerZone project={project} viewer={viewer} /> : null}

      <CreateEnvironmentDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        projectId={project.id}
      />
    </div>
  );
}

interface CreateEnvironmentDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  projectId: string;
}

function CreateEnvironmentDialog({ open, onOpenChange, projectId }: CreateEnvironmentDialogProps) {
  const action = useVaultAction();
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");

  function submit() {
    void action
      .run(async () => {
        await createEnvironmentFn({
          data: { projectId, name: name.trim(), slug: slug.trim() },
        });
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
        title="New environment"
        submitLabel="Create environment"
        pendingLabel="Creating"
        pending={action.pending}
        error={action.error}
        onSubmit={submit}
      >
        <FieldGroup>
          <Field>
            <FieldLabel htmlFor="environment-name">Name</FieldLabel>
            <Input
              id="environment-name"
              value={name}
              autoComplete="off"
              onChange={(event) => {
                setName(event.target.value);
                setSlug(toSlug(event.target.value));
              }}
            />
          </Field>
          <Field>
            <FieldLabel htmlFor="environment-slug">Slug</FieldLabel>
            <Input
              id="environment-slug"
              value={slug}
              autoComplete="off"
              onChange={(event) => {
                setSlug(event.target.value);
              }}
            />
            <FieldDescription>Unique within this project.</FieldDescription>
          </Field>
        </FieldGroup>
      </VaultDialog>
      {action.stepUpDialog}
    </>
  );
}

interface DangerZoneProps {
  project: ProjectSummary;
  viewer: Viewer;
}

function DangerZone({ project, viewer }: DangerZoneProps) {
  const router = useRouter();
  const action = useVaultAction();
  const [rotateOpen, setRotateOpen] = useState(false);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [confirmation, setConfirmation] = useState("");

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle>Project settings</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div className="text-sm">
              <p className="font-medium">Rotate the project key</p>
              <p className="text-muted-foreground">
                Key version {project.projectKeyVersion}. Only owners can rotate keys.
              </p>
            </div>
            <Button
              variant="outline"
              size="sm"
              disabled={!isOwner(viewer.role)}
              onClick={() => {
                setRotateOpen(true);
              }}
            >
              Rotate
            </Button>
          </div>
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div className="text-sm">
              <p className="font-medium">Delete this project</p>
              <p className="text-muted-foreground">
                Permanently delete all environments, secrets and tokens.
              </p>
            </div>
            <Button
              variant="destructive"
              size="sm"
              onClick={() => {
                setDeleteOpen(true);
              }}
            >
              Delete
            </Button>
          </div>
        </CardContent>
      </Card>

      <VaultDialog
        open={rotateOpen}
        onOpenChange={setRotateOpen}
        title="Rotate the project key"
        description="A new project key is generated and every environment key is rewrapped under it."
        submitLabel="Rotate key"
        pendingLabel="Rotating"
        pending={action.pending}
        error={action.error}
        onSubmit={() => {
          void action
            .run(async () => {
              await rotateProjectKeyFn({ data: { projectId: project.id } });
            })
            .then((done) => {
              if (done) setRotateOpen(false);
            });
        }}
      >
        <p className="text-muted-foreground text-sm">
          Current version {project.projectKeyVersion}. The retiring key is kept so historical
          environment keys stay readable.
        </p>
      </VaultDialog>

      <VaultDialog
        open={deleteOpen}
        onOpenChange={setDeleteOpen}
        title={`Delete ${project.name}`}
        description="Permanently deletes all environments, secrets and tokens. Type the project slug to confirm."
        submitLabel="Delete project"
        pendingLabel="Deleting"
        destructive
        pending={action.pending || confirmation !== project.slug}
        error={action.error}
        onSubmit={() => {
          if (confirmation !== project.slug) return;
          void action
            .run(async () => {
              await deleteProjectFn({ data: { projectId: project.id } });
            })
            .then((done) => {
              if (done) {
                setDeleteOpen(false);
                void router.navigate({ to: "/projects" });
              }
            });
        }}
      >
        <Field>
          <FieldLabel htmlFor="confirm-slug">Project slug</FieldLabel>
          <Input
            id="confirm-slug"
            value={confirmation}
            autoComplete="off"
            onChange={(event) => {
              setConfirmation(event.target.value);
            }}
          />
        </Field>
      </VaultDialog>
      {action.stepUpDialog}
    </>
  );
}
