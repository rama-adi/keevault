import { createFileRoute, useRouter } from "@tanstack/react-router";
import { useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Field, FieldLabel } from "@/components/ui/field";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { VaultPageHeader } from "@/components/vault/vault-page-header";
import { formatDate } from "@/lib/format";
import { loadOrRedirect } from "@/lib/route-guards";
import {
  listAuditEventsFn,
  listAuditFiltersFn,
  type AuditFilterProject,
} from "@/server/functions/audit";
import { getViewerFn, type Viewer } from "@/server/functions/session";
import type { AuditEventView } from "@/server/vault/service";

interface AuditData {
  viewer: Viewer;
  filters: AuditFilterProject[];
  events: AuditEventView[];
  nextCursor: string | null;
}

interface AuditSearch {
  projectId?: string;
  environmentId?: string;
  before?: string;
}

export const Route = createFileRoute("/audit/")({
  validateSearch: (search: Record<string, string | undefined>): AuditSearch => ({
    projectId: search["projectId"],
    environmentId: search["environmentId"],
    before: search["before"],
  }),
  loaderDeps: ({ search }) => search,
  loader: async ({ deps }): Promise<AuditData> =>
    await loadOrRedirect(async () => {
      const viewer = await getViewerFn();
      const filters = await listAuditFiltersFn();
      const page = await listAuditEventsFn({
        data: {
          projectId: deps.projectId ?? null,
          environmentId: deps.environmentId ?? null,
          before: deps.before ?? null,
        },
      });
      return { viewer, filters, events: page.events, nextCursor: page.nextCursor };
    }),
  component: AuditPage,
});

function AuditPage() {
  const { viewer, filters, events, nextCursor } = Route.useLoaderData();
  const search = Route.useSearch();
  const router = useRouter();
  const [expanded, setExpanded] = useState<string | null>(null);

  const selectedProject = filters.find((entry) => entry.project.id === search.projectId);

  function navigate(next: AuditSearch) {
    void router.navigate({ to: "/audit", search: next });
  }

  return (
    <div className="flex flex-col gap-6">
      <VaultPageHeader
        title="Audit"
        description="Every vault mutation, newest first. Metadata holds identifiers, fingerprints and counts, never a value."
        role={viewer.role}
      />

      <Card>
        <CardContent className="flex flex-wrap items-end gap-4">
          <Field className="w-56">
            <FieldLabel htmlFor="filter-project">Project</FieldLabel>
            <select
              id="filter-project"
              className="border-input bg-background h-9 rounded-md border px-3 text-sm"
              value={search.projectId ?? ""}
              onChange={(event) => {
                const value = event.target.value;
                navigate(value === "" ? {} : { projectId: value });
              }}
            >
              <option value="">All projects</option>
              {filters.map((entry) => (
                <option key={entry.project.id} value={entry.project.id}>
                  {entry.project.name}
                </option>
              ))}
            </select>
          </Field>
          <Field className="w-56">
            <FieldLabel htmlFor="filter-environment">Environment</FieldLabel>
            <select
              id="filter-environment"
              className="border-input bg-background h-9 rounded-md border px-3 text-sm"
              disabled={selectedProject === undefined}
              value={search.environmentId ?? ""}
              onChange={(event) => {
                const value = event.target.value;
                navigate(
                  value === ""
                    ? { projectId: search.projectId }
                    : { projectId: search.projectId, environmentId: value },
                );
              }}
            >
              <option value="">All environments</option>
              {(selectedProject?.environments ?? []).map((environment) => (
                <option key={environment.id} value={environment.id}>
                  {environment.name}
                </option>
              ))}
            </select>
          </Field>
          {search.before === undefined ? null : (
            <Button
              variant="ghost"
              size="sm"
              onClick={() => {
                navigate({ projectId: search.projectId, environmentId: search.environmentId });
              }}
            >
              Back to newest
            </Button>
          )}
        </CardContent>
      </Card>

      <Card className="p-0">
        {events.length === 0 ? (
          <CardContent className="text-muted-foreground p-6 text-sm">
            No audit events match this filter.
          </CardContent>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-44">Time</TableHead>
                <TableHead>Action</TableHead>
                <TableHead>Actor</TableHead>
                <TableHead>Scope</TableHead>
                <TableHead className="w-24" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {events.map((event) => (
                <TableRow key={event.id}>
                  <TableCell className="text-muted-foreground text-xs">
                    {formatDate(event.timestamp)}
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline" className="font-mono text-xs">
                      {event.action}
                    </Badge>
                    {expanded === event.id ? (
                      <pre className="bg-muted mt-2 overflow-x-auto rounded-md p-3 text-xs">
                        {event.metadataJson}
                      </pre>
                    ) : null}
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    {event.actorType}
                    {event.actorId === null ? "" : ` ${event.actorId}`}
                  </TableCell>
                  <TableCell className="text-muted-foreground font-mono text-xs">
                    {event.environmentId ?? event.projectId ?? "-"}
                  </TableCell>
                  <TableCell className="text-right">
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => {
                        setExpanded(expanded === event.id ? null : event.id);
                      }}
                    >
                      {expanded === event.id ? "Hide" : "Details"}
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </Card>

      {nextCursor === null ? null : (
        <Button
          variant="outline"
          className="w-fit"
          onClick={() => {
            navigate({
              projectId: search.projectId,
              environmentId: search.environmentId,
              before: nextCursor,
            });
          }}
        >
          Older events
        </Button>
      )}
    </div>
  );
}
