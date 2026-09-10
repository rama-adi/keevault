import type { BootHistoryPage } from "@keevault/vault-store";
import { z } from "zod";
import { createFileRoute, Link } from "@tanstack/react-router";
import { TriangleAlert } from "lucide-react";

import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { formatDate } from "@/lib/format";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { VaultAlert, VaultAlertDescription } from "@/components/vault/vault-alert";
import { VaultPageHeader } from "@/components/vault/vault-page-header";
import { VerificationBadge, toneForStatus } from "@/components/vault/verification-badge";
import { relativeAge } from "@/lib/relative-age";
import { loadOrRedirect } from "@/lib/route-guards";
import {
  listPendingBootsFn,
  listBootHistoryFn,
  type PendingBootGroup,
} from "@/server/functions/boots";
import { getViewerFn, type Viewer } from "@/server/functions/session";

interface BootsData {
  viewer: Viewer;
  groups: PendingBootGroup[];
  history: BootHistoryPage | null;
}

const searchSchema = z.object({
  tab: z.enum(["pending", "history"]).optional().catch(undefined),
  before: z.iso.datetime().optional().catch(undefined),
  beforeId: z
    .string()
    .regex(/^boot_[0-9A-HJKMNP-TV-Z]{26}$/)
    .optional()
    .catch(undefined),
});

export const Route = createFileRoute("/boots/")({
  validateSearch: (search: Record<string, string | undefined>) => searchSchema.parse(search),
  loaderDeps: ({ search }) => search,
  loader: async ({ deps }): Promise<BootsData> =>
    await loadOrRedirect(async () => {
      const viewer = await getViewerFn();
      const groups = deps.tab === "history" ? [] : await listPendingBootsFn();
      const history =
        deps.tab === "history"
          ? await listBootHistoryFn({
              data: {
                before:
                  deps.before && deps.beforeId
                    ? { createdAt: deps.before, id: deps.beforeId }
                    : null,
              },
            })
          : null;
      return { viewer, groups, history };
    }),
  component: BootsPage,
});

function BootsPage() {
  const { viewer, groups, history } = Route.useLoaderData();
  const search = Route.useSearch();
  const navigate = Route.useNavigate();
  const total = groups.reduce((count, group) => count + group.boots.length, 0);

  return (
    <div className="flex flex-col gap-6">
      <VaultPageHeader
        title="Boot requests"
        description="Review pending requests and look back at previous boots."
        role={viewer.role}
      />
      <Tabs
        value={search.tab ?? "pending"}
        onValueChange={(value) => {
          void navigate({ search: { tab: value === "history" ? "history" : "pending" } });
        }}
      >
        <TabsList aria-label="Boot requests">
          <TabsTrigger value="pending">
            {search.tab === "history" ? "Pending" : `Pending · ${total}`}
          </TabsTrigger>
          <TabsTrigger value="history">History</TabsTrigger>
        </TabsList>
        <TabsContent value="pending" className="pt-4">
          <div className="flex flex-col gap-6">
            {groups.length === 0 ? (
              <Card>
                <CardContent className="text-muted-foreground text-sm">
                  No pending requests. New boot requests will appear here.
                </CardContent>
              </Card>
            ) : (
              groups.map((group) => <EnvironmentGroup key={group.environmentId} group={group} />)
            )}
          </div>
        </TabsContent>
        <TabsContent value="history" className="pt-4">
          {history ? (
            <HistoryTable history={history} paginated={Boolean(search.before && search.beforeId)} />
          ) : null}
        </TabsContent>
      </Tabs>
    </div>
  );
}

function HistoryTable({ history, paginated }: { history: BootHistoryPage; paginated: boolean }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Boot history</CardTitle>
        <CardDescription>
          Requests no longer awaiting review, newest first. Times are UTC.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        {history.boots.length === 0 ? (
          <p className="text-muted-foreground text-sm">
            {paginated
              ? "No older boot requests."
              : "No boot history yet. Requests appear here after they leave pending review."}
          </p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Environment</TableHead>
                <TableHead>Token / request</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Source IP</TableHead>
                <TableHead>Claimed commit</TableHead>
                <TableHead>Requested</TableHead>
                <TableHead>Updated</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {history.boots.map((boot) => (
                <TableRow key={boot.id}>
                  <TableCell>
                    <div className="font-medium">{boot.environmentName}</div>
                    <div className="text-muted-foreground text-xs">{boot.projectName}</div>
                  </TableCell>
                  <TableCell>
                    <div className="font-medium">{boot.tokenLabel}</div>
                    <div className="text-muted-foreground font-mono text-xs">{boot.id}</div>
                  </TableCell>
                  <TableCell>
                    <VerificationBadge tone={toneForStatus(boot.status)}>
                      {boot.status.toLowerCase()}
                    </VerificationBadge>
                  </TableCell>
                  <TableCell className="font-mono text-xs">{boot.sourceIp ?? "unknown"}</TableCell>
                  <TableCell
                    className="font-mono text-xs"
                    title={boot.claimedGitCommit ?? undefined}
                  >
                    {boot.claimedGitCommit?.slice(0, 12) ?? "-"}
                  </TableCell>
                  <TableCell className="text-muted-foreground text-xs">
                    <time dateTime={boot.createdAt}>{formatDate(boot.createdAt)}</time>
                  </TableCell>
                  <TableCell className="text-muted-foreground text-xs">
                    <time dateTime={boot.updatedAt}>{formatDate(boot.updatedAt)}</time>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
        <div className="flex justify-end gap-2">
          {paginated ? (
            <Button asChild size="sm" variant="outline">
              <Link to="/boots" search={{ tab: "history" }}>
                Newest requests
              </Link>
            </Button>
          ) : null}
          {history.nextCursor ? (
            <Button asChild size="sm" variant="outline">
              <Link
                to="/boots"
                search={{
                  tab: "history",
                  before: history.nextCursor.createdAt,
                  beforeId: history.nextCursor.id,
                }}
              >
                Older requests
              </Link>
            </Button>
          ) : null}
        </div>
      </CardContent>
    </Card>
  );
}

function EnvironmentGroup({ group }: { group: PendingBootGroup }) {
  // Spec section 37: a stolen token shows up as several live boots collapsed
  // under one token, so say so instead of letting it read as ordinary traffic.
  const unusual = group.liveBootsByToken.filter((entry) => entry.count > 1);

  return (
    <Card>
      <CardHeader>
        <CardTitle>{group.environmentName}</CardTitle>
        <CardDescription>
          {group.projectName} · {group.provenanceMode} provenance
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        {unusual.length === 0 ? null : (
          <VaultAlert tone="warning">
            <TriangleAlert />
            <VaultAlertDescription>
              Unusual activity:{" "}
              {unusual
                .map((entry) => `${entry.tokenLabel} has ${entry.count} live boots`)
                .join(", ")}
              . Expected one live boot per token.
            </VaultAlertDescription>
          </VaultAlert>
        )}
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Token</TableHead>
              <TableHead>Source IP</TableHead>
              <TableHead>Claimed commit</TableHead>
              <TableHead>Requested</TableHead>
              <TableHead>State</TableHead>
              <TableHead className="text-right">Review</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {group.boots.map((boot) => (
              <TableRow key={boot.bootId}>
                <TableCell className="font-medium">
                  {boot.tokenLabel}
                  {group.liveBootsByToken.some(
                    (entry) => entry.tokenId === boot.tokenId && entry.count > 1,
                  ) ? (
                    <span className="text-muted-foreground ml-2 text-xs">unusual activity</span>
                  ) : null}
                </TableCell>
                <TableCell className="font-mono text-xs">{boot.sourceIp ?? "unknown"}</TableCell>
                <TableCell className="font-mono text-xs">
                  {boot.claimedGitCommit === null ? "-" : boot.claimedGitCommit.slice(0, 12)}
                </TableCell>
                <TableCell className="text-muted-foreground text-xs">
                  {relativeAge(boot.createdAt)}
                </TableCell>
                <TableCell>
                  <VerificationBadge tone={boot.connected ? "live" : "unavailable"}>
                    {boot.connected ? "connected" : "waiting"}
                  </VerificationBadge>
                </TableCell>
                <TableCell className="text-right">
                  <Button asChild size="sm" variant="outline">
                    <Link to="/boots/$bootId" params={{ bootId: boot.bootId }}>
                      Review
                    </Link>
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
}
