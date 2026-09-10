import { createFileRoute, Link } from "@tanstack/react-router";
import { TriangleAlert } from "lucide-react";

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
import { VerificationBadge } from "@/components/vault/verification-badge";
import { relativeAge } from "@/lib/relative-age";
import { loadOrRedirect } from "@/lib/route-guards";
import { listPendingBootsFn, type PendingBootGroup } from "@/server/functions/boots";
import { getViewerFn, type Viewer } from "@/server/functions/session";

interface BootsData {
  viewer: Viewer;
  groups: PendingBootGroup[];
}

export const Route = createFileRoute("/boots/")({
  loader: async (): Promise<BootsData> =>
    await loadOrRedirect(async () => ({
      viewer: await getViewerFn(),
      groups: await listPendingBootsFn(),
    })),
  component: BootsPage,
});

function BootsPage() {
  const { viewer, groups } = Route.useLoaderData();
  const total = groups.reduce((count, group) => count + group.boots.length, 0);

  return (
    <div className="flex flex-col gap-6">
      <VaultPageHeader
        title="Pending boots"
        description={
          total === 0
            ? "All caught up."
            : `${total} boot ${total === 1 ? "request" : "requests"} awaiting review.`
        }
        role={viewer.role}
      />
      {groups.length === 0 ? (
        <Card>
          <CardContent className="text-muted-foreground text-sm">
            New boot requests will appear here.
          </CardContent>
        </Card>
      ) : (
        groups.map((group) => <EnvironmentGroup key={group.environmentId} group={group} />)
      )}
    </div>
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
