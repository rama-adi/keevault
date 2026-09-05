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
import { VerificationBadge, toneForStatus } from "@/components/vault/verification-badge";
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
    <div className="flex flex-col gap-8">
      <VaultPageHeader
        title="Pending boots"
        description={
          total === 0
            ? "No workload is waiting for a decision."
            : `${total} boot ${total === 1 ? "request is" : "requests are"} waiting for a decision.`
        }
        role={viewer.role}
      />
      {groups.length === 0 ? (
        <Card>
          <CardContent className="text-muted-foreground text-sm">
            Nothing is waiting. A boot appears here as soon as a workload opens /bootstrap/v1 with a
            valid bootstrap token.
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
        <CardTitle className="uppercase">{group.environmentName}</CardTitle>
        <CardDescription>
          Project {group.projectName}. Provenance {group.provenanceMode}.
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
              . One token normally drives one boot at a time.
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
        <p className="text-muted-foreground text-xs">
          <VerificationBadge tone={toneForStatus("PENDING")}>PENDING</VerificationBadge> means the
          Durable Object still holds the request. The list is reconciled against it on every load.
        </p>
      </CardContent>
    </Card>
  );
}
