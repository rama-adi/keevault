import { formatFingerprint } from "@keevault/crypto";
import { createFileRoute, Link, useRouter } from "@tanstack/react-router";
import { ShieldAlert } from "lucide-react";
import { useState, type ReactNode } from "react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { useVaultAction } from "@/components/vault/use-vault-action";
import { VaultAlert, VaultAlertDescription, VaultAlertTitle } from "@/components/vault/vault-alert";
import { VerificationBadge, toneForStatus } from "@/components/vault/verification-badge";
import { relativeAge } from "@/lib/relative-age";
import { loadOrRedirect } from "@/lib/route-guards";
import {
  approveBootFn,
  cancelBootFn,
  declineBootFn,
  getBootFn,
  type BootDetail,
} from "@/server/functions/boots";
import { canEdit, getViewerFn, type Viewer } from "@/server/functions/session";
import type { VerificationResult } from "@/server/provenance/index";

interface BootPageData {
  viewer: Viewer;
  detail: BootDetail | null;
}

export const Route = createFileRoute("/boots/$bootId/")({
  loader: async ({ params }): Promise<BootPageData> =>
    await loadOrRedirect(async () => ({
      viewer: await getViewerFn(),
      detail: await getBootFn({ data: { bootId: params.bootId } }),
    })),
  component: BootApprovalPage,
});

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="flex flex-col gap-2">
      <h2 className="text-sm font-semibold">{title}</h2>
      <div className="flex flex-col gap-1">{children}</div>
    </section>
  );
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-1 items-baseline gap-1 text-sm sm:grid-cols-[11rem_1fr] sm:gap-3">
      <span className="text-muted-foreground">{label}</span>
      <span className="font-mono text-sm break-all">{children}</span>
    </div>
  );
}

function BootApprovalPage() {
  const { viewer, detail } = Route.useLoaderData();

  if (detail === null) {
    return (
      <Card>
        <CardContent className="text-muted-foreground text-sm">Boot request not found.</CardContent>
      </Card>
    );
  }
  return <ApprovalScreen viewer={viewer} detail={detail} />;
}

function ApprovalScreen({ viewer, detail }: { viewer: Viewer; detail: BootDetail }) {
  const router = useRouter();
  const action = useVaultAction();
  const [conflict, setConflict] = useState<string | null>(null);
  const summary = detail.summary;
  const decidable = summary.status === "PENDING" && canEdit(viewer.role);
  const blocked = !detail.evaluation.approvable;
  const failures = detail.results.filter((result) => result.status === "FAILED");

  async function decide(run: () => Promise<{ ok: boolean; message: string | null }>) {
    setConflict(null);
    await action.run(async () => {
      const outcome = await run();
      if (!outcome.ok) {
        setConflict(outcome.message ?? "That boot changed while you were reading it.");
        return;
      }
      await router.invalidate();
    });
  }

  return (
    <div className="flex flex-col gap-6">
      <Card>
        <CardHeader>
          <CardTitle>
            <h1>{summary.environmentName}</h1>
          </CardTitle>
          <CardDescription>{summary.projectName} · Boot review</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-6">
          {failures.length === 0 ? null : (
            <VaultAlert tone="danger">
              <ShieldAlert />
              <VaultAlertTitle>Signature verification failed</VaultAlertTitle>
              <VaultAlertDescription>
                The supplied evidence is invalid. Review the failed checks before approving.
              </VaultAlertDescription>
            </VaultAlert>
          )}

          <Section title="Boot request">
            <Row label="Token">{summary.tokenLabel}</Row>
            <Row label="Source IP">{summary.sourceIp ?? "unknown"}</Row>
            <Row label="CIDR policy">
              {detail.cidrPolicyConfigured
                ? detail.cidrPolicySatisfied
                  ? "satisfied"
                  : "not satisfied"
                : "no allow list configured"}
            </Row>
            <Row label="State">
              <VerificationBadge tone={toneForStatus(summary.status)}>
                {summary.status}
              </VerificationBadge>
            </Row>
          </Section>

          <Separator />

          <Section title="Verified evidence">
            {detail.results.length === 0 ? (
              <p className="text-muted-foreground text-sm">No verification results.</p>
            ) : (
              detail.results.map((result) => <ResultBlock key={result.verifier} result={result} />)
            )}
          </Section>

          <Separator />

          <Section title="Workload · unverified">
            <Row label="Repository">{summary.claimedGitRepository ?? "not claimed"}</Row>
            <Row label="Commit">{summary.claimedGitCommit ?? "not claimed"}</Row>
            <Row label="OCI">{summary.claimedOciRepository ?? "not claimed"}</Row>
            <Row label="Digest">{summary.claimedOciDigest ?? "not claimed"}</Row>
            <Row label="Provider">
              {detail.claimedProviderName ?? "not claimed"}
              {detail.claimedProviderDeploymentId === null
                ? ""
                : ` / ${detail.claimedProviderDeploymentId}`}
            </Row>
            <p className="text-muted-foreground pt-1 text-xs">
              Compare these claims with the verified evidence.
            </p>
          </Section>

          <details className="rounded-lg border p-4">
            <summary className="cursor-pointer text-sm font-medium">
              Client, keys and timing
            </summary>
            <div className="mt-5 grid gap-6 lg:grid-cols-2">
              <Section title="Client build · unverified">
                <Row label="Keevault version">
                  {detail.claimedClient?.version ?? "not reported"}
                </Row>
                <Row label="Operating system">{detail.claimedClient?.os ?? "not reported"}</Row>
                <Row label="Architecture">{detail.claimedClient?.arch ?? "not reported"}</Row>
                <Row label="Executable SHA-256">
                  {detail.claimedClient?.sha256 ?? "not reported"}
                </Row>
                <p className="text-muted-foreground pt-1 text-xs">
                  Client-reported values. The running binary is not attested.
                </p>
              </Section>
              <Section title="Boot identity">
                <Row label="Signing key">{formatFingerprint(summary.signingFingerprint)}</Row>
                <Row label="Encryption key">{formatFingerprint(summary.encryptionFingerprint)}</Row>
                <Row label="Boot id">{summary.bootId}</Row>
              </Section>
              <Section title="Runtime">
                <Row label="Running OCI identity">Not independently attested</Row>
              </Section>
              <Section title="Timing">
                <Row label="Requested">{relativeAge(summary.createdAt)}</Row>
                <Row label="Pending until">{summary.pendingExpiresAt ?? "-"}</Row>
                {detail.payloadExpiresAt === null ? null : (
                  <Row label="Payload expires">{detail.payloadExpiresAt}</Row>
                )}
              </Section>
            </div>
          </details>

          {blocked && summary.status === "PENDING" ? (
            <VaultAlert tone="warning">
              <VaultAlertTitle>Approval blocked</VaultAlertTitle>
              <VaultAlertDescription>
                <ul className="list-disc pl-5">
                  {detail.evaluation.blockers.map((blocker) => (
                    <li key={blocker}>{blocker}</li>
                  ))}
                </ul>
              </VaultAlertDescription>
            </VaultAlert>
          ) : null}

          {conflict === null ? null : (
            <VaultAlert tone="warning">
              <VaultAlertDescription>{conflict}</VaultAlertDescription>
            </VaultAlert>
          )}
          {action.error === null ? null : (
            <VaultAlert tone="danger">
              <VaultAlertDescription>{action.error}</VaultAlertDescription>
            </VaultAlert>
          )}

          <div className="flex flex-wrap items-center justify-between gap-4 pt-2">
            <Button asChild variant="ghost" size="sm">
              <Link to="/boots">Pending boots</Link>
            </Button>
            <div className="flex gap-3">
              <Button
                type="button"
                variant="outline"
                disabled={!decidable || action.pending}
                onClick={() => {
                  void decide(
                    async () =>
                      await declineBootFn({
                        data: { bootId: summary.bootId, reason: "declined on review" },
                      }),
                  );
                }}
              >
                Decline
              </Button>
              <Button
                type="button"
                disabled={!decidable || blocked || action.pending}
                onClick={() => {
                  void decide(
                    async () =>
                      await approveBootFn({
                        data: {
                          bootId: summary.bootId,
                          evidenceDigest: detail.evidenceDigest,
                        },
                      }),
                  );
                }}
              >
                Approve
              </Button>
            </div>
          </div>
          {summary.status === "PENDING" && canEdit(viewer.role) ? (
            <div className="flex justify-end">
              <Button
                type="button"
                variant="ghost"
                size="sm"
                disabled={action.pending}
                onClick={() => {
                  void decide(
                    async () =>
                      await cancelBootFn({
                        data: { bootId: summary.bootId, reason: "canceled on review" },
                      }),
                  );
                }}
              >
                Cancel boot
              </Button>
            </div>
          ) : null}
        </CardContent>
      </Card>
      {action.stepUpDialog}
    </div>
  );
}

function ResultBlock({ result }: { result: VerificationResult }) {
  return (
    <div className="border-border/60 flex flex-col gap-1 border-l-2 pt-2 pl-3 first:pt-0">
      <div className="flex items-center gap-2 text-sm">
        <span className="font-medium">{result.verifier}</span>
        <VerificationBadge tone={toneForStatus(result.status)}>{result.status}</VerificationBadge>
      </div>
      {result.facts.map((fact) => (
        <Row key={`${result.verifier}:${fact.key}`} label={fact.key}>
          {fact.value}
          {fact.matchesClaim === null ? null : (
            <span className={fact.matchesClaim ? "ml-2 text-emerald-600" : "text-destructive ml-2"}>
              {fact.matchesClaim ? "matches claim" : "does not match claim"}
            </span>
          )}
        </Row>
      ))}
      {result.warnings.map((warning) => (
        <p
          key={warning}
          className={
            result.status === "FAILED"
              ? "text-destructive text-xs font-semibold"
              : "text-muted-foreground text-xs"
          }
        >
          {warning}
        </p>
      ))}
    </div>
  );
}
