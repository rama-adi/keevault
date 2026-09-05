import { createFileRoute, Link, useRouter } from "@tanstack/react-router";
import { Plus, Upload } from "lucide-react";
import { useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
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
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { CopyOnce } from "@/components/vault/copy-once";
import { MaskedSecret } from "@/components/vault/masked-secret";
import { useVaultAction } from "@/components/vault/use-vault-action";
import { VaultDialog } from "@/components/vault/vault-dialog";
import { VaultPageHeader } from "@/components/vault/vault-page-header";
import { formatDate, parseCidrList } from "@/lib/format";
import { loadOrRedirect } from "@/lib/route-guards";
import {
  deleteEnvironmentFn,
  getEnvironmentFn,
  rotateEnvironmentKeyFn,
  setEnvironmentPolicyFn,
} from "@/server/functions/projects";
import {
  deleteSecretFn,
  importDotenvFn,
  listSecretsFn,
  putSecretFn,
} from "@/server/functions/secrets";
import { canEdit, getViewerFn, isOwner, type Viewer } from "@/server/functions/session";
import {
  addTrustedSignerFn,
  createBootstrapTokenFn,
  listBootstrapTokensFn,
  listTrustedSignersFn,
  revokeBootstrapTokenFn,
  revokeTrustedSignerFn,
  updateTokenCidrsFn,
} from "@/server/functions/tokens";
import type {
  BootstrapTokenSummary,
  EnvironmentSummary,
  SecretSummary,
  TrustedSignerSummary,
} from "@/server/vault/service";

interface EnvironmentData {
  viewer: Viewer;
  environment: EnvironmentSummary;
  secrets: SecretSummary[];
  tokens: BootstrapTokenSummary[];
  signers: TrustedSignerSummary[];
}

export const Route = createFileRoute("/projects/$projectId/environments/$environmentId/")({
  loader: async ({ params }): Promise<EnvironmentData> =>
    await loadOrRedirect(async () => {
      const viewer = await getViewerFn();
      const environment = await getEnvironmentFn({
        data: { environmentId: params.environmentId },
      });
      if (environment === null) throw new Error("That environment does not exist.");
      return {
        viewer,
        environment,
        secrets: await listSecretsFn({ data: { environmentId: environment.id } }),
        tokens: await listBootstrapTokensFn({ data: { environmentId: environment.id } }),
        signers: await listTrustedSignersFn({ data: { environmentId: environment.id } }),
      };
    }),
  component: EnvironmentPage,
});

function EnvironmentPage() {
  const { viewer, environment, secrets, tokens, signers } = Route.useLoaderData();
  const { projectId } = Route.useParams();

  return (
    <div className="flex flex-col gap-8">
      <VaultPageHeader
        title={environment.name}
        description={`Environment key version ${environment.environmentKeyVersion}. Provenance ${environment.provenanceMode}.`}
        role={viewer.role}
        actions={
          <Button asChild variant="ghost" size="sm">
            <Link to="/projects/$projectId" params={{ projectId }}>
              Back to project
            </Link>
          </Button>
        }
      />
      <Tabs defaultValue="secrets">
        <TabsList>
          <TabsTrigger value="secrets">Secrets</TabsTrigger>
          <TabsTrigger value="tokens">Tokens</TabsTrigger>
          <TabsTrigger value="policy">Policy</TabsTrigger>
        </TabsList>
        <TabsContent value="secrets" className="pt-6">
          <SecretsTab environment={environment} secrets={secrets} viewer={viewer} />
        </TabsContent>
        <TabsContent value="tokens" className="pt-6">
          <TokensTab environment={environment} tokens={tokens} viewer={viewer} />
        </TabsContent>
        <TabsContent value="policy" className="pt-6">
          <PolicyTab environment={environment} signers={signers} viewer={viewer} />
        </TabsContent>
      </Tabs>
    </div>
  );
}

interface SecretsTabProps {
  environment: EnvironmentSummary;
  secrets: SecretSummary[];
  viewer: Viewer;
}

function SecretsTab({ environment, secrets, viewer }: SecretsTabProps) {
  const action = useVaultAction();
  const [editing, setEditing] = useState<SecretSummary | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [removing, setRemoving] = useState<SecretSummary | null>(null);
  const editable = canEdit(viewer.role);

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between gap-4">
        <p className="text-muted-foreground text-sm">
          Values are write-only. The dashboard has no way to read one back.
        </p>
        {editable ? (
          <div className="flex gap-2">
            <Button
              size="sm"
              variant="outline"
              onClick={() => {
                setImportOpen(true);
              }}
            >
              <Upload className="size-4" />
              Import .env
            </Button>
            <Button
              size="sm"
              onClick={() => {
                setCreateOpen(true);
              }}
            >
              <Plus className="size-4" />
              New secret
            </Button>
          </div>
        ) : null}
      </div>

      <Card className="p-0">
        {secrets.length === 0 ? (
          <CardContent className="text-muted-foreground p-6 text-sm">
            No secrets in this environment yet.
          </CardContent>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Value</TableHead>
                <TableHead className="text-right">Updated</TableHead>
                <TableHead className="text-right">Version</TableHead>
                {editable ? <TableHead className="w-40" /> : null}
              </TableRow>
            </TableHeader>
            <TableBody>
              {secrets.map((secret) => (
                <TableRow key={secret.id}>
                  <TableCell className="font-mono text-xs font-medium">{secret.name}</TableCell>
                  <TableCell>
                    <MaskedSecret />
                  </TableCell>
                  <TableCell className="text-muted-foreground text-right text-xs">
                    {formatDate(secret.updatedAt)}
                  </TableCell>
                  <TableCell className="text-right tabular-nums">{secret.secretVersion}</TableCell>
                  {editable ? (
                    <TableCell className="text-right">
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => {
                          setEditing(secret);
                        }}
                      >
                        Replace
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        className="text-destructive"
                        onClick={() => {
                          setRemoving(secret);
                        }}
                      >
                        Delete
                      </Button>
                    </TableCell>
                  ) : null}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </Card>

      <SecretDialog
        environmentId={environment.id}
        open={createOpen || editing !== null}
        existing={editing}
        onOpenChange={(open) => {
          if (!open) {
            setCreateOpen(false);
            setEditing(null);
          }
        }}
      />
      <ImportDotenvDialog
        environmentId={environment.id}
        open={importOpen}
        onOpenChange={setImportOpen}
      />
      <VaultDialog
        open={removing !== null}
        onOpenChange={(open) => {
          if (!open) setRemoving(null);
        }}
        title={`Delete ${removing?.name ?? ""}`}
        description="The encrypted value is removed. Any running workload keeps what it already has."
        submitLabel="Delete secret"
        pendingLabel="Deleting"
        destructive
        pending={action.pending}
        error={action.error}
        onSubmit={() => {
          const target = removing;
          if (target === null) return;
          void action
            .run(async () => {
              await deleteSecretFn({
                data: { environmentId: environment.id, name: target.name },
              });
            })
            .then((done) => {
              if (done) setRemoving(null);
            });
        }}
      />
      {action.stepUpDialog}
    </div>
  );
}

interface SecretDialogProps {
  environmentId: string;
  open: boolean;
  existing: SecretSummary | null;
  onOpenChange: (open: boolean) => void;
}

function SecretDialog({ environmentId, open, existing, onOpenChange }: SecretDialogProps) {
  const action = useVaultAction();
  const [name, setName] = useState("");
  const [value, setValue] = useState("");
  const replacing = existing !== null;

  function submit() {
    void action
      .run(async () => {
        await putSecretFn({
          data: { environmentId, name: replacing ? existing.name : name.trim(), value },
        });
      })
      .then((done) => {
        if (done) {
          setName("");
          setValue("");
          onOpenChange(false);
        }
      });
  }

  return (
    <>
      <VaultDialog
        open={open}
        onOpenChange={onOpenChange}
        title={replacing ? `Replace ${existing.name}` : "New secret"}
        description="The value is encrypted under this environment's key and never read back."
        submitLabel={replacing ? "Replace value" : "Create secret"}
        pendingLabel="Saving"
        pending={action.pending}
        error={action.error}
        onSubmit={submit}
      >
        <FieldGroup>
          {replacing ? null : (
            <Field>
              <FieldLabel htmlFor="secret-name">Name</FieldLabel>
              <Input
                id="secret-name"
                value={name}
                autoComplete="off"
                spellCheck={false}
                onChange={(event) => {
                  setName(event.target.value.toUpperCase());
                }}
              />
              <FieldDescription>Upper case letters, digits and underscore.</FieldDescription>
            </Field>
          )}
          <Field>
            <FieldLabel htmlFor="secret-value">Value</FieldLabel>
            <Textarea
              id="secret-value"
              value={value}
              rows={4}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => {
                setValue(event.target.value);
              }}
            />
          </Field>
        </FieldGroup>
      </VaultDialog>
      {action.stepUpDialog}
    </>
  );
}

interface ImportDotenvDialogProps {
  environmentId: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

function ImportDotenvDialog({ environmentId, open, onOpenChange }: ImportDotenvDialogProps) {
  const action = useVaultAction();
  const [content, setContent] = useState("");
  const [summary, setSummary] = useState<string | null>(null);

  function submit() {
    void action
      .run(async () => {
        const result = await importDotenvFn({ data: { environmentId, content } });
        setSummary(`Imported ${result.created} new and replaced ${result.replaced}.`);
      })
      .then((done) => {
        if (done) setContent("");
      });
  }

  return (
    <>
      <VaultDialog
        open={open}
        onOpenChange={(next) => {
          if (!next) setSummary(null);
          onOpenChange(next);
        }}
        title="Import .env"
        description="Every line is parsed, encrypted and stored. Nothing is echoed back."
        submitLabel="Import"
        pendingLabel="Importing"
        pending={action.pending}
        error={action.error}
        onSubmit={submit}
      >
        <Field>
          <FieldLabel htmlFor="dotenv-file">File</FieldLabel>
          <Input
            id="dotenv-file"
            type="file"
            accept=".env,text/plain"
            onChange={(event) => {
              const file = event.target.files?.[0];
              if (file === undefined) return;
              void file.text().then(setContent);
            }}
          />
          <FieldDescription>Or paste the contents below.</FieldDescription>
        </Field>
        <Field>
          <FieldLabel htmlFor="dotenv-content">Contents</FieldLabel>
          <Textarea
            id="dotenv-content"
            rows={10}
            value={content}
            spellCheck={false}
            className="font-mono text-xs"
            onChange={(event) => {
              setContent(event.target.value);
            }}
          />
        </Field>
        {summary === null ? null : <p className="text-sm">{summary}</p>}
      </VaultDialog>
      {action.stepUpDialog}
    </>
  );
}

interface TokensTabProps {
  environment: EnvironmentSummary;
  tokens: BootstrapTokenSummary[];
  viewer: Viewer;
}

function TokensTab({ environment, tokens, viewer }: TokensTabProps) {
  const action = useVaultAction();
  const [createOpen, setCreateOpen] = useState(false);
  const [editing, setEditing] = useState<BootstrapTokenSummary | null>(null);
  const [revoking, setRevoking] = useState<BootstrapTokenSummary | null>(null);
  const editable = canEdit(viewer.role);

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between gap-4">
        <p className="text-muted-foreground text-sm">
          A token belongs to this environment only. The client cannot pick another one.
        </p>
        {editable ? (
          <Button
            size="sm"
            onClick={() => {
              setCreateOpen(true);
            }}
          >
            <Plus className="size-4" />
            New token
          </Button>
        ) : null}
      </div>

      <Card className="p-0">
        {tokens.length === 0 ? (
          <CardContent className="text-muted-foreground p-6 text-sm">
            No bootstrap tokens yet.
          </CardContent>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Label</TableHead>
                <TableHead>Allowed CIDRs</TableHead>
                <TableHead>Expires</TableHead>
                <TableHead>Last seen</TableHead>
                <TableHead>Status</TableHead>
                {editable ? <TableHead className="w-40" /> : null}
              </TableRow>
            </TableHeader>
            <TableBody>
              {tokens.map((token) => (
                <TableRow key={token.id}>
                  <TableCell className="font-medium">{token.label}</TableCell>
                  <TableCell className="font-mono text-xs">
                    {token.allowedCidrs.length === 0
                      ? "any address"
                      : token.allowedCidrs.join(", ")}
                  </TableCell>
                  <TableCell className="text-muted-foreground text-xs">
                    {formatDate(token.expiresAt)}
                  </TableCell>
                  <TableCell className="text-muted-foreground text-xs">
                    {formatDate(token.lastSeenAt)}
                  </TableCell>
                  <TableCell>
                    <Badge variant={token.revokedAt === null ? "secondary" : "outline"}>
                      {token.revokedAt === null ? "active" : "revoked"}
                    </Badge>
                  </TableCell>
                  {editable ? (
                    <TableCell className="text-right">
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => {
                          setEditing(token);
                        }}
                      >
                        CIDRs
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        className="text-destructive"
                        disabled={token.revokedAt !== null}
                        onClick={() => {
                          setRevoking(token);
                        }}
                      >
                        Revoke
                      </Button>
                    </TableCell>
                  ) : null}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </Card>

      <CreateTokenDialog
        environmentId={environment.id}
        open={createOpen}
        onOpenChange={setCreateOpen}
      />
      <EditCidrsDialog
        token={editing}
        onOpenChange={(open) => {
          if (!open) setEditing(null);
        }}
      />
      <VaultDialog
        open={revoking !== null}
        onOpenChange={(open) => {
          if (!open) setRevoking(null);
        }}
        title={`Revoke ${revoking?.label ?? ""}`}
        description="New sockets and reconnects stop immediately. Pending and approved boots from this token are cancelled."
        submitLabel="Revoke token"
        pendingLabel="Revoking"
        destructive
        pending={action.pending}
        error={action.error}
        onSubmit={() => {
          const target = revoking;
          if (target === null) return;
          void action
            .run(async () => {
              await revokeBootstrapTokenFn({ data: { tokenId: target.id } });
            })
            .then((done) => {
              if (done) setRevoking(null);
            });
        }}
      />
      {action.stepUpDialog}
    </div>
  );
}

interface CreateTokenDialogProps {
  environmentId: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

function CreateTokenDialog({ environmentId, open, onOpenChange }: CreateTokenDialogProps) {
  const action = useVaultAction();
  const [label, setLabel] = useState("");
  const [cidrs, setCidrs] = useState("");
  const [expiresAt, setExpiresAt] = useState("");
  const [issued, setIssued] = useState<string | null>(null);

  function submit() {
    void action.run(async () => {
      const created = await createBootstrapTokenFn({
        data: {
          environmentId,
          label: label.trim(),
          allowedCidrs: parseCidrList(cidrs),
          expiresAt: expiresAt === "" ? null : new Date(expiresAt).toISOString(),
          maxPendingBoots: 3,
        },
      });
      setIssued(created.token);
    });
  }

  function close() {
    setIssued(null);
    setLabel("");
    setCidrs("");
    setExpiresAt("");
    onOpenChange(false);
  }

  if (issued !== null) {
    return (
      <VaultDialog
        open={open}
        onOpenChange={(next) => {
          if (!next) close();
        }}
        title="Copy this token now"
        submitLabel="Done"
        onSubmit={close}
      >
        <CopyOnce
          title="This is the only time the token is shown"
          description="It is not stored anywhere. If you lose it, revoke the token and create another."
          value={issued}
        />
      </VaultDialog>
    );
  }

  return (
    <>
      <VaultDialog
        open={open}
        onOpenChange={(next) => {
          if (!next) close();
        }}
        title="New bootstrap token"
        description="Creating a token asks for a passkey verification from the last five minutes."
        submitLabel="Create token"
        pendingLabel="Creating"
        pending={action.pending}
        error={action.error}
        onSubmit={submit}
      >
        <FieldGroup>
          <Field>
            <FieldLabel htmlFor="token-label">Label</FieldLabel>
            <Input
              id="token-label"
              value={label}
              autoComplete="off"
              onChange={(event) => {
                setLabel(event.target.value);
              }}
            />
          </Field>
          <Field>
            <FieldLabel htmlFor="token-cidrs">Allowed CIDRs</FieldLabel>
            <Textarea
              id="token-cidrs"
              rows={3}
              value={cidrs}
              spellCheck={false}
              className="font-mono text-xs"
              onChange={(event) => {
                setCidrs(event.target.value);
              }}
            />
            <FieldDescription>
              One per line, IPv4 or IPv6. Leave empty to skip the address check.
            </FieldDescription>
          </Field>
          <Field>
            <FieldLabel htmlFor="token-expiry">Expires</FieldLabel>
            <Input
              id="token-expiry"
              type="datetime-local"
              value={expiresAt}
              onChange={(event) => {
                setExpiresAt(event.target.value);
              }}
            />
            <FieldDescription>Optional.</FieldDescription>
          </Field>
        </FieldGroup>
      </VaultDialog>
      {action.stepUpDialog}
    </>
  );
}

interface EditCidrsDialogProps {
  token: BootstrapTokenSummary | null;
  onOpenChange: (open: boolean) => void;
}

function EditCidrsDialog({ token, onOpenChange }: EditCidrsDialogProps) {
  const action = useVaultAction();
  const [draft, setDraft] = useState<string | null>(null);
  const value = draft ?? (token === null ? "" : token.allowedCidrs.join("\n"));

  return (
    <>
      <VaultDialog
        open={token !== null}
        onOpenChange={(open) => {
          if (!open) {
            setDraft(null);
            onOpenChange(false);
          }
        }}
        title="Allowed CIDRs"
        description="Checked against CF-Connecting-IP on the WebSocket upgrade."
        submitLabel="Save"
        pendingLabel="Saving"
        pending={action.pending}
        error={action.error}
        onSubmit={() => {
          if (token === null) return;
          void action
            .run(async () => {
              await updateTokenCidrsFn({
                data: { tokenId: token.id, allowedCidrs: parseCidrList(value) },
              });
            })
            .then((done) => {
              if (done) {
                setDraft(null);
                onOpenChange(false);
              }
            });
        }}
      >
        <Field>
          <FieldLabel htmlFor="edit-cidrs">One per line</FieldLabel>
          <Textarea
            id="edit-cidrs"
            rows={4}
            value={value}
            spellCheck={false}
            className="font-mono text-xs"
            onChange={(event) => {
              setDraft(event.target.value);
            }}
          />
        </Field>
      </VaultDialog>
      {action.stepUpDialog}
    </>
  );
}

interface PolicyTabProps {
  environment: EnvironmentSummary;
  signers: TrustedSignerSummary[];
  viewer: Viewer;
}

const PROVENANCE_MODES = ["OFF", "ADVISORY", "REQUIRED"] as const;

function PolicyTab({ environment, signers, viewer }: PolicyTabProps) {
  const router = useRouter();
  const action = useVaultAction();
  const [mode, setMode] = useState<string>(environment.provenanceMode);
  const [pendingTtl, setPendingTtl] = useState(String(environment.pendingTtlSeconds));
  const [approvedTtl, setApprovedTtl] = useState(String(environment.approvedTtlSeconds));
  const [signerOpen, setSignerOpen] = useState(false);
  const [rotateOpen, setRotateOpen] = useState(false);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [confirmation, setConfirmation] = useState("");
  const editable = canEdit(viewer.role);

  function saveMode(next: string) {
    setMode(next);
    void action.run(async () => {
      await setEnvironmentPolicyFn({
        data: {
          environmentId: environment.id,
          provenanceMode: readMode(next),
          pendingTtlSeconds: Number(pendingTtl),
          approvedTtlSeconds: Number(approvedTtl),
        },
      });
    });
  }

  return (
    <div className="flex flex-col gap-6">
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Provenance</CardTitle>
          <CardDescription>
            OFF records nothing. ADVISORY records the verdict and still allows the boot. REQUIRED
            refuses a boot that is not verified.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-6">
          <ToggleGroup
            type="single"
            value={mode}
            disabled={!editable}
            onValueChange={(next) => {
              if (next !== "") saveMode(next);
            }}
          >
            {PROVENANCE_MODES.map((option) => (
              <ToggleGroupItem key={option} value={option}>
                {option}
              </ToggleGroupItem>
            ))}
          </ToggleGroup>
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor="pending-ttl">Pending TTL (seconds)</FieldLabel>
              <Input
                id="pending-ttl"
                value={pendingTtl}
                inputMode="numeric"
                disabled={!editable}
                onChange={(event) => {
                  setPendingTtl(event.target.value);
                }}
              />
              <FieldDescription>How long a boot may wait for an approval.</FieldDescription>
            </Field>
            <Field>
              <FieldLabel htmlFor="approved-ttl">Approved TTL (seconds)</FieldLabel>
              <Input
                id="approved-ttl"
                value={approvedTtl}
                inputMode="numeric"
                disabled={!editable}
                onChange={(event) => {
                  setApprovedTtl(event.target.value);
                }}
              />
              <FieldDescription>How long the approved payload stays deliverable.</FieldDescription>
            </Field>
          </FieldGroup>
          {action.error === null ? null : (
            <p className="text-destructive text-sm">{action.error}</p>
          )}
          {editable ? (
            <Button
              size="sm"
              className="w-fit"
              disabled={action.pending}
              onClick={() => {
                saveMode(mode);
              }}
            >
              {action.pending ? "Saving" : "Save policy"}
            </Button>
          ) : null}
        </CardContent>
      </Card>

      <Card className="p-0">
        <CardHeader className="p-6 pb-0">
          <CardTitle className="text-base">Trusted signers</CardTitle>
          <CardDescription>
            Ed25519 keys whose signed build manifests this environment accepts.
          </CardDescription>
        </CardHeader>
        {signers.length === 0 ? (
          <CardContent className="text-muted-foreground p-6 text-sm">
            No trusted signers yet.
          </CardContent>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Label</TableHead>
                <TableHead>Fingerprint</TableHead>
                <TableHead>Scope</TableHead>
                <TableHead>Status</TableHead>
                {editable ? <TableHead className="w-24" /> : null}
              </TableRow>
            </TableHeader>
            <TableBody>
              {signers.map((signer) => (
                <TableRow key={signer.id}>
                  <TableCell className="font-medium">{signer.label}</TableCell>
                  <TableCell className="font-mono text-xs break-all">
                    {signer.fingerprint.slice(0, 32)}
                  </TableCell>
                  <TableCell className="text-xs">
                    {signer.environmentId === null ? "project" : "environment"}
                  </TableCell>
                  <TableCell>
                    <Badge variant={signer.enabled ? "secondary" : "outline"}>
                      {signer.enabled ? "enabled" : "revoked"}
                    </Badge>
                  </TableCell>
                  {editable ? (
                    <TableCell className="text-right">
                      <Button
                        size="sm"
                        variant="ghost"
                        className="text-destructive"
                        disabled={!signer.enabled}
                        onClick={() => {
                          void action.run(async () => {
                            await revokeTrustedSignerFn({
                              data: { environmentId: environment.id, signerId: signer.id },
                            });
                          });
                        }}
                      >
                        Revoke
                      </Button>
                    </TableCell>
                  ) : null}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
        {editable ? (
          <CardContent className="p-6 pt-0">
            <Button
              size="sm"
              variant="outline"
              onClick={() => {
                setSignerOpen(true);
              }}
            >
              <Plus className="size-4" />
              Add signer
            </Button>
          </CardContent>
        ) : null}
      </Card>

      {editable ? (
        <Card className="border-destructive/40">
          <CardHeader>
            <CardTitle className="text-base">Danger zone</CardTitle>
            <CardDescription>
              Both operations ask for a passkey verification from the last five minutes.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            <div className="flex items-center justify-between gap-4">
              <div className="text-sm">
                <p className="font-medium">Rotate the environment key</p>
                <p className="text-muted-foreground">
                  Every secret is decrypted and re-encrypted under a new key. Owner only.
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
            <div className="flex items-center justify-between gap-4">
              <div className="text-sm">
                <p className="font-medium">Delete this environment</p>
                <p className="text-muted-foreground">
                  Removes its key, secrets and bootstrap tokens. This cannot be undone.
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
      ) : null}

      <AddSignerDialog
        environmentId={environment.id}
        open={signerOpen}
        onOpenChange={setSignerOpen}
      />

      <VaultDialog
        open={rotateOpen}
        onOpenChange={setRotateOpen}
        title="Rotate the environment key"
        description="Every secret is re-encrypted under the new key in one batch."
        submitLabel="Rotate key"
        pendingLabel="Rotating"
        pending={action.pending}
        error={action.error}
        onSubmit={() => {
          void action
            .run(async () => {
              await rotateEnvironmentKeyFn({ data: { environmentId: environment.id } });
            })
            .then((done) => {
              if (done) setRotateOpen(false);
            });
        }}
      >
        <p className="text-muted-foreground text-sm">
          Current version {environment.environmentKeyVersion}. Workloads that already booted keep
          the key they hold; rotate the token as well if you need to cut them off.
        </p>
      </VaultDialog>

      <VaultDialog
        open={deleteOpen}
        onOpenChange={setDeleteOpen}
        title={`Delete ${environment.name}`}
        description="Type the environment slug to confirm."
        submitLabel="Delete environment"
        pendingLabel="Deleting"
        destructive
        pending={action.pending || confirmation !== environment.slug}
        error={action.error}
        onSubmit={() => {
          if (confirmation !== environment.slug) return;
          void action
            .run(async () => {
              await deleteEnvironmentFn({ data: { environmentId: environment.id } });
            })
            .then((done) => {
              if (done) {
                setDeleteOpen(false);
                void router.navigate({
                  to: "/projects/$projectId",
                  params: { projectId: environment.projectId },
                });
              }
            });
        }}
      >
        <Field>
          <FieldLabel htmlFor="confirm-environment">Environment slug</FieldLabel>
          <Input
            id="confirm-environment"
            value={confirmation}
            autoComplete="off"
            onChange={(event) => {
              setConfirmation(event.target.value);
            }}
          />
        </Field>
      </VaultDialog>
      {action.stepUpDialog}
    </div>
  );
}

/** Narrow the toggle group's string back to the policy union. */
function readMode(value: string): "OFF" | "ADVISORY" | "REQUIRED" {
  const found = PROVENANCE_MODES.find((option) => option === value);
  return found ?? "ADVISORY";
}

interface AddSignerDialogProps {
  environmentId: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

function AddSignerDialog({ environmentId, open, onOpenChange }: AddSignerDialogProps) {
  const action = useVaultAction();
  const [label, setLabel] = useState("");
  const [publicKey, setPublicKey] = useState("");
  const [projectWide, setProjectWide] = useState(false);

  return (
    <>
      <VaultDialog
        open={open}
        onOpenChange={onOpenChange}
        title="Add a trusted signer"
        description="The key is checked and fingerprinted before it is stored."
        submitLabel="Add signer"
        pendingLabel="Adding"
        pending={action.pending}
        error={action.error}
        onSubmit={() => {
          void action
            .run(async () => {
              await addTrustedSignerFn({
                data: {
                  environmentId,
                  label: label.trim(),
                  publicKey: publicKey.trim(),
                  projectWide,
                },
              });
            })
            .then((done) => {
              if (done) {
                setLabel("");
                setPublicKey("");
                onOpenChange(false);
              }
            });
        }}
      >
        <FieldGroup>
          <Field>
            <FieldLabel htmlFor="signer-label">Label</FieldLabel>
            <Input
              id="signer-label"
              value={label}
              autoComplete="off"
              onChange={(event) => {
                setLabel(event.target.value);
              }}
            />
          </Field>
          <Field>
            <FieldLabel htmlFor="signer-key">Public key</FieldLabel>
            <Input
              id="signer-key"
              value={publicKey}
              autoComplete="off"
              spellCheck={false}
              className="font-mono text-xs"
              onChange={(event) => {
                setPublicKey(event.target.value);
              }}
            />
            <FieldDescription>
              32 bytes as base64url without padding, 43 characters.
            </FieldDescription>
          </Field>
          <Field orientation="horizontal">
            <Checkbox
              id="signer-scope"
              checked={projectWide}
              onCheckedChange={(next) => {
                setProjectWide(next === true);
              }}
            />
            <FieldLabel htmlFor="signer-scope">Trust across the whole project</FieldLabel>
          </Field>
        </FieldGroup>
      </VaultDialog>
      {action.stepUpDialog}
    </>
  );
}
