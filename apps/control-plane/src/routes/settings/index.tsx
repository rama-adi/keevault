import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
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
import { useVaultAction } from "@/components/vault/use-vault-action";
import { VaultDialog } from "@/components/vault/vault-dialog";
import { VaultPageHeader } from "@/components/vault/vault-page-header";
import { formatDate } from "@/lib/format";
import { ROLES, type Role } from "@/lib/roles";
import { loadOrRedirect } from "@/lib/route-guards";
import {
  loadSettingsFn,
  setAdministratorRoleFn,
  type AdministratorView,
  type SettingsView,
} from "@/server/functions/settings";
import { isOwner } from "@/server/functions/session";

export const Route = createFileRoute("/settings/")({
  loader: async (): Promise<SettingsView> =>
    await loadOrRedirect(async () => await loadSettingsFn()),
  component: SettingsPage,
});

function SettingsPage() {
  const settings = Route.useLoaderData();
  const [editing, setEditing] = useState<AdministratorView | null>(null);
  const owner = isOwner(settings.viewerRole);

  return (
    <div className="flex flex-col gap-6">
      <VaultPageHeader
        title="Settings"
        description="Who can operate this vault, and which master key versions the Worker can read."
        role={settings.viewerRole}
      />

      <Card className="p-0">
        <CardHeader className="p-6 pb-0">
          <CardTitle className="text-base">Administrators</CardTitle>
          <CardDescription>
            Viewers read metadata. Admins edit secrets, tokens and provenance, and approve boots.
            Owners additionally rotate keys and change roles.
          </CardDescription>
        </CardHeader>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Email</TableHead>
              <TableHead>Role</TableHead>
              <TableHead className="text-right">Joined</TableHead>
              {owner ? <TableHead className="w-32" /> : null}
            </TableRow>
          </TableHeader>
          <TableBody>
            {settings.administrators.map((administrator) => (
              <TableRow key={administrator.id}>
                <TableCell className="font-medium">{administrator.name}</TableCell>
                <TableCell className="text-muted-foreground text-xs">
                  {administrator.email}
                </TableCell>
                <TableCell>
                  <Badge variant={administrator.role === "owner" ? "default" : "secondary"}>
                    {administrator.role}
                  </Badge>
                </TableCell>
                <TableCell className="text-muted-foreground text-right text-xs">
                  {formatDate(administrator.createdAt)}
                </TableCell>
                {owner ? (
                  <TableCell className="text-right">
                    <Button
                      size="sm"
                      variant="ghost"
                      disabled={administrator.id === settings.viewerId}
                      onClick={() => {
                        setEditing(administrator);
                      }}
                    >
                      Change role
                    </Button>
                  </TableCell>
                ) : null}
              </TableRow>
            ))}
          </TableBody>
        </Table>
        <CardContent className="p-6 pt-0">
          <Alert>
            <AlertTitle>Inviting a new operator is not available in V1</AlertTitle>
            <AlertDescription>
              Sign-in is passkey only, and Better Auth 1.7.2 can register a passkey only for an
              already authenticated session. An invited account would have no way to reach its first
              credential, so the vault would hold a user row nobody can use. Add operators through
              the first-owner setup ceremony, and change their role here.
            </AlertDescription>
          </Alert>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Master key versions</CardTitle>
          <CardDescription>
            Read from the Worker secrets on every request. Rotating the master key means adding a
            new secret, rewrapping project keys, and only then moving the active version.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-2">
          {settings.masterKeyVersions.map((version) => (
            <Badge
              key={version}
              variant={version === settings.activeMasterKeyVersion ? "default" : "outline"}
            >
              VAULT_MASTER_KEY_V{version}
              {version === settings.activeMasterKeyVersion ? " (active)" : ""}
            </Badge>
          ))}
        </CardContent>
      </Card>

      <ChangeRoleDialog
        administrator={editing}
        onOpenChange={(open) => {
          if (!open) setEditing(null);
        }}
      />
    </div>
  );
}

interface ChangeRoleDialogProps {
  administrator: AdministratorView | null;
  onOpenChange: (open: boolean) => void;
}

function ChangeRoleDialog({ administrator, onOpenChange }: ChangeRoleDialogProps) {
  const action = useVaultAction();
  const [role, setRole] = useState<Role | null>(null);
  const selected = role ?? administrator?.role ?? "viewer";

  return (
    <>
      <VaultDialog
        open={administrator !== null}
        onOpenChange={(open) => {
          if (!open) {
            setRole(null);
            onOpenChange(false);
          }
        }}
        title={`Change role for ${administrator?.name ?? ""}`}
        description="Changing a role asks for a passkey verification from the last five minutes."
        submitLabel="Save role"
        pendingLabel="Saving"
        pending={action.pending}
        error={action.error}
        onSubmit={() => {
          if (administrator === null) return;
          void action
            .run(async () => {
              await setAdministratorRoleFn({
                data: { userId: administrator.id, role: selected },
              });
            })
            .then((done) => {
              if (done) {
                setRole(null);
                onOpenChange(false);
              }
            });
        }}
      >
        <div className="flex gap-2">
          {ROLES.map((option) => (
            <Button
              key={option}
              type="button"
              size="sm"
              variant={option === selected ? "default" : "outline"}
              onClick={() => {
                setRole(option);
              }}
            >
              {option}
            </Button>
          ))}
        </div>
      </VaultDialog>
      {action.stepUpDialog}
    </>
  );
}
