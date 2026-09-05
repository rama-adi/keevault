import { createFileRoute, useRouter } from "@tanstack/react-router";
import { useState } from "react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { authClient, SETUP_CLAIM_PATH } from "@/lib/auth-client";
import { assertSetupOpen } from "@/server/auth/setup";

/**
 * First-owner ceremony. Reachable only while the vault has no accounts; the
 * loader returns 404 once one exists. The setup token is checked server side in
 * constant time by the Better Auth endpoint this form posts to.
 */
export const Route = createFileRoute("/setup/")({
  loader: () => assertSetupOpen(),
  component: SetupPage,
});

type Stage = "form" | "passkey" | "done";

/** Read one text input's value without widening through FormData's File union. */
function fieldValue(form: HTMLFormElement, name: string): string {
  const element = form.elements.namedItem(name);
  return element instanceof HTMLInputElement ? element.value : "";
}

function SetupPage() {
  const router = useRouter();
  const [stage, setStage] = useState<Stage>("form");
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  async function claimOwner(form: HTMLFormElement) {
    setPending(true);
    setError(null);

    const claim = await authClient.$fetch(SETUP_CLAIM_PATH, {
      method: "POST",
      body: {
        setupToken: fieldValue(form, "setupToken"),
        name: fieldValue(form, "name"),
        email: fieldValue(form, "email"),
      },
    });
    if (claim.error) {
      setPending(false);
      setError("Setup is not available. Check the setup token, or the vault already has an owner.");
      return;
    }

    setStage("passkey");
    const registration = await authClient.passkey.addPasskey({
      name: "Owner passkey",
    });
    setPending(false);
    if (registration?.error) {
      setError(
        "The owner account was created but the passkey was not registered. Sign in is impossible until a passkey exists; recreate the vault database and run setup again.",
      );
      return;
    }
    setStage("done");
    await router.navigate({ to: "/projects" });
  }

  return (
    <div className="mx-auto flex max-w-lg flex-col gap-6">
      <Card>
        <CardHeader>
          <CardTitle>Create the first owner</CardTitle>
          <CardDescription>
            This page works once. Supply the VAULT_SETUP_TOKEN secret, then register the owner
            passkey. After that the page returns 404 and further administrators are added by the
            owner.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {error === null ? null : (
            <Alert variant="destructive" className="mb-6">
              <AlertTitle>Setup failed</AlertTitle>
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
          <form
            onSubmit={(event) => {
              event.preventDefault();
              void claimOwner(event.currentTarget);
            }}
          >
            <FieldGroup>
              <Field>
                <FieldLabel htmlFor="setup-name">Name</FieldLabel>
                <Input id="setup-name" name="name" required autoComplete="name" />
              </Field>
              <Field>
                <FieldLabel htmlFor="setup-email">Email</FieldLabel>
                <Input id="setup-email" name="email" type="email" required autoComplete="email" />
              </Field>
              <Field>
                <FieldLabel htmlFor="setup-token">Setup token</FieldLabel>
                <Input
                  id="setup-token"
                  name="setupToken"
                  type="password"
                  required
                  autoComplete="off"
                />
              </Field>
              <Field orientation="horizontal">
                <Button type="submit" disabled={pending || stage === "done"}>
                  {stage === "passkey"
                    ? "Registering passkey"
                    : "Create owner and register passkey"}
                </Button>
              </Field>
            </FieldGroup>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
