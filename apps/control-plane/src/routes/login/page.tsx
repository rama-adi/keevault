import { createFileRoute, useRouter } from "@tanstack/react-router";
import { useState } from "react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { authClient } from "@/lib/auth-client";

export const Route = createFileRoute("/login/")({
  component: LoginPage,
});

function LoginPage() {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  async function signIn() {
    setPending(true);
    setError(null);
    const result = await authClient.signIn.passkey();
    setPending(false);
    if (result?.error) {
      setError(result.error.message ?? "Passkey sign-in failed.");
      return;
    }
    await router.navigate({ to: "/projects" });
  }

  return (
    <div className="mx-auto flex max-w-md flex-col gap-6">
      <Card>
        <CardHeader>
          <CardTitle>Sign in</CardTitle>
          <CardDescription>
            keevault accepts passkeys only. There is no password to fall back on.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          {error === null ? null : (
            <Alert variant="destructive">
              <AlertTitle>Sign-in failed</AlertTitle>
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
          <Button
            type="button"
            disabled={pending}
            onClick={() => {
              void signIn();
            }}
          >
            {pending ? "Waiting for your passkey" : "Continue with a passkey"}
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
