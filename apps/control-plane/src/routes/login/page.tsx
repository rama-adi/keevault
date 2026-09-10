import { createFileRoute, useRouter } from "@tanstack/react-router";
import { Fingerprint } from "lucide-react";
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
    <div className="mx-auto flex w-full max-w-sm flex-col gap-6 py-12 sm:py-20">
      <Card className="[--card-spacing:--spacing(6)]">
        <CardHeader className="gap-3">
          <Fingerprint className="text-primary mb-3 size-8" aria-hidden="true" />
          <CardTitle>Welcome back</CardTitle>
          <CardDescription>Sign in to your vault with a passkey.</CardDescription>
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
            {pending ? "Waiting for passkey…" : "Sign in with passkey"}
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
