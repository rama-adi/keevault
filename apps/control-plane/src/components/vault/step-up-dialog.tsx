import { useState } from "react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { authClient } from "@/lib/auth-client";
import { stepUp } from "@/server/auth/step-up";

/**
 * Shown when a server call fails with `AuthorizationError` code
 * "step_up_required" (spec section 22). It runs a fresh passkey assertion in
 * the browser and then asks the server to confirm the new timestamp.
 */
export interface StepUpDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Called once the step-up succeeded, so the caller can retry its action. */
  onVerified: () => void;
}

export function StepUpDialog({ open, onOpenChange, onVerified }: StepUpDialogProps) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function verify() {
    setPending(true);
    setError(null);
    const assertion = await authClient.signIn.passkey();
    if (assertion?.error) {
      setPending(false);
      setError(assertion.error.message ?? "Passkey verification failed.");
      return;
    }
    await stepUp();
    setPending(false);
    onOpenChange(false);
    onVerified();
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Verify with your passkey</DialogTitle>
          <DialogDescription>Confirm your identity to continue.</DialogDescription>
        </DialogHeader>
        {error === null ? null : <p className="text-destructive text-sm">{error}</p>}
        <DialogFooter>
          <Button
            type="button"
            variant="outline"
            disabled={pending}
            onClick={() => onOpenChange(false)}
          >
            Cancel
          </Button>
          <Button
            type="button"
            disabled={pending}
            onClick={() => {
              void verify();
            }}
          >
            {pending ? "Waiting for passkey…" : "Verify"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
