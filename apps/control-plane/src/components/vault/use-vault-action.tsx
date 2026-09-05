import { useRouter } from "@tanstack/react-router";
import { useCallback, useRef, useState, type ReactNode } from "react";

import { StepUpDialog } from "@/components/vault/step-up-dialog";
import { decodeVaultError } from "@/lib/vault-errors";

/**
 * Runs one vault mutation and handles the two failures every mutation shares.
 *
 * A guard that asks for a fresh passkey verification comes back as the encoded
 * "step_up_required" error. The hook remembers the action, opens the existing
 * step-up dialog, and replays the action once the operator has verified, so the
 * caller writes the happy path only. "unauthenticated" sends the operator to
 * the sign-in page. Everything else is surfaced as `error`.
 */

export interface VaultActionHandle {
  pending: boolean;
  error: string | null;
  clearError: () => void;
  /** Run an action. Resolves to true when it completed. */
  run: (action: () => Promise<void>) => Promise<boolean>;
  /** Render this once inside the page. */
  stepUpDialog: ReactNode;
}

export function useVaultAction(): VaultActionHandle {
  const router = useRouter();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [stepUpOpen, setStepUpOpen] = useState(false);
  const pendingAction = useRef<(() => Promise<void>) | null>(null);

  const run = useCallback(
    async (action: () => Promise<void>): Promise<boolean> => {
      setPending(true);
      setError(null);
      try {
        await action();
        await router.invalidate();
        return true;
      } catch (caught) {
        const decoded = decodeVaultError(caught instanceof Error ? caught : new Error("failed"));
        if (decoded.kind === "step_up_required") {
          pendingAction.current = action;
          setStepUpOpen(true);
          return false;
        }
        if (decoded.kind === "unauthenticated") {
          await router.navigate({ to: "/login" });
          return false;
        }
        setError(decoded.message);
        return false;
      } finally {
        setPending(false);
      }
    },
    [router],
  );

  const stepUpDialog = (
    <StepUpDialog
      open={stepUpOpen}
      onOpenChange={setStepUpOpen}
      onVerified={() => {
        const action = pendingAction.current;
        pendingAction.current = null;
        if (action !== null) void run(action);
      }}
    />
  );

  return {
    pending,
    error,
    clearError: () => {
      setError(null);
    },
    run,
    stepUpDialog,
  };
}
