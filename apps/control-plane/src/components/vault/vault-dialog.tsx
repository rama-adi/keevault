import type { ReactNode } from "react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

/**
 * The dialog shape every vault form uses, copied from the shadcn `dialog`
 * primitive and styled here. It always renders a `DialogTitle`, so the dialog
 * is announced correctly, and it keeps the submit and cancel buttons in one
 * place so every form behaves the same while a request is in flight.
 */

export interface VaultDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description?: string;
  /** Disables the submit button and shows the pending label. */
  pending?: boolean;
  submitLabel: string;
  pendingLabel?: string;
  /** Renders the submit button in the destructive style. */
  destructive?: boolean;
  onSubmit: () => void;
  /** Shown above the footer, for a failed attempt. */
  error?: string | null;
  children?: ReactNode;
}

export function VaultDialog({
  open,
  onOpenChange,
  title,
  description,
  pending = false,
  submitLabel,
  pendingLabel,
  destructive = false,
  onSubmit,
  error,
  children,
}: VaultDialogProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <form
          onSubmit={(event) => {
            event.preventDefault();
            onSubmit();
          }}
        >
          <DialogHeader>
            <DialogTitle>{title}</DialogTitle>
            {description === undefined ? null : (
              <DialogDescription>{description}</DialogDescription>
            )}
          </DialogHeader>
          <div className="flex flex-col gap-4 py-4">{children}</div>
          {error === null || error === undefined ? null : (
            <p className="text-destructive pb-2 text-sm">{error}</p>
          )}
          <DialogFooter>
            <Button
              type="button"
              variant="ghost"
              onClick={() => {
                onOpenChange(false);
              }}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              disabled={pending}
              variant={destructive ? "destructive" : "default"}
            >
              {pending ? (pendingLabel ?? "Working") : submitLabel}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
