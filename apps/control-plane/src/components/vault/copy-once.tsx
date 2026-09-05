import { Check, Copy } from "lucide-react";
import { useState } from "react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

/**
 * A credential shown exactly once, copied from the shadcn `alert` primitive and
 * styled here rather than in `components/ui`.
 *
 * The value lives in React state for the life of the dialog and is never sent
 * back to the server or written anywhere else.
 */

export interface CopyOnceProps {
  title: string;
  description: string;
  value: string;
  className?: string;
}

export function CopyOnce({ title, description, value, className }: CopyOnceProps) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    await navigator.clipboard.writeText(value);
    setCopied(true);
  }

  return (
    <Alert className={cn("border-amber-500/40 bg-amber-500/5", className)}>
      <AlertTitle>{title}</AlertTitle>
      <AlertDescription className="flex flex-col gap-3">
        <span>{description}</span>
        <code className="bg-muted block w-full overflow-x-auto rounded-md p-3 font-mono text-xs break-all">
          {value}
        </code>
        <Button
          type="button"
          size="sm"
          variant="outline"
          className="w-fit"
          onClick={() => {
            void copy();
          }}
        >
          {copied ? <Check className="size-3.5" /> : <Copy className="size-3.5" />}
          {copied ? "Copied" : "Copy"}
        </Button>
      </AlertDescription>
    </Alert>
  );
}
