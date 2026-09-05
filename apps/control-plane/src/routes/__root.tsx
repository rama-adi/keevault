/// <reference types="vite/client" />
import { createRootRoute, HeadContent, Link, Scripts } from "@tanstack/react-router";
import type { ReactNode } from "react";

import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import appCss from "@/styles/app.css?url";

export const Route = createRootRoute({
  head: () => ({
    meta: [
      { charSet: "utf-8" },
      { name: "viewport", content: "width=device-width, initial-scale=1" },
      { name: "robots", content: "noindex, nofollow" },
      { title: "env-vault" },
    ],
    links: [{ rel: "stylesheet", href: appCss }],
  }),
  shellComponent: RootDocument,
});

function RootDocument({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <head>
        <HeadContent />
      </head>
      <body className="bg-background text-foreground min-h-svh antialiased">
        <div className="flex min-h-svh flex-col">
          <AppNav />
          <main className="mx-auto w-full max-w-5xl flex-1 px-6 py-10">{children}</main>
          <Separator />
          <footer className="text-muted-foreground mx-auto w-full max-w-5xl px-6 py-6 text-xs">
            env-vault control plane
          </footer>
        </div>
        <Scripts />
      </body>
    </html>
  );
}

/**
 * Top navigation. The shadcn `sidebar` primitive is installed and available for
 * the project workspace pages, but the shell itself has too few destinations to
 * earn one.
 */
function AppNav() {
  return (
    <header className="border-b">
      <nav className="mx-auto flex w-full max-w-5xl items-center gap-4 px-6 py-4">
        <Link to="/" className="text-sm font-semibold tracking-tight">
          env-vault
        </Link>
        <div className="flex-1" />
        <Button asChild variant="ghost" size="sm">
          <Link to="/projects">Projects</Link>
        </Button>
      </nav>
    </header>
  );
}
