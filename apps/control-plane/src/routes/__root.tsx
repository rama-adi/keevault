/// <reference types="vite/client" />
import {
  createRootRoute,
  HeadContent,
  Link,
  Scripts,
  useRouterState,
} from "@tanstack/react-router";
import type { ReactNode } from "react";

import { Activity, FolderKey, KeyRound, ScrollText, Settings } from "lucide-react";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarInset,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  SidebarTrigger,
  useSidebar,
} from "@/components/ui/sidebar";
import { Separator } from "@/components/ui/separator";
import appCss from "@/styles/app.css?url";

export const Route = createRootRoute({
  head: () => ({
    meta: [
      { charSet: "utf-8" },
      { name: "viewport", content: "width=device-width, initial-scale=1" },
      { name: "robots", content: "noindex, nofollow" },
      { title: "keevault" },
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
        <AppLayout>{children}</AppLayout>
        <Scripts />
      </body>
    </html>
  );
}

const destinations = [
  { to: "/projects", label: "Projects", icon: FolderKey },
  { to: "/boots", label: "Boot requests", icon: Activity },
  { to: "/audit", label: "Activity log", icon: ScrollText },
  { to: "/settings", label: "Settings", icon: Settings },
] as const;

function AppLayout({ children }: { children: ReactNode }) {
  const pathname = useRouterState({ select: (state) => state.location.pathname });
  if (pathname === "/login" || pathname === "/setup") {
    return (
      <main className="mx-auto flex min-h-svh w-full max-w-lg flex-col justify-center gap-6 px-6 py-12">
        <span className="text-lg font-semibold tracking-tight">keevault</span>
        {children}
      </main>
    );
  }
  const current = destinations.find((item) => pathname.startsWith(item.to));
  return (
    <SidebarProvider>
      <AppNav pathname={pathname} />
      <SidebarInset>
        <header className="flex h-16 shrink-0 items-center gap-3 border-b px-4 md:px-8">
          <SidebarTrigger />
          <Separator orientation="vertical" className="h-4" />
          <span className="text-sm text-muted-foreground">Workspace</span>
          <span className="text-muted-foreground/50">/</span>
          <span className="text-sm font-medium">{current?.label ?? "keevault"}</span>
        </header>
        <main
          id="main-content"
          className="mx-auto w-full max-w-7xl min-w-0 flex-1 px-4 py-8 md:px-8 lg:px-12 lg:py-10"
        >
          {children}
        </main>
      </SidebarInset>
    </SidebarProvider>
  );
}

function AppNav({ pathname }: { pathname: string }) {
  const { setOpenMobile } = useSidebar();
  return (
    <Sidebar>
      <SidebarHeader className="px-5 py-6">
        <Link
          to="/projects"
          className="flex items-center gap-3"
          onClick={() => setOpenMobile(false)}
        >
          <span className="flex size-9 items-center justify-center rounded-lg bg-primary text-primary-foreground">
            <KeyRound className="size-5" />
          </span>
          <span className="text-lg font-semibold tracking-tight">keevault</span>
        </Link>
      </SidebarHeader>
      <SidebarContent>
        <SidebarGroup className="px-3">
          <SidebarGroupLabel>Workspace</SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {destinations.map((item) => (
                <SidebarMenuItem key={item.to}>
                  <SidebarMenuButton asChild isActive={pathname.startsWith(item.to)}>
                    <Link to={item.to} onClick={() => setOpenMobile(false)}>
                      <item.icon />
                      <span>{item.label}</span>
                    </Link>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              ))}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>
      <SidebarFooter className="px-5 py-5">
        <span className="text-xs text-muted-foreground">keevault / control plane</span>
      </SidebarFooter>
    </Sidebar>
  );
}
