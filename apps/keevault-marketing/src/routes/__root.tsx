import { createRootRoute, HeadContent, Outlet, Scripts, Link } from "@tanstack/react-router";
import { RootProvider } from "fumadocs-ui/provider/tanstack";
import appCss from "@/styles/app.css?url";

export const Route = createRootRoute({
  head: () => ({
    meta: [
      { charSet: "utf-8" },
      { name: "viewport", content: "width=device-width, initial-scale=1" },
      { title: "KeeVault | Every boot needs your approval." },
      {
        name: "description",
        content:
          "A secret vault for container and VPS deployments. Encrypt secrets at rest and require human approval before each workload boot receives them.",
      },
      { name: "theme-color", content: "#071015" },
    ],
    links: [
      { rel: "stylesheet", href: appCss },
      { rel: "icon", href: "/favicon.svg", type: "image/svg+xml" },
    ],
  }),
  component: Root,
  notFoundComponent: () => (
    <main className="mx-auto flex min-h-screen max-w-xl flex-col justify-center gap-5 px-6">
      <h1 className="text-4xl font-semibold">Page not found</h1>
      <p>The page may have moved. Browse the docs or return to KeeVault.</p>
      <Link to="/">Back to KeeVault</Link>
    </main>
  ),
});

function Root() {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <HeadContent />
      </head>
      <body>
        <RootProvider theme={{ forcedTheme: "dark" }}>
          <Outlet />
        </RootProvider>
        <Scripts />
      </body>
    </html>
  );
}
