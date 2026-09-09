import { cloudflare } from "@cloudflare/vite-plugin";
import { tanstackStart } from "@tanstack/react-start/plugin/vite";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath } from "node:url";

import type { Plugin } from "vite-plus";
import { defineConfig } from "vite-plus";

/**
 * Keep the Workers built-in modules out of the bundle. The Worker runtime
 * provides them; Rolldown otherwise fails to resolve `cloudflare:workers`
 * during the SSR build because the TanStack Start plugin replaces the SSR
 * environment's rolldown options.
 */
function externalizeWorkersModules(): Plugin {
  return {
    name: "keevault:externalize-cloudflare-modules",
    enforce: "pre",
    resolveId(id: string) {
      return id.startsWith("cloudflare:") ? { id, external: true } : null;
    },
  };
}

/**
 * Vitest configures its own `resolve.external` on the ssr environment, which
 * the Cloudflare plugin rejects. Unit tests here are plain module tests and do
 * not need the workerd runtime, so the plugin is left out under `vp test`.
 * Tests that need real bindings belong in a separate Workers-pool project.
 */
const underTest = process.env["VITEST"] !== undefined;

/**
 * Swap the Worker entry for the end-to-end harness entry.
 *
 * The harness needs seed and approve routes that a passkey cannot provide
 * headlessly, so they live in `src/server/worker.e2e.ts`. This plugin is the
 * only switch that pulls that module in, and it exists only when `VAULT_E2E=1`
 * is set at dev or build time. A normal `vp dev` or `vp build` never resolves
 * the module, so the shipped bundle cannot contain it.
 *
 * Only the entry itself is redirected. The harness module imports the normal
 * worker to delegate every request that is not a harness route, and that import
 * carries an importer, so it resolves to the real file.
 */
function selectHarnessWorkerEntry(): Plugin | null {
  if (process.env["VAULT_E2E"] !== "1") return null;
  const normal = fileURLToPath(new URL("./src/server/worker.ts", import.meta.url));
  const harness = fileURLToPath(new URL("./src/server/worker.e2e.ts", import.meta.url));
  return {
    name: "keevault:e2e-worker-entry",
    enforce: "pre",
    resolveId(id: string, importer: string | undefined) {
      // The harness itself imports the normal worker to delegate every request
      // that is not a harness route. That import must not loop back.
      if (importer === harness) return null;
      return id === normal ? harness : null;
    },
  };
}

export default defineConfig({
  resolve: {
    // shadcn writes `@/...` imports. tsconfig paths cover the type checker; the
    // dev server and the SSR build need the alias spelled out.
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
  plugins: [
    selectHarnessWorkerEntry(),
    externalizeWorkersModules(),
    underTest ? null : cloudflare({ viteEnvironment: { name: "ssr" } }),
    tailwindcss(),
    tanstackStart({
      // Custom Worker entry so the Durable Object class can be a named export.
      server: { entry: "server/worker.ts" },
      router: {
        // CLAUDE.md asks for a real `page-name.tsx` leaf inside a real
        // directory. Treating both `page` and `index` as the index token gives
        // `routes/login/page.tsx` the path /login without dot-notation.
        indexToken: { regex: "^(index|page)$" },
        // Emit the generated route tree in the repo's format so `vp check`
        // stays clean after a build regenerates it.
        quoteStyle: "double",
        semicolons: true,
      },
    }),
    react(),
  ],
});
