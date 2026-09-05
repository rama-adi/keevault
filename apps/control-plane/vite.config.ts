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
    name: "env-vault:externalize-cloudflare-modules",
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

export default defineConfig({
  resolve: {
    // shadcn writes `@/...` imports. tsconfig paths cover the type checker; the
    // dev server and the SSR build need the alias spelled out.
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
  plugins: [
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
