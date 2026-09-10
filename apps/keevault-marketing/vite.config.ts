import { cloudflare } from "@cloudflare/vite-plugin";
import { tanstackStart } from "@tanstack/react-start/plugin/vite";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { fumadocsMdx } from "fumadocs-mdx/vite";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vite-plus";

export default defineConfig({
  resolve: { alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) } },
  plugins: [
    process.env["VITEST"] === undefined ? cloudflare({ viteEnvironment: { name: "ssr" } }) : null,
    fumadocsMdx(),
    tailwindcss(),
    tanstackStart({
      router: {
        indexToken: { regex: "^(index|page)$" },
        quoteStyle: "double",
        semicolons: true,
      },
    }),
    react(),
  ],
});
