import { createFileRoute } from "@tanstack/react-router";

import { createAuth } from "@/server/auth/auth";

/**
 * Better Auth handler, mounted at the default basePath /api/auth.
 * The auth instance is built per request because Cloudflare supplies bindings
 * per request.
 */
export const Route = createFileRoute("/api/auth/$")({
  server: {
    handlers: {
      GET: ({ request }) => createAuth().handler(request),
      POST: ({ request }) => createAuth().handler(request),
    },
  },
});
