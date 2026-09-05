import handler from "@tanstack/react-start/server-entry";

import { handleBootstrapRequest, isBootstrapRequest } from "./bootstrap/upgrade.ts";

// Durable Object classes must be named exports of the Worker entry module.
export { EnvironmentSessionDO } from "./durable-objects/environment-session.ts";

export default {
  fetch(request: Request, env: Env): Response | Promise<Response> {
    // The machine protocol is handled before the dashboard: it authenticates
    // with a bootstrap token, not a session cookie, and it never renders a page.
    if (isBootstrapRequest(new URL(request.url))) {
      return handleBootstrapRequest(request, env);
    }
    return handler.fetch(request);
  },
};
