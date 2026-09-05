import handler from "@tanstack/react-start/server-entry";

// Durable Object classes must be named exports of the Worker entry module.
export { EnvironmentSessionDO } from "./durable-objects/environment-session.ts";

export default {
  fetch(request: Request): Response | Promise<Response> {
    // Extension point: the bootstrap agent routes `GET /bootstrap/v1` upgrades
    // to the EnvironmentSessionDO here, before delegating to TanStack Start.
    return handler.fetch(request);
  },
};
