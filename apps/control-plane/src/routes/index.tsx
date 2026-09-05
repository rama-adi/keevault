import { createFileRoute, redirect } from "@tanstack/react-router";
import { createServerFn } from "@tanstack/react-start";

import { getVaultSession } from "@/server/auth/guards";

const isSignedIn = createServerFn({ method: "GET" }).handler(
  async (): Promise<{ signedIn: boolean }> => {
    return { signedIn: (await getVaultSession()) !== null };
  },
);

export const Route = createFileRoute("/")({
  async beforeLoad() {
    const { signedIn } = await isSignedIn();
    throw redirect({ to: signedIn ? "/projects" : "/login" });
  },
});
