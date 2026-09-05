import { passkeyClient } from "@better-auth/passkey/client";
import { createAuthClient } from "better-auth/react";

/**
 * Browser-side Better Auth client. Passkey is the only method, so the only
 * calls the dashboard makes are `signIn.passkey`, `passkey.addPasskey`,
 * `signOut` and `useSession`.
 */
export const authClient = createAuthClient({
  plugins: [passkeyClient()],
});

/** Path of the first-owner ceremony endpoint on the mounted auth handler. */
export const SETUP_CLAIM_PATH = "/vault-setup/claim-owner";
