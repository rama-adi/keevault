# Dashboard guide

This is a page-by-page guide to the operator dashboard in `apps/control-plane`. Every page listed here corresponds to a file under `src/routes`.

## Login (`/login`)

Passkey only. There is no password field and no fallback. The page calls `authClient.signIn.passkey()`, and on success redirects to `/projects`. A sign-in failure shows the WebAuthn error message inline.

## Setup (`/setup`)

Reachable only while the auth database has zero users; the loader calls `assertSetupOpen`, which throws a 404 the moment an owner exists, for every visitor, signed in or not. The form takes the `VAULT_SETUP_TOKEN` value, a name, and an email, and posts to a Better Auth endpoint that checks the token in constant time before creating the first user with role `owner`. Immediately after, the page prompts a passkey registration. If registration fails after the account is created, sign-in is impossible until a passkey exists, since there is no password to fall back on.

## Projects (`/projects`)

Lists every project. An admin or owner sees a "New project" button that opens a dialog for a name and slug. Viewers see the same list with no create action, since `canEdit(role)` gates it.

## Project (`/projects/$projectId`)

Shows the project's name, slug, and current project key version, plus its list of environments. An admin or owner can create a new environment here. An owner additionally sees delete-project and rotate-project-key actions; both require a passkey verification from the last five minutes, and delete asks for confirmation since it removes every environment and secret underneath.

## Environment (`/projects/$projectId/environments/$environmentId`)

Shows the environment's name, current environment key version, and provenance mode, with three tabs.

**Secrets.** Every secret name is listed with a masked value, `••••••••••••` at a fixed width so the mask never leaks a value's length, and its last-updated time. An admin can create a secret, replace its value, or delete it. A ".env" import accepts pasted text, sends it once over HTTPS, and the Worker parses and encrypts each line independently; nothing pasted is ever returned afterward.

**Tokens.** Lists bootstrap tokens for this environment with their labels, CIDR allow lists, and revocation state. Creating a token requires the admin role and a recent passkey verification; the generated secret is shown exactly once in a copy-once dialog and cannot be retrieved again. Revoking or editing a token's CIDR list requires the admin role, without an additional step-up prompt. This tab also lists trusted signers for the signed-build-manifest verifier: an admin can add or revoke a signer's fingerprint here, again without a step-up prompt.

**Policy.** Sets the environment's provenance mode, `OFF`, `ADVISORY`, or `REQUIRED`, described in `docs/provenance.md`. Changing it requires the admin role and a recent passkey verification. An owner can also rotate the environment key or delete the environment from this tab, both step-up gated.

## Boots list (`/boots`)

Groups pending boot requests by environment. Each group shows the project name and the environment's provenance mode. When a token has more than one live boot at once, the page shows a warning banner instead of listing them as ordinary traffic, since a flood of boots from one token is one of the signs of a stolen token described in `docs/threat-model.md`. An empty list reads "Nothing is waiting."

## Approval screen (`/boots/$bootId`)

The most security-sensitive page. It renders in sections, top to bottom:

- **Boot request.** The token label, the source IP, whether the token's CIDR policy is satisfied, and the current state (`PENDING`, `APPROVED`, and so on).
- **Claimed workload.** Repository, commit, OCI repository, digest, and provider, all labeled "claimed" and followed by a note that everything in this section is workload supplied and untrusted. Compare it against the section below rather than trusting it on its own.
- **Verified evidence.** One block per verifier that ran, each showing its status (`VERIFIED`, `UNVERIFIED`, `FAILED`, `UNAVAILABLE`) and any facts or warnings it produced. A fact can additionally be marked as matching or not matching the corresponding claim above it.
- **Runtime.** Always shows "Running OCI identity: not independently attested", since no verifier in V1 confirms what is currently executing, only what was built.
- **Boot identity.** The signing and encryption key fingerprints for this specific boot, and the boot id. Approval binds to these fingerprints, not to the claimed commit.
- **Timing.** When the request was made and when it expires.

If any verifier's status is `FAILED` for this boot, a red banner reading "SIGNATURE VERIFICATION FAILED" appears at the top of the card, above every other section. This means cryptographic evidence was supplied and did not validate, which is a materially different and more serious situation than a verifier reporting `UNAVAILABLE` (no evidence was supplied to check at all). Do not approve a boot showing this banner without knowing why the signature failed.

If the environment's provenance policy is `REQUIRED` and the configured conditions are not all met, the Approve button is disabled and a warning lists exactly which conditions are unmet.

Approve requires the admin role and a passkey verification from the last five minutes; if the last verification has aged out, a dialog asks for one before the approval request is sent. Decline and cancel require the admin role with no step-up prompt. Approving or declining calls the environment's Durable Object, which re-checks that the boot is still pending, not expired, and that the token is still valid before making any change; if another administrator already acted on it, the page shows a conflict message rather than a stack trace.

## Audit (`/audit`)

Lists audit events with filters for project, environment, and a cursor-based "before" pagination. Any signed-in operator, including a viewer, can read this page. Every audit event name from `docs/product-specs.md` section 35 can appear here; none of them ever contain a secret value or key material.

## Settings (`/settings`)

Lists every administrator with their role and join date. An owner can change any other administrator's role between `owner`, `admin`, and `viewer` through a dialog that is step-up gated. Below that, a card lists which `VAULT_MASTER_KEY_V<n>` versions the Worker can currently read and marks the active one.

## The step-up rule

A signed-in session alone is not enough for the actions below. Each additionally requires a passkey verification from the last five minutes (`STEP_UP_MAX_AGE_SECONDS` in `src/lib/roles.ts`), enforced by `requireRecentPasskey` in `src/server/auth/guards.ts`. This table is read directly from the guard calls in `src/server/functions/*.ts`.

| Action                                        | Server function                                   | Minimum role | Step-up required |
| --------------------------------------------- | ------------------------------------------------- | ------------ | ---------------- |
| Approve a boot                                | `approveBootFn`                                   | admin        | yes              |
| Decline a boot                                | `declineBootFn`                                   | admin        | no               |
| Cancel a boot                                 | `cancelBootFn`                                    | admin        | no               |
| Delete a project                              | `deleteProjectFn`                                 | admin        | yes              |
| Rotate a project key                          | `rotateProjectKeyFn`                              | owner        | yes              |
| Delete an environment                         | `deleteEnvironmentFn`                             | admin        | yes              |
| Change provenance policy                      | `setEnvironmentPolicyFn`                          | admin        | yes              |
| Rotate an environment key                     | `rotateEnvironmentKeyFn`                          | owner        | yes              |
| Create a bootstrap token                      | `createBootstrapTokenFn`                          | admin        | yes              |
| Revoke a bootstrap token                      | `revokeBootstrapTokenFn`                          | admin        | no               |
| Change a token's CIDR list                    | `updateTokenCidrsFn`                              | admin        | no               |
| Add a trusted signer                          | `addTrustedSignerFn`                              | admin        | no               |
| Revoke a trusted signer                       | `revokeTrustedSignerFn`                           | admin        | no               |
| Change an operator's role                     | `setAdministratorRoleFn`                          | owner        | yes              |
| Create a project or environment               | `createProjectFn`, `createEnvironmentFn`          | admin        | no               |
| Create, replace, delete a secret; import .env | `putSecretFn`, `deleteSecretFn`, `importDotenvFn` | admin        | no               |

Spec section 22 lists "configure provenance" as a step-up action; in the current code that applies to changing the policy mode (`setEnvironmentPolicyFn`), but adding or revoking a trusted signer is not step-up gated. This is a gap against the spec, noted here rather than silently matched to it.

## Role matrix as implemented

Read from `ROLE_RANK` in `src/lib/roles.ts` and the `requireRole` calls above. Ranking is `viewer < admin < owner`; `requireRole(minimum)` allows that role and everything ranked above it.

| Operation                                            | Viewer | Admin | Owner |
| ---------------------------------------------------- | :----: | :---: | :---: |
| View projects, environments, secret names, audit log |  yes   |  yes  |  yes  |
| View pending boots and approval screens              |  yes   |  yes  |  yes  |
| Approve, decline, cancel a boot                      |        |  yes  |  yes  |
| Create, replace, delete a secret; import .env        |        |  yes  |  yes  |
| Create or delete a project or environment            |        |  yes  |  yes  |
| Create, revoke, or reconfigure a bootstrap token     |        |  yes  |  yes  |
| Change an environment's provenance policy            |        |  yes  |  yes  |
| Add or revoke a trusted signer                       |        |  yes  |  yes  |
| Rotate a project or environment key                  |        |       |  yes  |
| Change another operator's role                       |        |       |  yes  |

This matches the permissions table in `docs/product-specs.md` section 21, except that section does not separately list project or environment deletion; the code gates both at admin with step-up, consistent with the "edit secrets" and "manage bootstrap tokens" rows rather than the owner-only rotation rows.

## What the dashboard deliberately does not do

**Reveal a stored secret's value.** There is no server function that returns a decrypted secret to the browser once it has been stored, and the UI has no control for it. `MaskedSecret` renders a fixed-width mask with no toggle. The Worker is technically capable of decrypting a secret, since that capability is required to build boot payloads, but no dashboard code path exposes it. This is a deliberate reduction of accidental-disclosure surface, not a cryptographic guarantee that the Worker cannot read secrets.

**Invite a new operator.** The settings page shows this plainly: Better Auth 1.7.2's passkey plugin can only register a credential for an already-authenticated session, so an invited account would have a user row with no way to reach its first passkey. `inviteAdmin` in `src/server/auth/setup.ts` exists as a stub that throws `"inviteAdmin is not implemented yet."`; it is not implemented in V1. Operators are added only through the first-owner setup ceremony, and additional accounts must currently be created the same way infrastructure creates the first owner, then have their role changed on `/settings`.
