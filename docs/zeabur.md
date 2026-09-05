# Zeabur integration test matrix

This is the checklist an operator runs against a real Zeabur project before
calling env-vault V1 production-ready. It combines the readiness
consideration in product-specs.md section 33 with the Phase 10 test list in
section 43. Every row starts "not yet run" and stays that way until someone
actually runs it against Zeabur and records the result here.

None of these can be run from this repository alone: they need a Zeabur
account, a deployed env-vault control plane, and the example image in
`examples/zeabur-node-app`.

## Deployment mode tests

| #   | Test                                                                                                                                                                                                  | Status      | Notes                                         |
| --- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------- | --------------------------------------------- |
| 1   | Native Zeabur Git build deploys the example app and reaches an approved, running state                                                                                                                | not yet run |                                               |
| 2   | Prebuilt OCI deployment (Zeabur pulls a pre-built, pre-signed image) deploys and reaches an approved, running state                                                                                   | not yet run |                                               |
| 3   | Native Git build dashboard shows Git commit and repository as claimed, and cryptographic provenance as unavailable                                                                                    | not yet run |                                               |
| 4   | Prebuilt OCI deployment dashboard shows build provenance as verified when a valid signed build manifest is attached, and still labels runtime image identity as claimed rather than remotely attested | not yet run |                                               |
| 5   | Static outbound IP, if the Zeabur plan provides one, is confirmed and recorded so the bootstrap token's CIDR allow list can be scoped to it                                                           | not yet run | record the IP or "not available on this plan" |

## Readiness and timing tests (spec section 33)

| #   | Test                                                                                                                                                                                      | Status      | Notes                                                                   |
| --- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------- | ----------------------------------------------------------------------- |
| 6   | New deployment approval delayed 1 minute: old version keeps serving, new version's health check does not pass until approval, traffic switches only after approval                        | not yet run |                                                                         |
| 7   | New deployment approval delayed 5 minutes                                                                                                                                                 | not yet run |                                                                         |
| 8   | New deployment approval delayed 15 minutes                                                                                                                                                | not yet run |                                                                         |
| 9   | New deployment approval delayed 30 minutes                                                                                                                                                | not yet run | record whether Zeabur gives up before this point                        |
| 10  | Determine Zeabur's practical deployment timeout: the delay past which Zeabur stops waiting and marks the deployment failed                                                                | not yet run | this bounds how long the pending-approval TTL can usefully be on Zeabur |
| 11  | A deployment using a volume, if the service has one, is tested separately: Zeabur documents a recreate strategy for volumed services that can behave differently from rolling deployments | not yet run | skip this row and mark "no volume in this service" if not applicable    |

## Connection and lifecycle tests

| #   | Test                                                                                                                                                                                             | Status      | Notes                                                   |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------- | ------------------------------------------------------- |
| 12  | WebSocket disconnect while pending: bootstrap client reconnects and resumes without losing the pending boot                                                                                      | not yet run |                                                         |
| 13  | WebSocket disconnect immediately after approval, before boot.received is sent: client reconnects, resumes, and receives the identical boot.approved frame again                                  | not yet run |                                                         |
| 14  | Redeploy the service while a boot is pending: confirm the old boot is canceled or expires cleanly and the new deployment starts its own boot                                                     | not yet run |                                                         |
| 15  | Restart the service after a successful boot: confirm a fresh boot is created and requires a fresh approval, since the previous boot's keys are gone                                              | not yet run |                                                         |
| 16  | Health check behavior end to end: Zeabur's own health check against `/healthz` fails (or times out) for the whole pending window and only starts passing once vault-bootstrap execs into the app | not yet run | the health check must never be faked into passing early |

## What to record for each row

For every row marked as run, replace "not yet run" with a one-line result
(pass, fail, or partial) and add specifics in Notes: exact timings observed,
the Zeabur plan and region used, and links to logs or screenshots kept
outside this repository. Do not mark a row passed based on reading the code;
it means the operator watched it happen against a real Zeabur deployment.

## Metadata: what Zeabur gives you versus what is merely claimed

- Available from Zeabur as build metadata, forwarded as untrusted claims:
  commit SHA, repository owner and name, branch, and deployment id.
- Not available from Zeabur as a cryptographic attestation: there is no
  remote attestation of which exact binary or image is currently running,
  independent of what the deployment claims. The prebuilt OCI path narrows
  this gap by signing provenance before Zeabur ever sees the image, but even
  then Zeabur is not attesting to the running instance; the signature covers
  what your CI built and pushed.
- The dashboard must keep these two kinds of fact visually distinct, per
  spec section 29: claimed values shown as claims, verified values shown with
  a verifier status of VERIFIED, UNVERIFIED, FAILED, or UNAVAILABLE.
