# Documentation index

Read these in order if you are operating env-vault for the first time.

1. **[architecture.md](./architecture.md)**. Components, request paths, the key hierarchy with exact AAD strings, the boot state machine, and what lives in D1 versus the Durable Object.
2. **[operations.md](./operations.md)**. The deployment runbook: create the D1 databases, generate secrets, run the first-owner ceremony, then day-two tasks like adding secrets, approving boots, and rotating keys.
3. **[dashboard.md](./dashboard.md)**. A page-by-page guide to the operator dashboard, the step-up rule, and the role matrix as implemented.
4. **[threat-model.md](./threat-model.md)**. What the vault protects, against whom, and how each attacker scenario is stopped.
5. **[provenance.md](./provenance.md)**. The claims, evidence, verifier, and policy model that backs the approval screen.
6. **[key-rotation.md](./key-rotation.md)**. The three key rotation runbooks: environment key, project key, and master key.
7. **[incident-response.md](./incident-response.md)**. Detect, contain, eradicate, recover for each incident type, from a leaked token to a compromised admin account.
8. **[zeabur.md](./zeabur.md)**. The Zeabur integration test matrix. Every row starts unrun until an operator runs it against a real Zeabur project.
9. **[engineering-brief.md](./engineering-brief.md)**. The byte-level contract between the TypeScript and Go implementations, plus current implementation status.

`security-review-v1.md`, when it exists in this directory, is maintained by a separate review workstream and is not covered by this index.

The normative wire protocol lives outside this directory at `protocol/websocket-v1.md`, alongside the generated JSON schema and test vectors.
