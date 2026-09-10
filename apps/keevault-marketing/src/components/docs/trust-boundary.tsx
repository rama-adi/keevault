export function TrustBoundary() {
  return (
    <figure className="docs-diagram docs-trust-boundary">
      <figcaption>What changes when you approve a boot</figcaption>
      <div className="docs-boundary-zones">
        <section className="docs-boundary-zone">
          <span className="docs-diagram-label">Before approval</span>
          <h3>Your deployment can request access</h3>
          <p>
            The host holds a bootstrap token. The token lets the client request its environment; it
            does not grant approval.
          </p>
        </section>
        <div className="docs-boundary-gate">
          <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <path
              d="M5 12h14m-5-5 5 5-5 5"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
          <span>Approve this boot</span>
        </div>
        <section className="docs-boundary-zone">
          <span className="docs-diagram-label">After approval</span>
          <h3>Your runtime has the secrets</h3>
          <p>
            The client decrypts the environment and starts your application. Anyone controlling that
            application or its host can access the plaintext values.
          </p>
        </section>
      </div>
      <p className="docs-diagram-note">
        Revoking the bootstrap token blocks future access. Rotate exposed credentials at their
        issuing service to invalidate values already delivered.
      </p>
    </figure>
  );
}
