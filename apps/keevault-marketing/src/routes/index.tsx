import { createFileRoute } from "@tanstack/react-router";
import {
  ArrowDown,
  ArrowRight,
  Check,
  CheckCheck,
  ChevronRight,
  Code2,
  Database,
  Fingerprint,
  KeyRound,
  LockKeyhole,
  Network,
  ShieldCheck,
  Terminal,
  Workflow,
} from "lucide-react";
import { MarketingButton } from "@/components/marketing/button";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "keevault | Secrets for your apps. Always free." },
      {
        name: "description",
        content:
          "Store deployment secrets in keevault and approve each application boot before it receives them. Always free.",
      },
    ],
  }),
  component: MarketingPage,
});

function MarketingPage() {
  return (
    <div className="marketing-site">
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <header className="site-header page-width">
        <a href="/" className="wordmark" aria-label="keevault home">
          <span className="brand-icon">
            <LockKeyhole aria-hidden="true" />
          </span>
          keevault<span className="wordmark-period">.</span>
        </a>
        <nav aria-label="Main navigation" className="header-nav">
          <a href="#how-it-works">How it works</a>
          <a href="#security">Security</a>
          <a href="/docs">
            Docs <ChevronRight aria-hidden="true" />
          </a>
        </nav>
        <MarketingButton asChild size="sm">
          <a href="/docs/getting-started">
            Get started <ArrowRight data-icon="inline-end" />
          </a>
        </MarketingButton>
      </header>
      <main id="main">
        <section className="hero page-width" aria-labelledby="hero-title">
          <div className="hero-copy">
            <h1 id="hero-title">
              App secrets.
              <br />
              <span>You approve.</span>
            </h1>
            <p className="hero-description">
              Store your environment variables in keevault.
              <br className="desktop-break" /> Your app receives them after you approve its boot.
            </p>
            <div className="hero-actions">
              <MarketingButton asChild size="lg">
                <a href="/docs/getting-started">
                  Connect your app <ArrowRight data-icon="inline-end" />
                </a>
              </MarketingButton>
              <MarketingButton asChild variant="outline" size="lg">
                <a href="#how-it-works">
                  How it works <ArrowDown data-icon="inline-end" />
                </a>
              </MarketingButton>
            </div>
            <div className="hero-footnote">
              <Check aria-hidden="true" /> Always free <span>·</span> For containers & VPS
              deployments
            </div>
          </div>
          <div
            className="vault-visual"
            role="img"
            aria-label="keevault keeps environment secrets encrypted until you approve a specific application boot."
          >
            <div className="visual-grid" />
            <div className="visual-topline">
              <span>ENVIRONMENT SECRET DELIVERY</span>
              <span>01 / 03</span>
            </div>
            <div className="orbit orbit-one" />
            <div className="orbit orbit-two" />
            <div className="vault-object">
              <div className="vault-top" />
              <div className="vault-side" />
              <div className="vault-face">
                <div className="vault-face-caption">ENCRYPTED SECRETS</div>
                <div className="vault-dial">
                  <LockKeyhole strokeWidth={1.3} />
                  <i />
                  <b />
                </div>
                <span className="vault-face-footer">
                  keevault<span>● ● ●</span>
                </span>
              </div>
            </div>
            <div className="visual-secret">
              <Database />
              <span>
                ENVIRONMENT SECRETS<code>••••••••••••••••</code>
              </span>
              <LockKeyhole />
            </div>
            <div className="visual-connector" />
            <div className="approval-stamp">
              <Fingerprint />
              <div>
                Human approval<span>For this application boot</span>
              </div>
              <Check />
            </div>
            <div className="visual-bottom">
              <span>
                <span className="status-dot" /> WAITING FOR APPROVAL
              </span>
              <KeyRound />
            </div>
          </div>
        </section>
        <div className="platform-strip page-width">
          <p>
            Use keevault with
            <br />
            <strong>your existing deployment.</strong>
          </p>
          <div>
            <Code2 /> Containers
          </div>
          <div>
            <Terminal /> VPS
          </div>
          <div>
            <Network /> Zeabur
          </div>
          <div>
            <Workflow /> Your existing app
          </div>
        </div>
        <section
          className="workflow-section page-width"
          id="how-it-works"
          aria-labelledby="workflow-title"
        >
          <div className="section-heading">
            <div>
              <h2 id="workflow-title">
                Review each boot.
                <br />
                <span>Then release its secrets.</span>
              </h2>
            </div>
          </div>
          <ol className="workflow-grid">
            <li>
              <span className="step-number">01</span>
              <Terminal />
              <h3>Start the keevault client.</h3>
              <p>Run keevault. It requests your app's secrets and waits for approval.</p>
              <code>STATUS: PENDING</code>
            </li>
            <li>
              <span className="step-number">02</span>
              <Fingerprint />
              <h3>Review and approve the boot.</h3>
              <p>Check the request in your dashboard and approve it with your passkey.</p>
              <code>APPROVAL: THIS BOOT ONLY</code>
            </li>
            <li>
              <span className="step-number">03</span>
              <CheckCheck />
              <h3>Your application starts.</h3>
              <p>The client runs your configured command with the approved secrets.</p>
              <code>NEXT: START YOUR APP</code>
            </li>
          </ol>
        </section>
        <section className="developer-section page-width" aria-labelledby="developer-title">
          <div className="developer-copy">
            <h2 id="developer-title">
              Configure in JSON.
              <br />
              Run keevault.
            </h2>
            <p>Put your launch settings in keevault.json. Then run keevault.</p>
            <a className="text-link" href="/docs/client">
              Read the client guide <ArrowRight />
            </a>
            <div className="config-note">
              <KeyRound />
              <p>
                Your platform stores a bootstrap token.
                <br />
                <strong>The token alone cannot release secrets.</strong>
              </p>
            </div>
          </div>
          <div className="code-window">
            <div className="code-window-header">
              <span>
                <i />
                <i />
                <i />
              </span>
              <span>keevault.json</span>
              <Code2 />
            </div>
            <pre aria-label="Example keevault configuration">
              <code>
                {"{\n  "}
                <span className="code-key">"vaultUrl"</span>
                {": "}
                <span className="code-string">"https://vault.example.com"</span>
                {",\n  "}
                <span className="code-key">"environmentId"</span>
                {": "}
                <span className="code-string">"env_your_environment"</span>
                {",\n  "}
                <span className="code-key">"requiredSecrets"</span>
                {": [\n    "}
                <span className="code-string">"DATABASE_URL"</span>
                {",\n    "}
                <span className="code-string">"API_KEY"</span>
                {"\n  ],\n  "}
                <span className="code-key">"command"</span>
                {": ["}
                <span className="code-string">"node"</span>
                {", "}
                <span className="code-string">"server.js"</span>
                {"]\n}"}
              </code>
            </pre>
            <div className="terminal-command">
              <span>$</span> keevault
              <span className="terminal-cursor" />
            </div>
            <div className="terminal-result">
              <span className="status-dot" /> Waiting for approval<span>example boot</span>
            </div>
          </div>
        </section>
        <section
          className="security-section page-width"
          id="security"
          aria-labelledby="security-title"
        >
          <div className="section-heading">
            <div>
              <h2 id="security-title">
                What keevault protects.
                <br />
                <span>What you need to check.</span>
              </h2>
            </div>
            <a className="text-link" href="/docs/security">
              Read the security guide <ArrowRight />
            </a>
          </div>
          <div className="security-grid">
            <article>
              <Database />
              <h3>Store secret values in keevault.</h3>
              <p>Keep secret values out of your code and container image.</p>
            </article>
            <article>
              <KeyRound />
              <h3>Each approval applies to one boot.</h3>
              <p>A restart needs a new approval.</p>
            </article>
            <article>
              <ShieldCheck />
              <h3>Review requests before approving.</h3>
              <p>A token can request secrets. Only you can approve access.</p>
            </article>
            <article>
              <LockKeyhole />
              <h3>Protect your running application.</h3>
              <p>After approval, secrets are available to your app and anyone controlling it.</p>
            </article>
          </div>
        </section>
        <section className="final-cta page-width">
          <div className="cta-key">
            <LockKeyhole />
          </div>
          <h2>
            Connect your app
            <br />
            to keevault.
          </h2>
          <MarketingButton asChild size="lg">
            <a href="/docs/getting-started">
              Get started <ArrowRight data-icon="inline-end" />
            </a>
          </MarketingButton>
        </section>
      </main>
      <footer className="site-footer page-width">
        <a href="/" className="wordmark">
          <span className="brand-icon">
            <LockKeyhole aria-hidden="true" />
          </span>
          keevault<span className="wordmark-period">.</span>
        </a>
        <p>Always free.</p>
        <nav aria-label="Footer navigation">
          <a href="/docs">Documentation</a>
          <a href="/docs/security">Security guide</a>
        </nav>
      </footer>
    </div>
  );
}
