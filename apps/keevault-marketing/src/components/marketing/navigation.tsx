import { ArrowRight, ChevronRight, LockKeyhole } from "lucide-react";
import { MarketingButton } from "@/components/marketing/button";

export function MarketingHeader() {
  return (
    <header className="site-header page-width">
      <a href="/" className="wordmark" aria-label="keevault home">
        <span className="brand-icon">
          <LockKeyhole aria-hidden="true" />
        </span>
        keevault<span className="wordmark-period">.</span>
      </a>
      <nav aria-label="Main navigation" className="header-nav">
        <a href="/#how-it-works">How it works</a>
        <a href="/#security">Security</a>
        <a href="/pricing">Pricing</a>
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
  );
}

export function MarketingFooter() {
  return (
    <footer className="site-footer page-width">
      <a href="/" className="wordmark">
        <span className="brand-icon">
          <LockKeyhole aria-hidden="true" />
        </span>
        keevault<span className="wordmark-period">.</span>
      </a>
      <p>Always free.</p>
      <nav aria-label="Footer navigation">
        <a href="/pricing">Pricing</a>
        <a href="/docs">Documentation</a>
        <a href="/docs/security">Security guide</a>
      </nav>
    </footer>
  );
}
