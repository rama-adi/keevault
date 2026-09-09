import { createFileRoute } from "@tanstack/react-router";
import { MarketingHeader, MarketingFooter } from "@/components/marketing/navigation";

export const Route = createFileRoute("/pricing/")({
  head: () => ({
    meta: [
      { title: "Pricing | keevault" },
      { name: "description", content: "Always free, with reasonable rate limits." },
    ],
  }),
  component: PricingPage,
});

function PricingPage() {
  return (
    <div className="marketing-site flex min-h-svh flex-col">
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <MarketingHeader />
      <main id="main" className="grid flex-1 place-items-center px-6 py-24">
        <div className="flex flex-col gap-6 text-center">
          <h1 className="text-6xl font-semibold tracking-tight text-primary sm:text-8xl">
            Always free.
          </h1>
          <p className="text-lg text-muted-foreground">With reasonable rate limits.</p>
        </div>
      </main>
      <MarketingFooter />
    </div>
  );
}
