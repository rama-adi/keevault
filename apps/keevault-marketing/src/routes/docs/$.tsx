import { createFileRoute, notFound } from "@tanstack/react-router";
import { createServerFn } from "@tanstack/react-start";
import { DocsLayout } from "fumadocs-ui/layouts/docs";
import { DocsBody, DocsDescription, DocsPage, DocsTitle } from "fumadocs-ui/layouts/docs/page";
import { useFumadocsLoader } from "fumadocs-core/source/client";
import { LockKeyhole } from "lucide-react";
import { Suspense, use } from "react";
import { docs, source } from "@/lib/source";
import { getMDXComponents } from "@/components/mdx";

const loadPage = createServerFn({ method: "GET" })
  .validator((slugs: string[]) => slugs)
  .handler(async ({ data: slugs }) => {
    const page = source.getPage(slugs);
    if (!page) throw notFound();
    return {
      path: page.path,
      title: page.data.title,
      description: page.data.description,
      pageTree: await source.serializePageTree(source.getPageTree()),
    };
  });

export const Route = createFileRoute("/docs/$")({
  loader: async ({ params }) => {
    const data = await loadPage({ data: params._splat?.split("/").filter(Boolean) ?? [] });
    await docs.getPage(data.path)?.preload();
    return data;
  },
  head: ({ loaderData }) => ({
    meta: [
      { title: `${loaderData?.title ?? "Documentation"} | KeeVault docs` },
      {
        name: "description",
        content: loaderData?.description ?? "Learn how to use and operate KeeVault.",
      },
    ],
  }),
  component: DocumentationPage,
});

function Content({ path }: { path: string }) {
  const page = docs.getPage(path);
  if (!page) throw notFound();
  const { toc } = use(page.load());
  const MDX = page.body;
  return (
    <DocsPage toc={toc} className="docs-page">
      <div className="docs-page-heading">
        <p className="eyebrow">
          <span className="status-dot" /> KEEVAULT DOCS
        </p>
        <DocsTitle className="docs-page-title">{page.title}</DocsTitle>
        <DocsDescription className="docs-page-description">{page.description}</DocsDescription>
      </div>
      <DocsBody className="docs-prose">
        <MDX components={getMDXComponents()} />
      </DocsBody>
    </DocsPage>
  );
}

function DocumentationPage() {
  const data = useFumadocsLoader(Route.useLoaderData());
  return (
    <DocsLayout
      containerProps={{ className: "docs-site" }}
      nav={{
        title: (
          <span className="wordmark">
            <span className="brand-icon">
              <LockKeyhole aria-hidden="true" />
            </span>
            keevault<span className="wordmark-period">.</span>
          </span>
        ),
        url: "/",
      }}
      themeSwitch={{ enabled: false }}
      sidebar={{
        footer: (
          <nav className="docs-sidebar-footer" aria-label="Project links">
            <a href="/docs/why-keevault">Why Keevault</a>
            <a href="https://vault.keevault.my.id">Open vault</a>
          </nav>
        ),
      }}
      tree={data.pageTree}
    >
      <Suspense fallback={<p className="p-8">Loading documentation…</p>}>
        <Content path={data.path} />
      </Suspense>
    </DocsLayout>
  );
}
