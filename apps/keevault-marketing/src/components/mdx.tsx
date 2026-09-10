import { BootFlow } from "@/components/docs/boot-flow";
import { TrustBoundary } from "@/components/docs/trust-boundary";
import defaultMdxComponents from "fumadocs-ui/mdx";
import type { MDXComponents } from "mdx/types";

export function getMDXComponents(components?: MDXComponents) {
  return {
    ...defaultMdxComponents,
    BootFlow,
    TrustBoundary,
    ...components,
  } satisfies MDXComponents;
}
