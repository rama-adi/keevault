import { readBinaryCatalog, type ReleaseEnv } from "./catalog.ts";
import template from "./download.sh?raw";

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

export async function handleDownloadRequest(request: Request, env: ReleaseEnv): Promise<Response> {
  if (request.method !== "GET" && request.method !== "HEAD") {
    return new Response(null, { status: 405, headers: { Allow: "GET, HEAD" } });
  }
  const { latest, binaries } = await readBinaryCatalog(env.VAULT_DB);
  const cases = binaries
    .map(
      (binary) =>
        `    ${shellQuote(`${binary.version}:${binary.arch}`)}) url=${shellQuote(binary.url)}; hash=${shellQuote(binary.hash)} ;;`,
    )
    .join("\n");
  const script = template
    .replace("__KEEVAULT_LATEST__", () => shellQuote(latest ?? ""))
    .replace("# __KEEVAULT_RELEASES__", () => cases);
  return new Response(request.method === "HEAD" ? null : script, {
    headers: {
      "Content-Type": "text/x-shellscript; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    },
  });
}
