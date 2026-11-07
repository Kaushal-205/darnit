/**
 * Static origin check for the built exit page (plan §5/§6: no external requests except the RPC and
 * bundler the user enters).
 *
 * Bundled libraries contain some absolute URLs as plain text. Each one allowed below is listed with the
 * reason it can never become a request from this page. Any other host fails the check, as does any
 * resource reference (script src, link href, CSS url(), @import) that is not inline.
 * The runtime guarantee is the CSP (connect-src narrowed to the user's own origins after Connect,
 * img-src data: only); the end-to-end test also records every request the page makes.
 */
export const TEXT_ONLY_HOSTS: Record<string, string> = {
  "viem.sh": "viem error messages: 'Docs: https://viem.sh/...'",
  "abitype.dev": "abitype error messages: 'Docs: https://abitype.dev/...'",
  "oxlib.sh": "ox error messages: 'See: https://oxlib.sh/...'",
  "4byte.sourcify.dev":
    "viem error text: 'look up the signature here: https://4byte.sourcify.dev/?q=...'",
  "docs.soliditylang.org": "viem error text explaining Solidity panic codes",
  "ipfs.io":
    "viem ENS avatar default gateway; the page never resolves ENS avatars, and CSP blocks it",
  "arweave.net":
    "viem ENS avatar default gateway; the page never resolves ENS avatars, and CSP blocks it",
  localhost: "placeholder text and loopback detection in the page itself",
  "127.0.0.1": "placeholder text (http://127.0.0.1:8545) in the page itself",
};

export type OriginReport = { hosts: Map<string, number>; problems: string[] };

export function checkOrigins(html: string): OriginReport {
  const problems: string[] = [];
  const hosts = new Map<string, number>();
  for (const m of html.matchAll(
    /\b(?:https?|wss?|ftp):\/\/([^\s"'`<>()\\/?#:$]*)/gi,
  )) {
    const host = m[1].toLowerCase().replace(/\.$/, "");
    if (!/[a-z0-9]/.test(host) || host.startsWith("${")) continue; // templates such as `https://${rpId}`
    hosts.set(host, (hosts.get(host) ?? 0) + 1);
  }
  for (const host of hosts.keys())
    if (!(host in TEXT_ONLY_HOSTS))
      problems.push(`unexpected origin in bundle: ${host}`);

  if (/<script\b[^>]*\bsrc\s*=/i.test(html))
    problems.push("external <script src>");
  if (/<link\b[^>]*\bhref\s*=/i.test(html))
    problems.push("<link href> (external resource)");
  if (
    /<(img|iframe|audio|video|source|embed|object)\b[^>]*\bsrc\s*=\s*["']?(?!data:)/i.test(
      html,
    )
  )
    problems.push("external media reference");
  const styles = [...html.matchAll(/<style\b[^>]*>([\s\S]*?)<\/style>/gi)]
    .map((m) => m[1])
    .join("\n");
  if (/@import|url\(\s*["']?(?!data:)/i.test(styles))
    problems.push("CSS @import or url() to a non-data resource");

  const csp =
    /<meta\s+http-equiv="Content-Security-Policy"\s+content="([^"]+)"/i.exec(
      html,
    )?.[1];
  if (!csp) problems.push("Content-Security-Policy meta tag missing");
  else {
    if (!/default-src 'none'/.test(csp))
      problems.push("CSP lacks default-src 'none'");
    if (/unsafe-inline|unsafe-eval|\*/.test(csp))
      problems.push("CSP allows unsafe-inline, unsafe-eval or *");
    if (!/script-src 'sha256-/.test(csp))
      problems.push("CSP does not pin the script by hash");
  }
  return { hosts, problems };
}
