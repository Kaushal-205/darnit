import { createHash } from "node:crypto";

/** CSP source expression for an inline element's exact text. */
export const cspHash = (text: string) =>
  `'sha256-${createHash("sha256").update(text, "utf8").digest("base64")}'`;

/** Inline <script> and <style> bodies, in document order. */
export function inlineBlocks(html: string): {
  scripts: string[];
  styles: string[];
} {
  const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)];
  for (const m of scripts)
    if (/\bsrc\s*=/.test(m[1]))
      throw new Error(
        "External <script src> found; the build must inline everything",
      );
  if (
    /<link\b[^>]*rel=["']?(stylesheet|modulepreload|preload|icon)/i.test(html)
  )
    throw new Error(
      "<link> to an external resource found; the build must inline everything",
    );
  return {
    scripts: scripts.map((m) => m[2]),
    styles: [...html.matchAll(/<style\b[^>]*>([\s\S]*?)<\/style>/g)].map(
      (m) => m[1],
    ),
  };
}

/**
 * The page's policy. Scripts and styles are pinned to the exact inlined bytes, nothing else may load.
 * `connect-src http: https:` is the one open door, because the RPC and bundler are chosen by the user at
 * runtime; src/net.ts narrows it to exactly those origins as soon as the user connects.
 */
export function buildPolicy(html: string): string {
  const { scripts, styles } = inlineBlocks(html);
  if (scripts.length === 0) throw new Error("No inline script found");
  return [
    "default-src 'none'",
    `script-src ${scripts.map(cspHash).join(" ")}`,
    `style-src ${styles.length ? styles.map(cspHash).join(" ") : "'none'"}`,
    "img-src data:",
    "connect-src http: https:",
    "base-uri 'none'",
    "form-action 'none'",
  ].join("; ");
}
