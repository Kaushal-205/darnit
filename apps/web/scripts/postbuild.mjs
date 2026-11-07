// Post-processes the static export:
// 1. adds Subresource Integrity (sha384) to every <script src> and stylesheet/preload <link>,
// 2. adds a meta CSP, so hosts that cannot set headers (IPFS gateways, a local folder) still get one,
// 3. fails if an inline executable script exists, which script-src 'self' would refuse.
import { createHash } from "node:crypto";
import { readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const out = process.argv[2] ?? join(here, "..", "out");
const headers = JSON.parse(readFileSync(join(here, "..", "security-headers.json"), "utf8"));
// frame-ancestors is ignored (and warned about) in a meta tag; the header carries it.
const metaCsp = headers["Content-Security-Policy"].replace(/;\s*frame-ancestors[^;]*/, "");

function htmlFiles(dir) {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) return name === "_next" ? [] : htmlFiles(p);
    return name.endsWith(".html") ? [p] : [];
  });
}

const sri = (file) => `sha384-${createHash("sha384").update(readFileSync(file)).digest("base64")}`;

for (const file of htmlFiles(out)) {
  let html = readFileSync(file, "utf8");
  const dir = dirname(file);
  html = html.replace(/<(script|link)\b([^>]*?)(\/?)>/g, (tag, name, attrs, close) => {
    const m = /\b(?:src|href)="([^"]+)"/.exec(attrs);
    if (!m || !/\.(js|css)(\?|$)/.test(m[1]) || /\bintegrity=/.test(attrs)) return tag;
    const target = join(dir, m[1].split("?")[0]);
    return `<${name}${attrs} integrity="${sri(target)}"${close}>`;
  });
  html = html.replace(
    /<head>/,
    `<head><meta http-equiv="Content-Security-Policy" content="${metaCsp}"/>`,
  );
  const inline = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)].filter(
    ([, attrs, body]) => body.trim() && !/type="application\/json"/.test(attrs),
  );
  if (inline.length) {
    console.error(`${relative(out, file)}: ${inline.length} inline script(s) would break the CSP`);
    process.exit(1);
  }
  writeFileSync(file, html);
  console.log(`postbuild: ${relative(out, file)} hardened`);
}
