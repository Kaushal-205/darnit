// `pnpm --filter @session-firewall/web check:origins`: fail on any third-party origin in the static export.
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { scanText } from "./origins.mjs";

const out = process.argv[2] ?? "out";
const TEXT = /\.(html|js|mjs|css|json|txt|map|svg|xml|webmanifest)$/;

function walk(dir) {
  return readdirSync(dir).flatMap((n) => {
    const p = join(dir, n);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });
}

let files;
try {
  files = walk(out).filter((f) => TEXT.test(f));
} catch {
  console.error(`check:origins: ${out} not found. Run the build first.`);
  process.exit(2);
}
if (!files.some((f) => f.endsWith("index.html"))) {
  console.error(`check:origins: no index.html in ${out}.`);
  process.exit(2);
}

const problems = files.flatMap((f) => scanText(relative(out, f), readFileSync(f, "utf8")));
if (problems.length) {
  for (const p of problems) console.error(`${p.file}: ${p.url} (${p.reason})`);
  console.error(`check:origins FAILED: ${problems.length} problem(s) in ${files.length} files.`);
  process.exit(1);
}
console.log(`check:origins OK: ${files.length} files scanned, no third-party origins loaded or unreviewed.`);
