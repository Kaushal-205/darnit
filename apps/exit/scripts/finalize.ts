/**
 * Post-build: write the Content-Security-Policy (with the hashes of the inlined script and style) into
 * dist/exit.html, then print its SHA-256 so a downloaded copy can be checked against the release.
 *   tsx scripts/finalize.ts dist/exit.html
 */
import { createHash } from "node:crypto";
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { buildPolicy } from "./csp.js";

const file = process.argv[2] ?? "dist/exit.html";
const html = readFileSync(file, "utf8");
if (!html.includes("__CSP__"))
  throw new Error(`${file}: CSP placeholder missing`);
const out = html.replace("__CSP__", buildPolicy(html));
writeFileSync(file, out);

const others = readdirSync(dirname(file)).filter((f) => f !== "exit.html");
if (others.length)
  throw new Error(`dist must hold only exit.html, found: ${others.join(", ")}`);

const digest = createHash("sha256").update(out).digest("hex");
console.log(`${file}: ${(out.length / 1024).toFixed(0)} KiB, sha256 ${digest}`);
