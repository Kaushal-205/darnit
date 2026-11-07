/** tsx scripts/check-origins.ts dist/exit.html — fails if the built page could reach a third party. */
import { readFileSync } from "node:fs";
import { TEXT_ONLY_HOSTS, checkOrigins } from "./origins.js";

const file = process.argv[2] ?? "dist/exit.html";
const { hosts, problems } = checkOrigins(readFileSync(file, "utf8"));
for (const [host, n] of hosts)
  console.log(`  ${host} x${n}: ${TEXT_ONLY_HOSTS[host] ?? "NOT ALLOWED"}`);
if (problems.length) {
  for (const p of problems) console.error(`FAIL ${p}`);
  process.exit(1);
}
console.log(`${file}: no third-party origins, CSP present and hash-pinned`);
