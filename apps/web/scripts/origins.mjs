// Scans a static export for third-party origins. Kept free of Node I/O for unit tests.

/**
 * URLs that appear in the bundle as plain text but are never requested: library error-message links and
 * XML namespaces. Reviewed by hand; anything not listed fails the check. The two entries with a `connect`
 * reason are the defaults in runtime-config.json, which the user can replace on the Network screen.
 */
export const ALLOWED_TEXT_ORIGINS = {
  "https://viem.sh": "doc links in viem error messages",
  "https://oxlib.sh": "doc links in ox error messages",
  "https://abitype.dev": "doc links in abitype error messages",
  "https://react.dev": "doc links in React error messages",
  "https://reactjs.org": "doc links in React error messages",
  "https://nextjs.org": "doc links in Next.js error messages",
  "https://eips.ethereum.org": "comments or messages referring to EIPs",
  "https://github.com": "library error messages",
  "https://www.w3.org": "XML namespaces used by the DOM",
  "http://www.w3.org": "XML namespaces used by the DOM",
  "http://localhost": "viem/Next.js URL parsing placeholder, never third-party",
  "http://n": "Next.js internal URL parsing base, never requested",
  "http://a.com": "URL parsing feature test in a polyfill, never requested",
  "https://ethereum-sepolia-rpc.publicnode.com": "connect: default RPC in runtime-config.json",
  "https://sepolia.etherscan.io": "connect: explorer link base in runtime-config.json",
};

const URL_RE = /\b(?:https?|wss?):\/\/[a-zA-Z0-9.-]+(?::\d+)?/g;
/** Places where a browser would actually load the URL. No allowlist applies to these. */
const LOADING_RES = [
  /<(?:script|img|iframe|audio|video|source|embed)\b[^>]*\bsrc=["']?((?:https?:)?\/\/[^"'\s>]+)/gi,
  /<link\b[^>]*\bhref=["']?((?:https?:)?\/\/[^"'\s>]+)/gi,
  /url\(\s*["']?((?:https?:)?\/\/[^"')\s]+)/gi,
  /@import\s+(?:url\()?["']?((?:https?:)?\/\/[^"')\s]+)/gi,
  /importScripts\(\s*["']((?:https?:)?\/\/[^"']+)/gi,
];

/** @returns {{ file: string, url: string, reason: string }[]} */
export function scanText(file, text, allowed = ALLOWED_TEXT_ORIGINS) {
  const problems = [];
  for (const re of LOADING_RES) {
    for (const m of text.matchAll(re))
      problems.push({ file, url: m[1], reason: "loaded by the browser" });
  }
  for (const m of text.matchAll(URL_RE)) {
    const origin = m[0].replace(/:\d+$/, "");
    if (!Object.hasOwn(allowed, origin))
      problems.push({ file, url: m[0], reason: "not on the reviewed allowlist" });
  }
  return problems;
}
