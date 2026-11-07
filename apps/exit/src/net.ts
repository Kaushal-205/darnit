/**
 * Network policy for the exit page.
 *
 * A static file cannot know the user's RPC and bundler in advance, so the Content-Security-Policy baked
 * into exit.html allows `connect-src http: https:` and nothing else (no scripts, styles, images, fonts
 * or frames from anywhere). Once the user presses "Connect", `lockConnections` narrows it to exactly the
 * origins they typed, in two layers:
 *   1. a second CSP <meta> tag with `connect-src <rpc origin> <bundler origin>`. CSP policies only ever
 *      add up, so the browser now refuses any other connection for the rest of the page's life;
 *   2. a fetch() wrapper that refuses any other origin, in case a browser ignores a CSP meta tag that
 *      was added after load.
 * Changing the addresses afterwards needs a page reload, which is stated in the UI.
 */

export type Endpoint = { url: string; origin: string };

/** Parse a user-entered RPC or bundler URL. Only http(s), no credentials in the URL. */
export function parseEndpoint(input: string, label: string): Endpoint {
  const text = input.trim();
  let u: URL;
  try {
    u = new URL(text);
  } catch {
    throw new Error(`The ${label} address is not a valid web address.`);
  }
  if (u.protocol !== "https:" && u.protocol !== "http:")
    throw new Error(
      `The ${label} address must start with https:// or http://.`,
    );
  if (u.username || u.password)
    throw new Error(
      `Remove the user name and password from the ${label} address.`,
    );
  if (u.protocol === "http:" && !isLoopback(u.hostname))
    throw new Error(
      `The ${label} address must use https:// (plain http:// is only allowed for this computer, e.g. http://127.0.0.1:8545).`,
    );
  return { url: text, origin: u.origin };
}

export function isLoopback(hostname: string): boolean {
  return (
    hostname === "localhost" ||
    hostname.endsWith(".localhost") ||
    hostname === "[::1]" ||
    /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)
  );
}

/** The narrowed policy added by lockConnections. */
export function lockedPolicy(origins: readonly string[]): string {
  const unique = [...new Set(origins)];
  for (const o of unique)
    if (!/^https?:\/\/[A-Za-z0-9.\-[\]:]+$/.test(o))
      throw new Error(`Refusing to allow unexpected origin ${o}`);
  return `connect-src ${unique.join(" ")}`;
}

let allowed: Set<string> | undefined;

export function allowedOrigins(): readonly string[] {
  return allowed ? [...allowed] : [];
}

/** Narrow all further network access to `origins`. Can be called only once per page load. */
export function lockConnections(origins: readonly string[]): void {
  if (allowed) {
    const same = origins.every((o) => allowed?.has(o)) && origins.length > 0;
    if (same) return;
    throw new Error(
      "The page is already connected to other addresses. Reload the page to use different ones.",
    );
  }
  const policy = lockedPolicy(origins);
  allowed = new Set(origins);
  const meta = document.createElement("meta");
  meta.httpEquiv = "Content-Security-Policy";
  meta.content = policy;
  document.head.appendChild(meta);

  const original = window.fetch.bind(window);
  window.fetch = (input: RequestInfo | URL, init?: RequestInit) => {
    const url =
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.href
          : input.url;
    const origin = new URL(url, location.href).origin;
    if (!allowed?.has(origin))
      return Promise.reject(
        new Error(`Blocked a request to ${origin}: not one of your addresses.`),
      );
    return original(input, init);
  };
}
