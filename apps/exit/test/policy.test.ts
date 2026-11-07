import { describe, expect, it } from "vitest";
import { buildPolicy, cspHash } from "../scripts/csp.js";
import { checkOrigins } from "../scripts/origins.js";
import { lockedPolicy, parseEndpoint } from "../src/net.js";

describe("user endpoints", () => {
  it("accepts https anywhere and http only on this computer", () => {
    expect(
      parseEndpoint(" https://rpc.example/v1?key=1 ", "network").origin,
    ).toBe("https://rpc.example");
    expect(parseEndpoint("http://127.0.0.1:8545", "network").origin).toBe(
      "http://127.0.0.1:8545",
    );
    expect(parseEndpoint("http://localhost:3000", "bundler").origin).toBe(
      "http://localhost:3000",
    );
    expect(() => parseEndpoint("http://rpc.example", "network")).toThrow(
      /https/,
    );
    expect(() => parseEndpoint("ws://127.0.0.1:8545", "network")).toThrow(
      /https/,
    );
    expect(() => parseEndpoint("https://u:p@rpc.example", "network")).toThrow(
      /password/,
    );
    expect(() => parseEndpoint("not a url", "network")).toThrow(/valid/);
  });

  it("narrows connect-src to exactly the given origins", () => {
    expect(
      lockedPolicy([
        "https://a.example",
        "http://127.0.0.1:8545",
        "https://a.example",
      ]),
    ).toBe("connect-src https://a.example http://127.0.0.1:8545");
    expect(() => lockedPolicy(["https://a.example; script-src *"])).toThrow();
  });
});

const page = (body: string, csp = "__CSP__") =>
  `<html><head><meta http-equiv="Content-Security-Policy" content="${csp}" /><style>b{}</style></head><body>${body}<script type="module">run()</script></body></html>`;

describe("build policy and origin check", () => {
  it("pins the inline script and style by hash", () => {
    const policy = buildPolicy(page(""));
    expect(policy).toContain(`script-src ${cspHash("run()")}`);
    expect(policy).toContain(`style-src ${cspHash("b{}")}`);
    expect(policy).toContain("default-src 'none'");
    expect(policy).toContain("connect-src http: https:");
  });

  it("passes a clean page and flags third parties", () => {
    const ok = page("", buildPolicy(page("")));
    expect(checkOrigins(ok).problems).toEqual([]);
    expect(
      checkOrigins(ok.replace("run()", 'fetch("https://tracker.example/x")'))
        .problems,
    ).toContain("unexpected origin in bundle: tracker.example");
    expect(
      checkOrigins(page('<script src="x.js"></script>', "default-src 'none'"))
        .problems,
    ).toContain("external <script src>");
    expect(
      checkOrigins(page("", "default-src *")).problems.length,
    ).toBeGreaterThan(0);
  });
});
