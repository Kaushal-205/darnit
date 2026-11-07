import type { Severity } from "../src/lib/rules.ts";

/**
 * Sliding-window rate limit per (account, contact). Critical and high alerts (queued changes,
 * emergency uninstall) are never suppressed: missing one can cost the account. Warning and info
 * alerts share a budget; suppressed alerts are counted and mentioned in the next delivered one.
 */
export type RateLimiter = {
  /** Returns true when the alert may be sent now, recording it; false when suppressed. */
  allow(key: string, severity: Severity, now: number): boolean;
  /** Number of alerts suppressed for `key` since the last call (resets the counter). */
  takeSuppressed(key: string): number;
};

export function rateLimiter(
  p: { max?: number; windowSeconds?: number } = {},
): RateLimiter {
  const max = p.max ?? 10;
  const window = p.windowSeconds ?? 3_600;
  const sent = new Map<string, number[]>();
  const suppressed = new Map<string, number>();
  return {
    allow(key, severity, now) {
      if (severity === "critical" || severity === "high") return true;
      const times = (sent.get(key) ?? []).filter((t) => t > now - window);
      if (times.length >= max) {
        sent.set(key, times);
        suppressed.set(key, (suppressed.get(key) ?? 0) + 1);
        return false;
      }
      times.push(now);
      sent.set(key, times);
      return true;
    },
    takeSuppressed(key) {
      const n = suppressed.get(key) ?? 0;
      suppressed.delete(key);
      return n;
    },
  };
}
