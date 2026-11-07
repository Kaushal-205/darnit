/** USDC and outcome shares both use 6 decimals. */
const UNIT = 1_000_000n;

function groupThousands(s: string): string {
  return s.replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

/** 1234560000n -> "$1,234.56" */
export function formatUsd(v: bigint): string {
  const neg = v < 0n;
  const abs = neg ? -v : v;
  const cents = (abs + 5_000n) / 10_000n; // round half up to cents
  const whole = cents / 100n;
  const frac = (cents % 100n).toString().padStart(2, "0");
  return `${neg ? "-" : ""}$${groupThousands(whole.toString())}.${frac}`;
}

/** 100500000n -> "100.5" */
export function formatShares(v: bigint): string {
  const whole = v / UNIT;
  const frac = (v % UNIT).toString().padStart(6, "0").replace(/0+$/, "");
  return `${groupThousands(whole.toString())}${frac ? `.${frac}` : ""}`;
}

/** Price per share, e.g. 500000n -> "$0.50" */
export function formatPrice(v: bigint): string {
  return formatUsd(v);
}

/**
 * Parse a dollar or share amount typed by a person ("1,000", "$25.5") into 6-decimal base units.
 * Returns undefined for anything that is not a positive amount with at most 6 decimals.
 */
export function parseAmount(input: string): bigint | undefined {
  const s = input.trim().replace(/^\$/, "").replace(/,/g, "");
  const m = /^(\d+)(?:\.(\d{0,6}))?$/.exec(s);
  if (!m) return undefined;
  const v = BigInt(m[1]) * UNIT + BigInt((m[2] ?? "").padEnd(6, "0") || "0");
  return v > 0n ? v : undefined;
}

/** "in 23 h 59 min" / "ready now" for a unix-seconds deadline. */
export function formatEta(eta: bigint, now: bigint): string {
  if (eta <= now) return "ready now";
  const s = Number(eta - now);
  const h = Math.floor(s / 3600);
  const m = Math.ceil((s % 3600) / 60);
  if (h === 0) return `in ${m} min`;
  return `in ${h} h ${m} min`;
}

/** "7 days" / "3 h" until a unix-seconds time, or "expired". */
export function formatRemaining(until: bigint, now: bigint): string {
  if (until <= now) return "expired";
  const s = Number(until - now);
  const d = Math.floor(s / 86_400);
  if (d >= 1) return `${d} day${d === 1 ? "" : "s"} left`;
  const h = Math.floor(s / 3600);
  if (h >= 1) return `${h} h left`;
  return `${Math.max(1, Math.floor(s / 60))} min left`;
}

export function shortHex(v: string, chars = 6): string {
  return v.length <= 2 + chars * 2
    ? v
    : `${v.slice(0, 2 + chars)}…${v.slice(-chars)}`;
}

export function formatDate(unixSeconds: bigint | number): string {
  return new Date(Number(unixSeconds) * 1000).toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}
