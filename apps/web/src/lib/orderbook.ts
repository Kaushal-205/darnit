import { ORDER_SIDE, type SignedOrder } from "@session-firewall/sdk";
import { type Address, type Hex, hashTypedData } from "viem";

const ONE = 1_000_000n;

/** EIP-712 order hash, identical to ReferenceMarket.hashOrder (domain "ReferenceMarket", version "1"). */
export function orderHash(signed: SignedOrder, market: Address, chainId: number): Hex {
  return hashTypedData({
    domain: { name: "ReferenceMarket", version: "1", chainId, verifyingContract: market },
    types: {
      Order: [
        { name: "maker", type: "address" },
        { name: "tokenId", type: "uint256" },
        { name: "side", type: "uint8" },
        { name: "price", type: "uint256" },
        { name: "amount", type: "uint256" },
        { name: "expiry", type: "uint256" },
        { name: "salt", type: "uint256" },
      ],
    },
    primaryType: "Order",
    message: signed.order,
  });
}

export type BookLevel = {
  signed: SignedOrder;
  hash: Hex;
  price: bigint;
  /** Shares still available on this maker order. */
  remaining: bigint;
};

export type Book = {
  /** Maker sells: what you can buy. Cheapest first. */
  asks: BookLevel[];
  /** Maker buys: what you can sell into. Highest first. */
  bids: BookLevel[];
};

/** Live order book for one outcome token, from the fixture maker orders and their filled amounts. */
export function buildBook(
  orders: readonly SignedOrder[],
  tokenId: bigint,
  filled: ReadonlyMap<Hex, bigint>,
  hashes: ReadonlyMap<SignedOrder, Hex>,
  now: bigint,
): Book {
  const levels: BookLevel[] = [];
  for (const signed of orders) {
    const o = signed.order;
    if (o.tokenId !== tokenId || o.expiry < now) continue;
    const hash = hashes.get(signed);
    if (!hash) continue;
    const remaining = o.amount - (filled.get(hash) ?? 0n);
    if (remaining <= 0n) continue;
    levels.push({ signed, hash, price: o.price, remaining });
  }
  return {
    asks: levels
      .filter((l) => l.signed.order.side === ORDER_SIDE.Sell)
      .sort((a, b) => (a.price < b.price ? -1 : a.price > b.price ? 1 : 0)),
    bids: levels
      .filter((l) => l.signed.order.side === ORDER_SIDE.Buy)
      .sort((a, b) => (a.price > b.price ? -1 : a.price < b.price ? 1 : 0)),
  };
}

/** Best single maker order that can take the whole amount, or undefined. */
export function pickLevel(book: Book, action: "buy" | "sell", shares: bigint): BookLevel | undefined {
  const side = action === "buy" ? book.asks : book.bids;
  return side.find((l) => l.remaining >= shares);
}

/** USDC paid (buy, rounded up) or received (sell, rounded down), matching ReferenceMarket.fill. */
export function fillCost(level: Pick<BookLevel, "price">, shares: bigint, action: "buy" | "sell"): bigint {
  const n = shares * level.price;
  return action === "buy" ? (n + ONE - 1n) / ONE : n / ONE;
}

/**
 * Worst-case budget a fill uses (plan R4): a buy can lose everything paid; a sell gives up shares worth
 * at most $1 each, minus the USDC received.
 */
export function worstCaseLoss(level: Pick<BookLevel, "price">, shares: bigint, action: "buy" | "sell"): bigint {
  if (action === "buy") return fillCost(level, shares, "buy");
  const out = shares; // shares x $1, both in 6 decimals
  const received = fillCost(level, shares, "sell");
  return out > received ? out - received : 0n;
}
