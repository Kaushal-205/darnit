import {
  type Address,
  type Hex,
  type LocalAccount,
  encodeFunctionData,
} from "viem";
import { referenceMarketAbi } from "./abi/index.js";

/** ReferenceMarket order. `side` is the maker's side: Buy = 0 (taker sells), Sell = 1 (taker buys). */
export type ReferenceOrder = {
  maker: Address;
  tokenId: bigint;
  side: 0 | 1;
  /** USDC base units per whole share (1e6 = $1) */
  price: bigint;
  /** shares, 6 decimals */
  amount: bigint;
  expiry: bigint;
  salt: bigint;
};

export type SignedOrder = { order: ReferenceOrder; signature: Hex };

export const ORDER_SIDE = { Buy: 0, Sell: 1 } as const;

const orderTypes = {
  Order: [
    { name: "maker", type: "address" },
    { name: "tokenId", type: "uint256" },
    { name: "side", type: "uint8" },
    { name: "price", type: "uint256" },
    { name: "amount", type: "uint256" },
    { name: "expiry", type: "uint256" },
    { name: "salt", type: "uint256" },
  ],
} as const;

/** EIP-712 maker signature for a ReferenceMarket order (domain "ReferenceMarket", version "1"). */
export async function signReferenceOrder(
  maker: LocalAccount,
  p: { market: Address; chainId: number; order: Omit<ReferenceOrder, "maker"> },
): Promise<SignedOrder> {
  const order: ReferenceOrder = { ...p.order, maker: maker.address };
  const signature = await maker.signTypedData({
    domain: {
      name: "ReferenceMarket",
      version: "1",
      chainId: p.chainId,
      verifyingContract: p.market,
    },
    types: orderTypes,
    primaryType: "Order",
    message: order,
  });
  return { order, signature };
}

/** Calldata for `ReferenceMarket.fill(order, signature, fillAmount, recipient)`. */
export function encodeFill(
  signed: SignedOrder,
  amount: bigint,
  recipient: Address,
): Hex {
  return encodeFunctionData({
    abi: referenceMarketAbi,
    functionName: "fill",
    args: [signed.order, signed.signature, amount, recipient],
  });
}
