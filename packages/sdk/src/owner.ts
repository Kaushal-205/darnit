import type { Address, Hex, LocalAccount } from "viem";
import { BASE_SEPOLIA } from "./addresses.js";
import {
  DUMMY_ECDSA_SIGNATURE,
  encodeOwnableValidatorData,
} from "./encoding.js";

/**
 * The account owner, as seen by the SDK: an ERC-7579 validator module plus a way to sign the
 * ERC-4337 user operation hash for it. Every owner action is a user operation validated by
 * `validator` (selected via the nonce key), and then checked by the firewall hook like any other.
 *
 * A WebAuthn / passkey owner (FirewallOwnerValidator, docs/decisions.md D12) implements the same
 * interface: `validator` = its address, `validatorInitData` = its onInstall data (credential id,
 * public key), `signUserOpHash` = run navigator.credentials.get over the hash and encode the assertion
 * the way the validator expects.
 */
export interface OwnerSigner {
  /** Validator module that checks owner signatures. Installed at account creation. */
  readonly validator: Address;
  /** `onInstall` data for `validator`. */
  readonly validatorInitData: Hex;
  /** Return `userOp.signature` for this user operation hash. */
  signUserOpHash(userOpHash: Hex): Promise<Hex>;
  /** A signature of the right shape for gas estimation; it must not be valid. */
  readonly stubSignature: Hex;
  /** Optional label for logs. */
  readonly label?: string;
}

/**
 * ECDSA owner through Rhinestone's OwnableValidator (1-of-1). OwnableValidator.validateUserOp checks
 * an ECDSA signature over the EIP-191 hash of the user operation hash, so we `signMessage({ raw })`.
 */
export function ecdsaOwner(
  signer: LocalAccount,
  opts: { validator?: Address } = {},
): OwnerSigner & { address: Address } {
  return {
    address: signer.address,
    validator: opts.validator ?? BASE_SEPOLIA.ownableValidator,
    validatorInitData: encodeOwnableValidatorData([signer.address]),
    signUserOpHash: (userOpHash) =>
      signer.signMessage({ message: { raw: userOpHash } }),
    stubSignature: DUMMY_ECDSA_SIGNATURE,
    label: `ecdsa:${signer.address}`,
  };
}
