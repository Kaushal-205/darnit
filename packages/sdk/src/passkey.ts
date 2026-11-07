import {
  type Address,
  type Hex,
  type SignableMessage,
  concat,
  encodeAbiParameters,
  hashMessage,
  keccak256,
  numberToHex,
  size,
  slice,
  stringToHex,
  toHex,
  zeroHash,
} from "viem";
import type { WebAuthnAccount } from "viem/account-abstraction";
import type { FirewallAccount } from "./account.js";
import type { OwnerSigner } from "./owner.js";

const P256_N =
  0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const authComponents = [
  { name: "r", type: "bytes32" },
  { name: "s", type: "bytes32" },
  { name: "challengeIndex", type: "uint256" },
  { name: "typeIndex", type: "uint256" },
  { name: "authenticatorData", type: "bytes" },
  { name: "clientDataJSON", type: "string" },
] as const;
export const webAuthnAuthAbi = [
  { type: "tuple", components: authComponents },
] as const;
export const signatureEnvelopeAbi = [
  {
    type: "tuple",
    components: [
      { name: "kind", type: "uint8" },
      { name: "appDomainSeparator", type: "bytes32" },
      { name: "contentsType", type: "string" },
      { name: "data", type: "bytes" },
      { name: "auth", type: "tuple", components: authComponents },
    ],
  },
] as const;

/** OpenZeppelin WebAuthnAuth, in exactly the tuple order used by FirewallOwnerValidator. */
export type WebAuthnAuth = {
  authenticatorData: Hex;
  clientDataJSON: string;
  challengeIndex: bigint;
  typeIndex: bigint;
  r: Hex;
  s: Hex;
};
export type AccountDomain = { account: Address; chainId: number };
/** EIP-712 encodeData excludes the leading type hash. Hash dynamic fields before encoding them. */
export type FirewallTypedContent = {
  appDomainSeparator: Hex;
  contentsType: string;
  data: Hex;
};
export type PasskeyOwner = OwnerSigner & {
  signPersonalMessage(
    domain: AccountDomain,
    message: SignableMessage,
  ): Promise<Hex>;
  signTypedContent(
    domain: AccountDomain,
    content: FirewallTypedContent,
  ): Promise<Hex>;
};

const hashText = (text: string) => keccak256(stringToHex(text));
const eip712Digest = (separator: Hex, structHash: Hex) =>
  keccak256(concat(["0x1901", separator, structHash]));

export function firewallOwnerDomainSeparator({
  account,
  chainId,
}: AccountDomain): Hex {
  return keccak256(
    encodeAbiParameters(
      [
        { type: "bytes32" },
        { type: "bytes32" },
        { type: "bytes32" },
        { type: "uint256" },
        { type: "address" },
      ],
      [
        hashText(
          "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
        ),
        hashText("FirewallOwnerValidator"),
        hashText("1"),
        BigInt(chainId),
        account,
      ],
    ),
  );
}

export function personalSignDigest(
  domain: AccountDomain,
  message: SignableMessage,
): Hex {
  return eip712Digest(
    firewallOwnerDomainSeparator(domain),
    keccak256(
      encodeAbiParameters(
        [{ type: "bytes32" }, { type: "bytes32" }],
        [hashText("PersonalSign(bytes prefixed)"), hashMessage(message)],
      ),
    ),
  );
}

export function typedContentDigest(
  domain: AccountDomain,
  content: FirewallTypedContent,
): Hex {
  const name = /^([A-Za-z_][A-Za-z0-9_]*)\(/.exec(content.contentsType)?.[1];
  if (!name || size(content.data) === 0 || size(content.data) % 32 !== 0)
    throw new Error(
      "Expected an EIP-712 contentsType and nonempty, word-aligned encodeData",
    );
  const contents = keccak256(
    concat([hashText(content.contentsType), content.data]),
  );
  const typeHash = hashText(
    `TypedDataSign(${name} contents,string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)${content.contentsType}`,
  );
  return eip712Digest(
    content.appDomainSeparator,
    keccak256(
      encodeAbiParameters(
        [
          { type: "bytes32" },
          { type: "bytes32" },
          { type: "bytes32" },
          { type: "bytes32" },
          { type: "uint256" },
          { type: "address" },
          { type: "bytes32" },
        ],
        [
          typeHash,
          contents,
          hashText("FirewallOwnerValidator"),
          hashText("1"),
          BigInt(domain.chainId),
          domain.account,
          zeroHash,
        ],
      ),
    ),
  );
}

export function encodeWebAuthnAuth(auth: WebAuthnAuth): Hex {
  // P256.verify requires low-s; authenticators may return either form.
  const s = BigInt(auth.s);
  if (
    s === 0n ||
    s >= P256_N ||
    BigInt(auth.r) === 0n ||
    BigInt(auth.r) >= P256_N
  )
    throw new Error("Invalid P-256 signature scalar");
  return encodeAbiParameters(webAuthnAuthAbi, [
    { ...auth, s: numberToHex(s > P256_N / 2n ? P256_N - s : s, { size: 32 }) },
  ]);
}

/** D12 owner: user ops sign their hash directly; ERC-1271 signs a nested digest and carries its plaintext/fields. */
export function passkeyOwner(opts: {
  validator: Address;
  x: Hex;
  y: Hex;
  allowedContentTypes?: readonly string[];
  signAssertion: (challenge: Hex) => Promise<WebAuthnAuth>;
  /** Same byte shape as a real assertion, for gas estimation; signature scalars are made invalid. */
  stubAuth: WebAuthnAuth;
}): PasskeyOwner {
  const normalized = async (digest: Hex) => {
    const auth = await opts.signAssertion(digest);
    // Reuse the scalar validation/normalization for both transport forms.
    const s = BigInt(auth.s);
    encodeWebAuthnAuth(auth);
    return {
      ...auth,
      s: numberToHex(s > P256_N / 2n ? P256_N - s : s, { size: 32 }),
    };
  };
  return {
    validator: opts.validator,
    validatorInitData: encodeAbiParameters(
      [{ type: "bytes32" }, { type: "bytes32" }, { type: "string[]" }],
      [opts.x, opts.y, opts.allowedContentTypes ?? []],
    ),
    signUserOpHash: async (hash) => encodeWebAuthnAuth(await normalized(hash)),
    stubSignature: encodeAbiParameters(webAuthnAuthAbi, [
      { ...opts.stubAuth, r: zeroHash, s: zeroHash },
    ]),
    signPersonalMessage: async (domain, message) => {
      const data =
        typeof message === "string"
          ? stringToHex(message)
          : typeof message.raw === "string"
            ? message.raw
            : toHex(message.raw);
      return encodeAbiParameters(signatureEnvelopeAbi, [
        {
          kind: 2,
          appDomainSeparator: zeroHash,
          contentsType: "",
          data,
          auth: await normalized(personalSignDigest(domain, message)),
        },
      ]);
    },
    signTypedContent: async (domain, content) =>
      encodeAbiParameters(signatureEnvelopeAbi, [
        {
          kind: 1,
          ...content,
          auth: await normalized(typedContentDigest(domain, content)),
        },
      ]),
    label: "passkey",
  };
}

/** Adapter for viem.toWebAuthnAccount. Its credential request uses userVerification="required". */
export function webAuthnOwner(opts: {
  validator: Address;
  credential: WebAuthnAccount;
  stubAuth: WebAuthnAuth;
  allowedContentTypes?: readonly string[];
}): PasskeyOwner {
  const publicKey = opts.credential.publicKey;
  if (size(publicKey) !== 65 || slice(publicKey, 0, 1) !== "0x04")
    throw new Error("Expected an uncompressed P-256 public key");
  return passkeyOwner({
    ...opts,
    x: slice(publicKey, 1, 33),
    y: slice(publicKey, 33, 65),
    signAssertion: async (challenge) => {
      const { signature, webauthn } = await opts.credential.sign({
        hash: challenge,
      });
      return {
        authenticatorData: webauthn.authenticatorData,
        clientDataJSON: webauthn.clientDataJSON,
        challengeIndex: jsonKeyOffset(webauthn.clientDataJSON, "challenge"),
        typeIndex: jsonKeyOffset(webauthn.clientDataJSON, "type"),
        r: slice(signature, 0, 32),
        s: slice(signature, 32, 64),
      };
    },
  });
}

function jsonKeyOffset(json: string, key: string): bigint {
  const at = json.indexOf(`"${key}":`);
  if (at < 0) throw new Error(`WebAuthn response lacks ${key}`);
  return BigInt(size(stringToHex(json.slice(0, at))));
}

/** Safe7579 routes ERC-1271 signatures using the leading validator address. */
export async function signFirewallMessage(
  account: FirewallAccount,
  message: SignableMessage,
): Promise<Hex> {
  const owner = account.owner as Partial<PasskeyOwner>;
  if (!owner.signPersonalMessage)
    throw new Error("Owner does not support D12 PersonalSign");
  return concat([
    account.owner.validator,
    await owner.signPersonalMessage(
      {
        account: account.address,
        chainId: account.client.publicClient.chain.id,
      },
      message,
    ),
  ]);
}

export async function signFirewallTypedContent(
  account: FirewallAccount,
  content: FirewallTypedContent,
): Promise<Hex> {
  const owner = account.owner as Partial<PasskeyOwner>;
  if (!owner.signTypedContent)
    throw new Error("Owner does not support D12 TypedDataSign");
  return concat([
    account.owner.validator,
    await owner.signTypedContent(
      {
        account: account.address,
        chainId: account.client.publicClient.chain.id,
      },
      content,
    ),
  ]);
}
