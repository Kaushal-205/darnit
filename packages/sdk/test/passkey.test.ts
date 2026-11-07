import { decodeAbiParameters, hashMessage, numberToHex, zeroHash } from "viem";
import { describe, expect, it, vi } from "vitest";
import { testPasskey } from "../scripts/test-passkey.js";
import {
  encodeWebAuthnAuth,
  passkeyOwner,
  personalSignDigest,
  signatureEnvelopeAbi,
  typedContentDigest,
  webAuthnAuthAbi,
} from "../src/passkey.js";

const validator = "0x0000000000000000000000000000000000000021";
const domain = {
  account: "0x0000000000000000000000000000000000000042",
  chainId: 31337,
} as const;
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

describe("D12 transport", () => {
  it("uses OZ 5.6 WebAuthnAuth order and normalizes high-s", async () => {
    const key = testPasskey(validator);
    const auth = await key.assertion(zeroHash);
    const encoded = encodeWebAuthnAuth({
      ...auth,
      r: numberToHex(3, { size: 32 }),
      s: numberToHex(N - 1n, { size: 32 }),
    });
    const [got] = decodeAbiParameters(webAuthnAuthAbi, encoded);
    expect(got.r).toBe(numberToHex(3, { size: 32 }));
    expect(got.s).toBe(numberToHex(1, { size: 32 }));
    expect(got.authenticatorData).toBe(auth.authenticatorData);
    expect(got.challengeIndex).toBe(23n);
  });
  it("PersonalSign carries exact UTF-8 plaintext and signs the nested digest", async () => {
    const key = testPasskey(validator);
    const signAssertion = vi.fn(key.assertion);
    const owner = passkeyOwner({
      validator,
      x: key.x,
      y: key.y,
      signAssertion,
      stubAuth: await key.assertion(zeroHash),
    });
    const sig = await owner.signPersonalMessage(domain, "hello 🔥");
    const [env] = decodeAbiParameters(signatureEnvelopeAbi, sig);
    expect(env.kind).toBe(2);
    expect(env.data).toBe("0x68656c6c6f20f09f94a5");
    expect(signAssertion).toHaveBeenCalledWith(
      personalSignDigest(domain, "hello 🔥"),
    );
    expect(personalSignDigest(domain, "hello 🔥")).not.toBe(
      hashMessage("hello 🔥"),
    );
    const raw = await owner.signPersonalMessage(domain, { raw: "0x1234" });
    expect(decodeAbiParameters(signatureEnvelopeAbi, raw)[0].data).toBe(
      "0x1234",
    );
  });
  it("stub signatures decode but have invalid scalars", async () => {
    const key = testPasskey(validator);
    const [stub] = decodeAbiParameters(webAuthnAuthAbi, key.stubSignature);
    expect(stub.r).toBe(zeroHash);
    expect(stub.s).toBe(zeroHash);
  });
  it("rejects empty/misaligned typed fields and binds chain, account and content", () => {
    const c = {
      appDomainSeparator: zeroHash,
      contentsType: "Mail(uint256 id)",
      data: numberToHex(1, { size: 32 }),
    };
    expect(() => typedContentDigest(domain, { ...c, data: "0x" })).toThrow();
    expect(() => typedContentDigest(domain, { ...c, data: "0xff" })).toThrow();
    expect(typedContentDigest(domain, c)).not.toBe(
      typedContentDigest({ ...domain, chainId: 1 }, c),
    );
    expect(typedContentDigest(domain, c)).not.toBe(
      typedContentDigest(domain, { ...c, data: numberToHex(2, { size: 32 }) }),
    );
  });
});
