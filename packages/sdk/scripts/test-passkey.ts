/** Local software authenticator fixture. Never use this exported private key for a user account. */
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import {
  type Address,
  type Hex,
  concat,
  numberToHex,
  stringToHex,
  toHex,
} from "viem";
import { type WebAuthnAuth, passkeyOwner } from "../src/passkey.js";

export function testPasskey(
  validator: Address,
  allowedContentTypes: string[] = [],
) {
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  });
  const jwk = publicKey.export({ format: "jwk" });
  const x = toHex(Buffer.from(jwk.x as string, "base64url"));
  const y = toHex(Buffer.from(jwk.y as string, "base64url"));
  const sha256 = (data: Uint8Array) =>
    createHash("sha256").update(data).digest();
  const assertion = async (challenge: Hex): Promise<WebAuthnAuth> => {
    const authenticatorData = concat([
      toHex(sha256(Buffer.from("firewall.test"))),
      "0x05",
      numberToHex(1, { size: 4 }),
    ]);
    const clientDataJSON = JSON.stringify({
      type: "webauthn.get",
      challenge: Buffer.from(challenge.slice(2), "hex").toString("base64url"),
      origin: "https://firewall.test",
      crossOrigin: false,
    });
    const payload = Buffer.concat([
      Buffer.from(authenticatorData.slice(2), "hex"),
      sha256(Buffer.from(clientDataJSON)),
    ]);
    const sig = sign("sha256", payload, {
      key: privateKey,
      dsaEncoding: "ieee-p1363",
    });
    return {
      authenticatorData,
      clientDataJSON,
      challengeIndex: 23n,
      typeIndex: 1n,
      r: toHex(sig.subarray(0, 32)),
      s: toHex(sig.subarray(32, 64)),
    };
  };
  // Stub carries realistic lengths. Scalars are replaced with zero by passkeyOwner.
  const stubAuth: WebAuthnAuth = {
    r: numberToHex(1, { size: 32 }),
    s: numberToHex(1, { size: 32 }),
    challengeIndex: 23n,
    typeIndex: 1n,
    authenticatorData: concat([
      toHex(sha256(Buffer.from("firewall.test"))),
      "0x05",
      "0x00000001",
    ]),
    clientDataJSON: `{"type":"webauthn.get","challenge":"${Buffer.alloc(32).toString("base64url")}","origin":"https://firewall.test","crossOrigin":false}`,
  };
  return {
    ...passkeyOwner({
      validator,
      x,
      y,
      allowedContentTypes,
      signAssertion: assertion,
      stubAuth,
    }),
    x,
    y,
    assertion,
  };
}
