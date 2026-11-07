import { p256 } from "@noble/curves/p256";
import { bytesToHex, concat, hexToBytes, sha256, toHex } from "viem";
import { describe, expect, it } from "vitest";
import {
  externalRequest,
  jsonKeyOffset,
  parseExternalAssertion,
  parseSignature,
  toAuth,
  unwrapCborBytes,
  verifyAuth,
} from "../src/webauthn.js";

const priv = p256.utils.randomPrivateKey();
const pub = p256.getPublicKey(priv, false);
const key = { x: bytesToHex(pub.slice(1, 33)), y: bytesToHex(pub.slice(33)) };
const challenge = `0x${"ab".repeat(32)}` as const;
const authData = hexToBytes(
  concat([sha256(toHex("localhost")), "0x05", "0x00000001"]),
);

function signAssertion(clientDataJSON: string, data = authData) {
  const msg = concat([bytesToHex(data), sha256(toHex(clientDataJSON))]);
  return p256.sign(hexToBytes(sha256(msg)), priv, { prehash: false });
}

describe("signature parsing", () => {
  it("parses DER and raw r||s identically", () => {
    const { clientDataJSON } = externalRequest(challenge, "localhost");
    const sig = signAssertion(clientDataJSON);
    const der = parseSignature(sig.toDERRawBytes());
    const raw = parseSignature(sig.toCompactRawBytes());
    expect(der).toEqual(raw);
    expect(BigInt(der.r)).toBe(sig.r);
    expect(BigInt(der.s)).toBe(sig.s);
  });

  it("rejects non-DER input", () => {
    expect(() => parseSignature(new Uint8Array([1, 2, 3]))).toThrow(/DER/);
  });

  it("indexes JSON keys by UTF-8 byte offset", () => {
    expect(jsonKeyOffset('{"type":"x","challenge":"y"}', "type")).toBe(1n);
    expect(jsonKeyOffset('{"é":1,"type":"x"}', "type")).toBe(8n);
  });
});

describe("verifyAuth (what the contract checks)", () => {
  const { clientDataJSON } = externalRequest(challenge, "localhost");
  const sig = signAssertion(clientDataJSON);
  const auth = toAuth(authData, clientDataJSON, sig.toDERRawBytes());

  it("accepts a correct assertion, high or low s", () => {
    expect(verifyAuth(auth, challenge, key)).toEqual({ ok: true });
    const highS = p256.CURVE.n - sig.s;
    expect(
      verifyAuth({ ...auth, s: toHex(highS, { size: 32 }) }, challenge, key),
    ).toEqual({ ok: true });
  });

  it("refuses another key, another challenge, or missing user verification", () => {
    const other = p256.getPublicKey(p256.utils.randomPrivateKey(), false);
    const otherKey = {
      x: bytesToHex(other.slice(1, 33)),
      y: bytesToHex(other.slice(33)),
    };
    expect(verifyAuth(auth, challenge, otherKey).ok).toBe(false);
    expect(verifyAuth(auth, `0x${"cd".repeat(32)}`, key).ok).toBe(false);
    const noUv = authData.slice();
    noUv[32] = 0x01;
    const s2 = signAssertion(clientDataJSON, noUv);
    const r = verifyAuth(
      toAuth(noUv, clientDataJSON, s2.toDERRawBytes()),
      challenge,
      key,
    );
    expect(r.ok).toBe(false);
  });
});

describe("external signer (fido2-assert)", () => {
  it("builds the request and parses CBOR-wrapped fido2-assert output", () => {
    const req = externalRequest(challenge, "app.example");
    expect(JSON.parse(req.clientDataJSON)).toMatchObject({
      type: "webauthn.get",
      challenge: Buffer.from(hexToBytes(challenge)).toString("base64url"),
    });
    const sig = signAssertion(req.clientDataJSON);
    const cborAuthData = new Uint8Array([0x58, authData.length, ...authData]);
    const out = [
      req.clientDataHash,
      req.rpId,
      Buffer.from(cborAuthData).toString("base64"),
      Buffer.from(sig.toDERRawBytes()).toString("base64"),
      "dXNlcg==",
    ].join("\n");
    const auth = parseExternalAssertion(out, req.clientDataJSON);
    expect(auth.authenticatorData).toBe(bytesToHex(authData));
    expect(verifyAuth(auth, challenge, key)).toEqual({ ok: true });
  });

  it("parses JSON with hex values", () => {
    const req = externalRequest(challenge, "localhost");
    const sig = signAssertion(req.clientDataJSON);
    const auth = parseExternalAssertion(
      JSON.stringify({
        authenticatorData: bytesToHex(authData),
        signature: bytesToHex(sig.toCompactRawBytes()),
      }),
      req.clientDataJSON,
    );
    expect(verifyAuth(auth, challenge, key)).toEqual({ ok: true });
  });

  it("leaves raw authenticator data alone", () => {
    expect(unwrapCborBytes(authData)).toEqual(authData);
  });
});
