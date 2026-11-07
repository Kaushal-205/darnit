import { p256 } from "@noble/curves/p256";
import type { WebAuthnAuth } from "@session-firewall/sdk";
import {
  type Hex,
  bytesToHex,
  concat,
  hexToBytes,
  numberToHex,
  size,
  stringToHex,
  sha256 as viemSha256,
} from "viem";

/**
 * WebAuthn for the exit page, written out in full so it is easy to audit.
 *
 * The contract (FirewallOwnerValidator, docs/decisions.md V4) checks the P-256 signature over
 * authenticatorData || sha256(clientDataJSON), that clientDataJSON has type "webauthn.get" and the
 * user-operation hash as challenge, and the user-presence and user-verification flags. It does not check
 * the origin or the RP ID hash: binding a passkey to a website is done by the browser. That is why a
 * passkey made on the app's website cannot be used from this page on another origin (the browser
 * refuses), and why an assertion made outside a browser (a security key driven by a command-line tool)
 * is accepted.
 */

const sha256 = (b: Uint8Array) => viemSha256(b, "bytes");

const P256_N =
  0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

const b64url = (bytes: Uint8Array) =>
  btoa(String.fromCharCode(...bytes))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
const b64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));

export function fromBase64(text: string): Uint8Array {
  const s = text.trim().replaceAll("-", "+").replaceAll("_", "/");
  const padded = s + "=".repeat((4 - (s.length % 4)) % 4);
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}

/** Hex (0x...), base64 or base64url bytes. */
export function looseBytes(text: string): Uint8Array {
  const t = text.trim();
  if (/^0x([0-9a-fA-F]{2})*$/.test(t)) return hexToBytes(t as Hex);
  return fromBase64(t);
}

/** Byte offset of `"key":` in the UTF-8 encoding of json (what the contract indexes). */
export function jsonKeyOffset(json: string, key: string): bigint {
  const at = json.indexOf(`"${key}":`);
  if (at < 0) throw new Error(`The signature data lacks "${key}".`);
  return BigInt(size(stringToHex(json.slice(0, at))));
}

/** ASN.1 DER ECDSA-Sig-Value -> (r, s) as 32-byte hex. Raw 64-byte r||s is accepted too. */
export function parseSignature(sig: Uint8Array): { r: Hex; s: Hex } {
  if (sig.length === 64)
    return {
      r: bytesToHex(sig.slice(0, 32)),
      s: bytesToHex(sig.slice(32)),
    };
  let i = 0;
  const expect = (b: number) => {
    if (sig[i++] !== b) throw new Error("The signature is not in DER form.");
  };
  const len = () => {
    let n = sig[i++];
    if (n & 0x80) {
      const k = n & 0x7f;
      n = 0;
      for (let j = 0; j < k; j++) n = (n << 8) | sig[i++];
    }
    return n;
  };
  expect(0x30);
  len();
  const int = () => {
    expect(0x02);
    const n = len();
    let v = sig.slice(i, i + n);
    i += n;
    while (v.length > 32 && v[0] === 0) v = v.slice(1);
    if (v.length > 32) throw new Error("Signature number too long.");
    const out = new Uint8Array(32);
    out.set(v, 32 - v.length);
    return bytesToHex(out);
  };
  const r = int();
  const s = int();
  return { r, s };
}

/** Assemble the auth tuple the validator expects. */
export function toAuth(
  authenticatorData: Uint8Array,
  clientDataJSON: string,
  signature: Uint8Array,
): WebAuthnAuth {
  const { r, s } = parseSignature(signature);
  return {
    authenticatorData: bytesToHex(authenticatorData),
    clientDataJSON,
    challengeIndex: jsonKeyOffset(clientDataJSON, "challenge"),
    typeIndex: jsonKeyOffset(clientDataJSON, "type"),
    r,
    s,
  };
}

/** Check an assertion the way the contract will, before paying for a transaction that would fail. */
export function verifyAuth(
  auth: WebAuthnAuth,
  challenge: Hex,
  key: { x: Hex; y: Hex },
): { ok: true } | { ok: false; reason: string } {
  let client: { type?: string; challenge?: string };
  try {
    client = JSON.parse(auth.clientDataJSON);
  } catch {
    return { ok: false, reason: "The signature data is not valid JSON." };
  }
  if (client.type !== "webauthn.get")
    return { ok: false, reason: 'The signature is not a "sign in" assertion.' };
  if (client.challenge !== b64url(hexToBytes(challenge)))
    return {
      ok: false,
      reason: "The signature is for a different request. Sign again.",
    };
  const authData = hexToBytes(auth.authenticatorData);
  if (authData.length < 37)
    return { ok: false, reason: "The authenticator data is too short." };
  const flags = authData[32];
  if (!(flags & 0x01) || !(flags & 0x04))
    return {
      ok: false,
      reason:
        "The key did not confirm it was you (PIN, fingerprint or face). Sign again and complete that step.",
    };
  const message = concat([
    auth.authenticatorData,
    bytesToHex(sha256(new TextEncoder().encode(auth.clientDataJSON))),
  ]);
  const r = BigInt(auth.r);
  let s = BigInt(auth.s);
  if (s > P256_N / 2n) s = P256_N - s;
  const pub = concat(["0x04", key.x, key.y]);
  const valid = p256.verify(
    concat([numberToHex(r, { size: 32 }), numberToHex(s, { size: 32 })]).slice(
      2,
    ),
    sha256(hexToBytes(message)),
    pub.slice(2),
    { prehash: false, lowS: false },
  );
  return valid
    ? { ok: true }
    : {
        ok: false,
        reason:
          "This passkey is not the selected key of this account. Pick the other key, or use the passkey that belongs to it.",
      };
}

/** Why WebAuthn is unavailable here, or undefined when it can be tried. */
export function webAuthnUnavailableReason(): string | undefined {
  if (location.protocol === "file:")
    return "Browsers do not allow passkeys on a page opened as a file. Open this page from a local web server (http://localhost) or use “Another device or tool”.";
  if (!window.isSecureContext)
    return "Browsers allow passkeys only on https:// pages or on http://localhost.";
  if (!window.PublicKeyCredential || !navigator.credentials)
    return "This browser does not support passkeys.";
  return undefined;
}

/** Sign `challenge` (the user operation hash) with a discoverable passkey for this page's site. */
export async function browserAssertion(
  challenge: Hex,
  rpId: string = location.hostname,
): Promise<WebAuthnAuth> {
  const why = webAuthnUnavailableReason();
  if (why) throw new Error(why);
  let cred: Credential | null;
  try {
    cred = await navigator.credentials.get({
      publicKey: {
        challenge: new Uint8Array(hexToBytes(challenge)),
        rpId,
        userVerification: "required",
        allowCredentials: [],
        timeout: 180_000,
      },
    });
  } catch (e) {
    const name = (e as Error)?.name;
    if (name === "NotAllowedError")
      throw new Error(
        `No passkey was used. Either you cancelled, or this browser has no passkey for “${rpId}”. A passkey made on another website cannot be used here.`,
      );
    if (name === "SecurityError")
      throw new Error(
        `The browser refused to use passkeys for “${rpId}” on this page (${(e as Error).message}).`,
      );
    throw e;
  }
  if (!cred) throw new Error("No passkey was used.");
  const res = (cred as PublicKeyCredential)
    .response as AuthenticatorAssertionResponse;
  return toAuth(
    new Uint8Array(res.authenticatorData),
    new TextDecoder().decode(res.clientDataJSON),
    new Uint8Array(res.signature),
  );
}

/** What an external signer (e.g. libfido2's fido2-assert with a security key) needs to sign. */
export function externalRequest(challenge: Hex, rpId: string) {
  const origin = `https://${rpId}`;
  const clientDataJSON = JSON.stringify({
    type: "webauthn.get",
    challenge: b64url(hexToBytes(challenge)),
    origin,
    crossOrigin: false,
  });
  const clientDataHash = b64(sha256(new TextEncoder().encode(clientDataJSON)));
  return { rpId, clientDataJSON, clientDataHash };
}

/**
 * Parse what the external signer returned: JSON {authenticatorData, signature, clientDataJSON?} with
 * hex/base64 values, or fido2-assert output lines (client data hash, rp id, authdata, signature, ...).
 * fido2-assert prints authdata CBOR-wrapped; the byte-string header is removed here.
 */
export function parseExternalAssertion(
  text: string,
  defaultClientDataJSON: string,
): WebAuthnAuth {
  const t = text.trim();
  let authData: Uint8Array;
  let signature: Uint8Array;
  let clientDataJSON = defaultClientDataJSON;
  if (t.startsWith("{")) {
    const j = JSON.parse(t) as Record<string, string>;
    if (!j.authenticatorData || !j.signature)
      throw new Error("Expected authenticatorData and signature.");
    authData = looseBytes(j.authenticatorData);
    signature = looseBytes(j.signature);
    if (j.clientDataJSON)
      clientDataJSON = j.clientDataJSON.trim().startsWith("{")
        ? j.clientDataJSON
        : new TextDecoder().decode(looseBytes(j.clientDataJSON));
  } else {
    // fido2-assert -G output: clientDataHash, rp id, authdata, signature [, user id ...]
    const lines = t.split(/\r?\n/).map((l) => l.trim());
    if (lines.length < 4)
      throw new Error("Paste the four or more lines fido2-assert printed.");
    authData = looseBytes(lines[2]);
    signature = looseBytes(lines[3]);
  }
  return toAuth(unwrapCborBytes(authData), clientDataJSON, signature);
}

/** Strip a CBOR byte-string header (major type 2) if present. */
export function unwrapCborBytes(b: Uint8Array): Uint8Array {
  const major = b[0] >> 5;
  const info = b[0] & 0x1f;
  if (major !== 2) return b;
  let len: number;
  let head: number;
  if (info < 24) [len, head] = [info, 1];
  else if (info === 24) [len, head] = [b[1], 2];
  else if (info === 25) [len, head] = [(b[1] << 8) | b[2], 3];
  else return b;
  return head + len === b.length ? b.slice(head) : b;
}

/** Make a new recovery passkey for this page's site and return its public key. */
export async function createRecoveryPasskey(
  label: string,
): Promise<{ x: Hex; y: Hex; rpId: string; credentialId: string }> {
  const why = webAuthnUnavailableReason();
  if (why) throw new Error(why);
  const rpId = location.hostname;
  const cred = (await navigator.credentials.create({
    publicKey: {
      rp: { id: rpId, name: "Session Firewall exit page" },
      user: {
        id: crypto.getRandomValues(new Uint8Array(16)),
        name: label,
        displayName: label,
      },
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      authenticatorSelection: {
        residentKey: "required",
        userVerification: "required",
      },
      timeout: 180_000,
    },
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error("No passkey was created.");
  const res = cred.response as AuthenticatorAttestationResponse;
  const spki = res.getPublicKey?.();
  if (!spki || res.getPublicKeyAlgorithm?.() !== -7)
    throw new Error("The authenticator did not return a P-256 (ES256) key.");
  const point = new Uint8Array(spki).slice(-65);
  if (point[0] !== 0x04) throw new Error("Unexpected public key format.");
  return {
    x: bytesToHex(point.slice(1, 33)),
    y: bytesToHex(point.slice(33)),
    rpId,
    credentialId: b64url(new Uint8Array(cred.rawId)),
  };
}

/** A stub with the byte lengths of a real assertion from this site, for gas estimation. */
export function stubAuth(rpId: string): WebAuthnAuth {
  const clientDataJSON = externalRequest(
    `0x${"00".repeat(32)}`,
    rpId,
  ).clientDataJSON;
  return {
    authenticatorData: `0x${"11".repeat(32)}0500000001`,
    clientDataJSON,
    challengeIndex: jsonKeyOffset(clientDataJSON, "challenge"),
    typeIndex: jsonKeyOffset(clientDataJSON, "type"),
    r: numberToHex(1, { size: 32 }),
    s: numberToHex(1, { size: 32 }),
  };
}
