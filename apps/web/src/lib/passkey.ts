import {
  type PasskeyOwner,
  type WebAuthnAuth,
  webAuthnOwner,
} from "@session-firewall/sdk";
import {
  type Address,
  type Hex,
  concat,
  numberToHex,
  sha256,
  size,
  stringToHex,
} from "viem";
import {
  createWebAuthnCredential,
  toWebAuthnAccount,
} from "viem/account-abstraction";

/** What we keep about the passkey: its id and public key. The private key never leaves the authenticator. */
export type StoredPasskey = {
  id: string;
  /** Uncompressed P-256 public key, 0x04 || x || y (65 bytes). */
  publicKey: Hex;
};

/**
 * Create a passkey with the browser's own WebAuthn prompt (navigator.credentials.create):
 * ES256 (-7), user verification required, bound to this site's domain.
 */
export async function createPasskey(label: string): Promise<StoredPasskey> {
  const credential = await createWebAuthnCredential({
    name: label,
    rp: { id: window.location.hostname, name: "Session Firewall" },
  });
  const pk = credential.publicKey;
  const publicKey = size(pk) === 64 ? concat(["0x04", pk]) : pk;
  if (size(publicKey) !== 65)
    throw new Error("The authenticator returned an unexpected key type.");
  return { id: credential.id, publicKey };
}

/**
 * A gas-estimation stand-in with the same byte lengths as a real assertion from this origin.
 * The SDK replaces its signature scalars with zero, so it can never validate.
 */
export function stubAuthFor(origin: string, rpId: string): WebAuthnAuth {
  const authenticatorData = concat([
    sha256(stringToHex(rpId)),
    "0x05",
    numberToHex(1, { size: 4 }),
  ]);
  const challenge = bytesToBase64Url(new Uint8Array(32));
  const clientDataJSON = `{"type":"webauthn.get","challenge":"${challenge}","origin":"${origin}","crossOrigin":false}`;
  return {
    authenticatorData,
    clientDataJSON,
    challengeIndex: BigInt(clientDataJSON.indexOf('"challenge":')),
    typeIndex: BigInt(clientDataJSON.indexOf('"type":')),
    r: numberToHex(1, { size: 32 }),
    s: numberToHex(1, { size: 32 }),
  };
}

function bytesToBase64Url(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** The account owner for SDK calls: every signature is a fresh passkey prompt (D12 envelope). */
export function passkeyOwnerFor(
  passkey: StoredPasskey,
  validator: Address,
): PasskeyOwner {
  return webAuthnOwner({
    validator,
    credential: toWebAuthnAccount({
      credential: { id: passkey.id, publicKey: passkey.publicKey },
      rpId: window.location.hostname,
    }),
    stubAuth: stubAuthFor(window.location.origin, window.location.hostname),
  });
}

export function webAuthnSupported(): boolean {
  return (
    typeof window !== "undefined" &&
    window.isSecureContext &&
    typeof window.PublicKeyCredential === "function" &&
    typeof navigator.credentials?.create === "function"
  );
}
