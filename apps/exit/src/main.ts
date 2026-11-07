import type { WebAuthnAuth } from "@session-firewall/sdk";
import {
  type Address,
  type Hex,
  formatUnits,
  getAddress,
  isAddress,
  isHex,
} from "viem";
import { assetKey, decimalsOf, parseAmount, planExit } from "./calls.js";
import { lockConnections, parseEndpoint } from "./net.js";
import {
  type AccountSnapshot,
  type Asset,
  type Client,
  readAccount,
} from "./reads.js";
import { queueRecoveryInstall, recoveryInitData } from "./recovery.js";
import {
  ENTRY_POINT_V07,
  type Submitter,
  sendExit,
  userClient,
} from "./send.js";
import {
  browserAssertion,
  createRecoveryPasskey,
  externalRequest,
  parseExternalAssertion,
  webAuthnUnavailableReason,
} from "./webauthn.js";

const $ = <T extends HTMLElement = HTMLElement>(id: string) => {
  const el = document.getElementById(id);
  if (!el) throw new Error(`missing #${id}`);
  return el as T;
};
const input = (id: string) => $<HTMLInputElement>(id);
const radio = (name: string) =>
  (
    document.querySelector(
      `input[name="${name}"]:checked`,
    ) as HTMLInputElement | null
  )?.value;

function status(id: string, text: string, kind: "" | "bad" | "good" = "") {
  const el = $(id);
  el.textContent = text;
  el.className = `status ${kind}`;
}
const errorText = (e: unknown) =>
  e instanceof Error ? e.message.split("\n\nRequest Arguments")[0] : String(e);

type Session = {
  client: Client;
  rpcUrl: string;
  chainId: number;
  entryPoint: Address;
  submitter: Submitter;
  account: Address;
  extraShareIds: bigint[];
  snap?: AccountSnapshot;
};
let session: Session | undefined;

// ------------------------------------------------------------------ setup

input("entry-point").value = ENTRY_POINT_V07;
input("external-rpid").value = location.hostname || "";
{
  const why = webAuthnUnavailableReason();
  $("origin-note").textContent = why
    ? `Opened from ${location.protocol === "file:" ? "a file" : location.origin}. ${why}`
    : `Opened from ${location.origin}. Passkeys made for “${location.hostname}” can sign here.`;
}
for (const el of document.querySelectorAll<HTMLInputElement>(
  'input[name="submit"]',
))
  el.addEventListener("change", () => {
    const eoa = radio("submit") === "eoa";
    $("bundler-field").hidden = eoa;
    $("eoa-field").hidden = !eoa;
  });

// ------------------------------------------------------------------ 1. connect

$("connect-btn").addEventListener("click", async () => {
  const btn = $<HTMLButtonElement>("connect-btn");
  btn.disabled = true;
  try {
    session = connectFromForm();
    status("connect-status", "Reading your account…");
    const remoteChain = await session.client.getChainId();
    if (remoteChain !== session.chainId)
      throw new Error(
        `The network address belongs to network ${remoteChain}, not ${session.chainId}. Check both.`,
      );
    await refresh();
    status("connect-status", "Connected.", "good");
  } catch (e) {
    status("connect-status", errorText(e), "bad");
  } finally {
    btn.disabled = false;
  }
});

function connectFromForm(): Session {
  const rpc = parseEndpoint(input("rpc").value, "network");
  const chainId = Number(input("chain-id").value.trim());
  if (!Number.isSafeInteger(chainId) || chainId <= 0)
    throw new Error("The network number must be a whole number.");
  const accountText = input("account").value.trim();
  if (!isAddress(accountText, { strict: false }))
    throw new Error("The account address is not valid.");
  const entryText = input("entry-point").value.trim();
  if (!isAddress(entryText, { strict: false }))
    throw new Error("The EntryPoint address is not valid.");
  const extraShareIds = input("share-ids")
    .value.split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) => {
      if (!/^\d+$/.test(s)) throw new Error(`"${s}" is not a share id.`);
      return BigInt(s);
    });

  let submitter: Submitter;
  const origins = [rpc.origin];
  if (radio("submit") === "eoa") {
    const key = input("eoa-key").value.trim();
    if (!isHex(key) || key.length !== 66)
      throw new Error("The wallet key must be 0x followed by 64 hex digits.");
    submitter = { kind: "eoa", privateKey: key };
  } else {
    const bundler = parseEndpoint(input("bundler").value, "bundler");
    origins.push(bundler.origin);
    submitter = { kind: "bundler", bundlerUrl: bundler.url };
  }
  // From here on the browser refuses every other connection (see net.ts).
  lockConnections(origins);
  return {
    client: userClient(chainId, rpc.url),
    rpcUrl: rpc.url,
    chainId,
    entryPoint: getAddress(entryText),
    submitter,
    account: getAddress(accountText),
    extraShareIds,
  };
}

// ------------------------------------------------------------------ 2. account view

async function refresh() {
  if (!session) return;
  const snap = await readAccount(
    session.client,
    session.account,
    session.extraShareIds,
  );
  session.snap = snap;
  renderAccount(snap);
}

const fmt = (a: Asset) =>
  `${formatUnits(a.balance, decimalsOf(a))} ${a.kind === "token" ? a.symbol : "shares"}`;
const short = (a: string) => `${a.slice(0, 6)}…${a.slice(-4)}`;

function renderAccount(snap: AccountSnapshot) {
  $("account-section").hidden = false;
  $("move-section").hidden = false;
  $("account-state").textContent = [
    snap.frozen
      ? "Trading is paused on this account."
      : "Trading is not paused.",
    `Hourly spending limit left: ${formatUnits(snap.availableBudget, 6)} of ${formatUnits(snap.hourlyCap, 6)} USDC.`,
    "Moving funds to a trusted destination never uses the limit and works while trading is paused.",
    `ETH for network fees: ${formatUnits(snap.ethBalance, 18)}.`,
  ].join(" ");

  const tbody = $("balances").querySelector("tbody") as HTMLElement;
  tbody.replaceChildren();
  const assets: Asset[] = [...snap.tokens, ...snap.shares];
  for (const a of assets) {
    const tr = document.createElement("tr");
    tr.dataset.asset = assetKey(a);
    const name = document.createElement("td");
    name.textContent =
      a.kind === "token" ? `${a.symbol} (${short(a.token)})` : a.label;
    const amount = document.createElement("td");
    amount.textContent = fmt(a);
    tr.append(name, amount);
    tbody.append(tr);
  }
  if (assets.length === 0) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.textContent = "No balances found.";
    tr.append(td);
    tbody.append(tr);
  }

  $("destinations").replaceChildren(
    ...snap.destinations.map((d) => {
      const li = document.createElement("li");
      li.textContent = d;
      return li;
    }),
  );

  const keys = $("keys");
  keys.replaceChildren();
  snap.validators.forEach((v, i) => {
    const label = document.createElement("label");
    label.className = "inline";
    const r = document.createElement("input");
    r.type = "radio";
    r.name = "key";
    r.value = v.address;
    r.checked = i === 0;
    label.append(
      r,
      ` Passkey ${i + 1}: key contract ${short(v.address)}, public key ${short(v.x)}`,
    );
    keys.append(label);
  });
  if (snap.validators.length === 0)
    keys.textContent = "No passkey is installed on this account.";
  else if (snap.validators.length > 1) {
    const p = document.createElement("small");
    p.textContent =
      "Pick the key whose passkey you will use. The newest key is listed first.";
    keys.append(p);
  }

  const assetSel = $<HTMLSelectElement>("asset");
  const previous = assetSel.value;
  assetSel.replaceChildren(
    ...assets.map(
      (a) =>
        new Option(
          `${fmt(a)} — ${a.kind === "token" ? a.symbol : a.label}`,
          assetKey(a),
        ),
    ),
    new Option("Everything listed above", "all"),
  );
  if ([...assetSel.options].some((o) => o.value === previous))
    assetSel.value = previous;
  const destSel = $<HTMLSelectElement>("destination");
  const prevDest = destSel.value;
  destSel.replaceChildren(...snap.destinations.map((d) => new Option(d, d)));
  if (snap.destinations.includes(prevDest as Address)) destSel.value = prevDest;
}

// ------------------------------------------------------------------ 3. move funds

let pendingExternal:
  | {
      resolve: (a: WebAuthnAuth) => void;
      reject: (e: Error) => void;
      clientDataJSON: string;
    }
  | undefined;

function externalSign(hash: Hex): Promise<WebAuthnAuth> {
  const rpId = input("external-rpid").value.trim();
  if (!rpId)
    return Promise.reject(
      new Error("Type the website name your key was made for."),
    );
  const req = externalRequest(hash, rpId);
  $("external").hidden = false;
  $("external-request").textContent =
    `${req.clientDataHash}\n${req.rpId}\n\n(Input file: line 1 is the client data hash, line 2 the website name. Add your credential id in base64 as line 3 only if your key needs it.)\n\nThe page signs this client data, which it keeps:\n${req.clientDataJSON}`;
  $<HTMLTextAreaElement>("external-response").value = "";
  return new Promise((resolve, reject) => {
    pendingExternal = { resolve, reject, clientDataJSON: req.clientDataJSON };
  });
}

$("external-btn").addEventListener("click", () => {
  if (!pendingExternal) return;
  try {
    const auth = parseExternalAssertion(
      $<HTMLTextAreaElement>("external-response").value,
      pendingExternal.clientDataJSON,
    );
    pendingExternal.resolve(auth);
    pendingExternal = undefined;
    $("external").hidden = true;
  } catch (e) {
    status("move-status", errorText(e), "bad");
  }
});

$("move-btn").addEventListener("click", async () => {
  const btn = $<HTMLButtonElement>("move-btn");
  if (!session?.snap) return;
  const s = session;
  const snap = session.snap;
  btn.disabled = true;
  $("result").hidden = true;
  try {
    const key = radio("key");
    const validator = snap.validators.find((v) => v.address === key);
    if (!validator) throw new Error("Pick the key you will sign with.");
    const which = $<HTMLSelectElement>("asset").value;
    const asset =
      which === "all"
        ? "all"
        : [...snap.tokens, ...snap.shares].find((a) => assetKey(a) === which);
    if (!asset) throw new Error("Pick what to move.");
    const amount =
      asset === "all" ? undefined : parseAmount(input("amount").value, asset);
    const destination = getAddress($<HTMLSelectElement>("destination").value);
    const plan = planExit(snap, asset, amount, destination);

    const external = radio("signer") === "external";
    if (!external) {
      const why = webAuthnUnavailableReason();
      if (why) throw new Error(why);
    }
    status("move-status", "Preparing the request…");
    const result = await sendExit({
      client: s.client,
      rpcUrl: s.rpcUrl,
      entryPoint: s.entryPoint,
      hook: snap.hook,
      account: snap.account,
      validator,
      calls: plan.calls,
      submitter: s.submitter,
      rpId: external
        ? input("external-rpid").value.trim() || "localhost"
        : location.hostname,
      sign: external ? externalSign : (hash) => browserAssertion(hash),
      onStatus: (t) => status("move-status", t),
    });
    $("result-userop").textContent = result.userOpHash;
    $("result-tx").textContent = result.transactionHash;
    $("result").hidden = false;
    status(
      "move-status",
      `Sent ${plan.lines.map((l) => `${formatUnits(l.amount, decimalsOf(l.asset))} ${l.asset.kind === "token" ? l.asset.symbol : l.asset.label}`).join(", ")} to ${destination}.`,
      "good",
    );
    await refresh();
  } catch (e) {
    pendingExternal = undefined;
    $("external").hidden = true;
    status("move-status", errorText(e), "bad");
  } finally {
    btn.disabled = false;
  }
});

// ------------------------------------------------------------------ recovery key

$("recovery-btn").addEventListener("click", async () => {
  try {
    const v = input("recovery-validator").value.trim();
    if (!isAddress(v, { strict: false }))
      throw new Error("Type the address of the recovery key contract first.");
    const account = input("account").value.trim();
    if (!isAddress(account, { strict: false }))
      throw new Error("Type your account address in step 1 first.");
    status("recovery-status", "Waiting for your passkey…");
    const key = await createRecoveryPasskey(
      `Session Firewall recovery ${short(account)}`,
    );
    const q = queueRecoveryInstall({
      account: getAddress(account),
      recoveryValidator: getAddress(v),
      x: key.x,
      y: key.y,
    });
    const out = $("recovery-out");
    out.hidden = false;
    out.textContent = [
      `Recovery passkey made for “${key.rpId}”. It only works on pages served from ${key.rpId}.`,
      `Public key x: ${key.x}`,
      `Public key y: ${key.y}`,
      `Key contract: ${getAddress(v)}`,
      `Install data: ${recoveryInitData(key.x, key.y)}`,
      "",
      "Add it from the main app (Settings → Recovery key), or send this owner call to your firewall module:",
      `FirewallModule.queue(${q.change.kind}, ${q.change.data})`,
      `calldata: ${q.data}`,
      "",
      "After 24 hours, run the queued change. Until then you can cancel it.",
    ].join("\n");
    status("recovery-status", "Recovery passkey made.", "good");
  } catch (e) {
    status("recovery-status", errorText(e), "bad");
  }
});
