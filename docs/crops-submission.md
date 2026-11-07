# CROPS submission gates

Lead: onchain security for a compromised browser trading session. Censorship resistance is supported
by replaceable RPC/bundler configuration and server-independent contracts; browser recovery has an
explicit RP-domain dependency until independent-origin enrollment is demonstrated.

- Public free/open-source repo: verified with `gh repo view` on 2026-11-07. MIT plus the documented GPL test fixture.
- Reproducible run instructions: SDK fork, contracts and optional monitor are documented. M5 browser build is pending.
- README CROPS: C, O, P and S each disclose dependencies and trade-offs.
- Client privacy: no third-party scripts, trackers, analytics, remote fonts or credential collection. In M5, enforce CSP and scan exported bundles/network traffic. Third-party RPC/bundler requests remain visible to those providers.
- Key handling: browser passkeys stay in the authenticator; session keys stay on device. Monitor contact storage is opt-in and explained in its privacy notes. The software P-256 signer is local testing only.
- UX: user-facing labels should say "Hourly spending limit", "Trusted destinations", "Pause trading", "Cancel pending change" and "Move funds out"; no CROPS knowledge is required. Show normal trade, blocked action, and recovery with plain error messages.
- Ship gate: pinned deployment dependencies, CI passing, browser passkeys, mobile checks, recovery enrollment, public addresses, operational monitor and external audit before mainnet. Resolve V13 before M7.
- EF prize: submit once for consideration; do not claim simultaneous EF awards or automate a submission.

## Three-minute recording script (pending M5/M8)

0:00–0:25: Show a fresh account, its registered exit destination and hourly limit. Explain: "The account enforces this limit even if this website is compromised."

0:25–0:55: Create a session and complete one ordinary trade. Show transaction success and the resulting balance.

0:55–1:35: Enable the malicious-client demo. Try transfer to an attacker, unknown-spender approval, diverted proceeds, and account/module replacement (A1/A2/A5/A9). Show actual errors and zero attacker balance; include transaction/explorer evidence, and label any validation-only rejection accurately.

1:35–2:20: Stop the optional monitor/backend. Repeat a malicious action and show the contract still rejects it. Change the RPC endpoint and perform a normal read or owner exit. If a genuine independent-origin recovery credential has been enrolled, block the main domain and exit from that origin; otherwise explicitly state the RP-domain limitation and do not stage a fake domain-loss demonstration.

2:20–2:45: Show funds at the registered destination. Briefly display the README's CROPS section, public license and run command.

2:45–3:00: State the current network, audit status, privacy trade-offs and repository/video links. Stop by 3:00.

Acceptance: a real screen recording with timestamps and visible transaction outcomes, not a narrated mockup. Do not mark the video submitted or qualification complete before the file exists and its duration is checked. Keep API keys, contact addresses and live credentials out of the recording.

Reference: [EF Mandate announcement](https://blog.ethereum.org/2026/03/13/ef-mandate).
