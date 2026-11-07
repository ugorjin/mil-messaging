# mil-messaging: two-layer encryption prototype

A working prototype of a messenger in which every message is end-to-end
encrypted, and **classified** messages carry a second layer of encryption that
only the recipient's hardware token can open, after a PIN, a device check and a
clearance check.

> **Prototype only.** This shows the design; it is not approved for real
> classified information. That requires accreditation (an Authority to Operate,
> FIPS 140-3 validated crypto, real hardware tokens and attestation, and an
> independent security review). See [Production gaps](#production-gaps).

## Run it

Needs Node 22.18 or newer (it runs the TypeScript directly). The one runtime
dependency is [libsignal](https://github.com/signalapp/libsignal)
(`@signalapp/libsignal-client`), which ships prebuilt native binaries for
Linux, macOS and Windows (x64 and arm64).

```bash
npm install
```

```bash
npm run demo
```

```bash
npm test
```

```bash
npm run typecheck
```

## How it works

```
  ┌─ Layer 1: Signal protocol (libsignal) ─ every message ──────────────────────┐
  │  session start: PQXDH (X25519 + Kyber/ML-KEM pre-keys)                      │
  │  messages: Double Ratchet (forward secrecy, post-compromise security)       │
  │  sealed sender: relay sees only the recipient; sender proved inside by a    │
  │    short-lived SenderCertificate from the organisation's Authority          │
  │  identity keys trusted only if they match the Authority's enrollment cert   │
  │                                                                             │
  │   ┌─ Layer 2: classified envelope ─ classified messages only ────────────┐  │
  │   │ header (authenticated, not secret):                                  │  │
  │   │   from · to · SECRET//OPS · noForward · viewOnce · expiresAt         │  │
  │   │   recipient clearance cert serial                                    │  │
  │   │ content: AES-256-GCM with a random message key                       │  │
  │   │ message key: encrypted to the recipient's CLEARANCE key, which       │  │
  │   │   only exists on their hardware token                                │  │
  │   └──────────────────────────────────────────────────────────────────────┘  │
  └─────────────────────────────────────────────────────────────────────────────┘
```

| Part | File | What it does |
|---|---|---|
| Primitives | `src/crypto.ts` | X25519, Ed25519, HKDF-SHA256, AES-256-GCM, canonical JSON |
| Labels | `src/classification.ts` | Levels + compartments; "dominates" check (no read up) |
| Clearance Authority | `src/authority.ts` | Organisation PKI: signs enrollment and clearance certificates, revocation; sealed-sender trust root |
| Hardware token | `src/token.ts` | Holds the clearance private key; PIN with lockout and key erasure |
| Device posture | `src/device.ts` | MDM enrolled, not rooted, recent OS patches, screen capture blocked |
| Layer 1 | `src/layer1.ts` | libsignal: key stores, pre-keys, PQXDH session start, sealed-sender encrypt/decrypt |
| Layer 2 | `src/layer2.ts` | Classified envelope bound to its label and handling rules |
| Relay server | `src/relay.ts` | Stores certificates, pre-keys (hands out each one-time pre-key once) and opaque envelopes |
| Client | `src/client.ts` | Send / receive / open / forward, with every check enforced |
| Audit log | `src/audit.ts` | Hash-chained log of events; never stores content |

### Sending a classified message
The send is refused (nothing goes out) unless:
1. the sender's own clearance covers the label;
2. the recipient's clearance certificate is signed by the authority, unexpired
   and unrevoked, and covers the label (level **and** every compartment).

### Opening a classified message
It arrives locked: the recipient sees only a banner (sender, label, handling
rules). Opening checks, in order:
1. not already viewed (view-once) and not expired;
2. the device passes the posture check;
3. the recipient's clearance is still valid and covers the label, and is the
   certificate the message was encrypted to;
4. the hardware token belongs to the recipient and the PIN is correct;
5. decryption succeeds. The header is bound to the ciphertext, so changing the
   label, the recipient or the handling rules breaks it.

Every refusal and every successful open is written to the audit log. The text
is returned with a watermark naming the reader, device and time.

### What the tests cover (`test/messaging.test.ts`, 24 tests)
**Layer 1:** messages round-trip, and a two-way conversation keeps working as
the ratchet advances · each one-time pre-key is used once · the relay sees no
sender, account ID, text or label · a server swapping in its own identity key
is refused · sender certificates not from the organisation are rejected · a
user can't use another user's sender certificate · replays are rejected by the
ratchet · revoked enrollment stops new sender certificates and messages · an
expired sender certificate can't be used.

**Layer 2:** clearance too low, missing compartment, and sending above your own
level are refused (and audited) · wrong PIN, PIN lockout with key erasure, and
another user's token are refused · header tampering (downgrade) fails · revoked
and expired clearances are refused · message expiry and view-once erase the
message · forwarding is blocked, or re-encrypted to a cleared recipient when
allowed · rooted or unmanaged devices are refused · the audit chain detects
edits and deletions.

## Production gaps

| Prototype | Production |
|---|---|
| 1:1 chats only | Groups via MLS (OpenMLS) or Signal sender keys, with the same clearance check per member |
| Pre-keys generated once, kept in memory | Encrypted on-device stores; replenish one-time pre-keys, rotate signed and Kyber pre-keys on a schedule |
| Sender certificates refreshed manually | The app fetches a new one daily from an authenticated endpoint |
| Layer 2 and the Authority's signatures are classical (X25519, Ed25519) | Hybrid post-quantum wrapping (add ML-KEM) and ML-DSA signatures |
| Token is a JS object | Smart card / CAC / YubiKey PIV, Secure Enclave / StrongBox, with touch or biometric |
| Device state is self-reported | Hardware attestation (App Attest, Play Integrity, Key Attestation) checked by the server, plus MDM |
| Revocation is an in-memory set | Signed revocation lists / OCSP from an HSM-backed CA, short-lived certificates |
| Rules (no forward, view-once, watermark) enforced by this client | Same, plus OS-level enforcement (FLAG_SECURE, no backups, encrypted local storage, remote wipe) |
| In-memory relay | Self-hosted, on-premises or air-gapped server (e.g. Matrix/Synapse), mutual TLS, padded message sizes, authenticated fetch |
| No key verification UI | Safety numbers / QR verification and key transparency |
| Audit log is local | Write-once, replicated audit service with signed checkpoints |

Limits no design removes: a compromised device can read what its user reads; a
second camera can photograph the screen (the watermark only traces the leak);
cleared insiders can still leak.

## Licence note

libsignal is licensed **AGPL-3.0**. If you distribute an app built on it, or let
users interact with it over a network, you must make your source code available
under the AGPL. That is usually fine for a government or in-house system, but
check with counsel before any commercial or closed-source use.

## Hosting

Only the **relay server** and the **Authority** need hosting. Encryption and
decryption happen on the devices. libsignal is a native library, so clients are
native apps: iOS (Swift), Android (Java/Kotlin) or desktop (Electron/Node).
There is no supported browser build, so a plain web app can't be a client.

| Option | Good for | Notes |
|---|---|---|
| **Vercel** | Marketing site, docs, an admin UI | Poor fit for the relay: serverless functions don't keep WebSocket connections open or keep state between requests, and you'd need a separate database and queue anyway. Not suitable for anything with classified handling requirements. |
| Fly.io / Railway / Render / a VPS with Docker | Development and pilots | One long-running Node process with WebSockets plus Postgres (bundles, queues) and Redis (presence). The simplest real deployment of this relay. |
| AWS GovCloud / Azure Government (and their high-impact authorised regions) | Government use of non-classified sensitive data | Needs the matching compliance authorisation for your data category. |
| On-premises or air-gapped servers, or the government's own classified networks | Real classified traffic | Required for classified data in practice; the Authority's keys go in an HSM. |
