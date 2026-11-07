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

Needs Node 22.18 or newer (it runs the TypeScript directly). No runtime dependencies.

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
                    ┌──────────── Layer 1: transport (every message) ─────────────┐
                    │  ECIES to recipient's transport key · sender hidden inside  │
                    │  signed with sender's identity key (Ed25519)                │
                    │   ┌──────── Layer 2: classified envelope ──────────────┐    │
                    │   │ header (authenticated, not secret):                │    │
                    │   │   from · to · SECRET//OPS · noForward · viewOnce   │    │
                    │   │   expiresAt · recipient clearance cert serial      │    │
                    │   │ content: AES-256-GCM with a random message key     │    │
                    │   │ message key: encrypted to recipient's CLEARANCE    │    │
                    │   │   key, which only exists on their hardware token   │    │
                    │   └────────────────────────────────────────────────────┘    │
                    └─────────────────────────────────────────────────────────────┘
```

| Part | File | What it does |
|---|---|---|
| Primitives | `src/crypto.ts` | X25519, Ed25519, HKDF-SHA256, AES-256-GCM, canonical JSON |
| Labels | `src/classification.ts` | Levels + compartments; "dominates" check (no read up) |
| Clearance Authority | `src/authority.ts` | Organisation PKI: signs enrollment and clearance certificates, revocation |
| Hardware token | `src/token.ts` | Holds the clearance private key; PIN with lockout and key erasure |
| Device posture | `src/device.ts` | MDM enrolled, not rooted, recent OS patches, screen capture blocked |
| Layers 1 and 2 | `src/layers.ts` | The two encryption layers |
| Relay server | `src/relay.ts` | Stores key bundles and opaque envelopes; cannot read anything |
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

### What the tests cover (`test/messaging.test.ts`)
The relay sees no sender, text or label · clearance too low, missing
compartment, and sending above your own level are all refused · wrong PIN, PIN
lockout with key erasure, and another user's token are refused · header
tampering (downgrade) fails · forged signatures are rejected · revoked and
expired clearances are refused · message expiry and view-once erase the message
· forwarding is blocked, or re-encrypted to a cleared recipient when allowed ·
rooted or unmanaged devices are refused · replays are ignored · the audit chain
detects edits and deletions.

## Production gaps

| Prototype | Production |
|---|---|
| Layer 1 is one ephemeral key per message (only the sender side has forward secrecy) | Signal Double Ratchet (libsignal) for 1:1 chats, MLS (OpenMLS) for groups, with hybrid post-quantum (X25519 + ML-KEM) |
| Classical crypto only | Hybrid post-quantum key exchange for both layers; ML-DSA signatures |
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
