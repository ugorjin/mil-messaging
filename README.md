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

Needs Node 22.18 or newer (it runs the TypeScript directly, with no build
step); Node 24 LTS is recommended and is what the Docker image uses. Runtime
dependencies: [libsignal](https://github.com/signalapp/libsignal)
(`@signalapp/libsignal-client`, prebuilt native binaries for Linux, macOS and
Windows), plus `ws` and `pg` for the relay server.

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

`npm run demo` runs everything in one process. To run the real relay server,
see [Relay server](#relay-server).

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
| Relay interface | `src/relay.ts` | What clients talk to; in-memory implementation for tests and the demo |
| Relay server | `src/server/` | HTTP + WebSocket server, Postgres or in-memory storage |
| Network client | `src/http-relay.ts` | Signed requests to the relay server, WebSocket push |
| Request signing | `src/request-auth.ts` | Requests signed with the device's Signal identity key |
| Remote trust | `src/remote-trust.ts` | Authority public keys + signed revocations fetched from the relay |
| Authority tool | `src/tools/authority.ts` | Create Authority keys, print public keys, publish revocations |
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

### What the tests cover
`test/messaging.test.ts` (25 tests, in-memory relay):

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

`test/server.test.ts` (over real HTTP and WebSocket; runs against the
in-memory store, and again against Postgres when `TEST_DATABASE_URL` is set):
plain and classified round trips, and the server stores no sender, text or
label · messages stay queued until acknowledged · one-time pre-keys are never
handed out twice, even under concurrent requests · unsigned, forged, stale,
replayed and re-targeted requests are refused · users can read only their own
queue · bundles can't be published for someone else or with a rogue
Authority's certificate · forged revocations are refused; real ones cut the
user off · oversized and malformed envelopes are refused · WebSocket push works
and refuses bad or replayed signatures · rate limiting.

## Relay server

### Run it with Docker Compose (relay + Postgres)

1. Create the Authority's keys. This writes `authority.secret.json`, which holds
   **private keys**: keep it offline and out of git (it's in `.gitignore`).
   ```bash
   npm run authority -- init
   ```
2. Copy the example settings and fill in `AUTHORITY_PUBLIC_KEY` (printed by
   step 1) and a long random `POSTGRES_PASSWORD`.
   ```bash
   cp .env.example .env
   ```
3. Start it. The relay listens on `127.0.0.1:8080` only.
   ```bash
   docker compose up -d --build
   ```
4. Try it end to end: enrolls two users, then sends a plain and a classified
   message through the server.
   ```bash
   RELAY_URL=http://localhost:8080 npm run net-demo
   ```

For a public server with automatic HTTPS (Let's Encrypt), set `DOMAIN` in
`.env`, point that DNS name at the machine, open ports 80 and 443, and run:
```bash
docker compose --profile tls up -d --build
```

Without Compose, the image runs anywhere that runs containers (Fly.io,
Railway, Render, a VPS, Kubernetes). It needs `AUTHORITY_PUBLIC_KEY` and
`DATABASE_URL`; all settings are listed at the top of `src/server/main.ts`.

### API

| Method and path | Auth | Purpose |
|---|---|---|
| `GET /healthz` | none | Liveness and database check |
| `GET /v1/revocations` | none | Authority-signed revocation list |
| `POST /v1/revocations` | Authority signature | Publish a revocation (`npm run authority -- revoke`) |
| `PUT /v1/bundle` | signed | Publish your certificates and pre-keys |
| `GET /v1/bundle/:userId`, `GET /v1/aci/:aci` | signed | Look up a user (one-time pre-keys are never listed) |
| `POST /v1/prekeys/:userId` | signed | Take a pre-key bundle to start a session |
| `POST /v1/messages` | signed | Deliver a sealed-sender envelope |
| `GET /v1/messages`, `POST /v1/messages/ack` | signed | Fetch your queue, then delete what you've processed |
| `GET /v1/ws` | signed query string | Push notification when messages arrive |

### How the server is secured
- **Who can use it:** only enrolled users. Each request is signed with the
  device's Signal identity key, and the server checks the signature against the
  user's Authority-signed enrollment certificate. Timestamps must be within 5
  minutes and each nonce works once, so captured requests can't be replayed.
- **Revocation:** the Authority signs revocations and publishes them to the
  relay. A revoked user is refused at once and disappears from lookups, and
  their open WebSocket is closed.
- **What it holds:** certificates, public keys and opaque envelopes. Envelopes
  don't record the sender. Undelivered messages are deleted after
  `MESSAGE_RETENTION_DAYS` (default 30).
- **Logs:** method, route, status and timing only. No user IDs, message IDs
  or IPs, because who-talks-to-whom is sensitive too.
- **Limits:** request body and envelope size limits, per-user / per-IP rate
  limiting, request timeouts.
- **Container:** non-root user, read-only filesystem, all Linux capabilities
  dropped, `no-new-privileges`. The database is on an internal network with no
  outside route, and only the relay can reach it.
- **Image:** contains no keys. Behind a TLS-inspecting corporate proxy, pass
  the proxy's CA certificate as a build secret (`--secret id=ca,src=ca.crt`);
  it isn't kept in the image.

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
| The relay sees which enrolled user is delivering (it doesn't store it) | Anonymous delivery tokens, as Signal does, so the server can't link sender to recipient |
| One relay instance (WebSocket push and rate limits are in process memory) | Several instances behind a load balancer with Postgres LISTEN/NOTIFY or Redis for push and shared rate limits |
| Envelope sizes reveal message length | Pad to fixed size buckets |
| Server TLS only | Mutual TLS with device certificates; on-premises or air-gapped hosting |
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
| Fly.io / Railway / Render / a VPS with Docker | Development and pilots | Run the Docker image from this repo plus a managed Postgres. The simplest real deployment. |
| AWS GovCloud / Azure Government (and their high-impact authorised regions) | Government use of non-classified sensitive data | Needs the matching compliance authorisation for your data category. |
| On-premises or air-gapped servers, or the government's own classified networks | Real classified traffic | Required for classified data in practice; the Authority's keys go in an HSM. |
