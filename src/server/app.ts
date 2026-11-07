/**
 * The relay server: HTTP API plus a WebSocket that tells clients when new
 * messages arrive (the messages themselves are fetched over HTTP).
 *
 *   GET  /healthz                     liveness + database check
 *   GET  /v1/revocations              signed revocation list (public)
 *   POST /v1/revocations              publish a revocation signed by the Authority (public)
 *   PUT  /v1/bundle                   publish your own bundle             (signed)
 *   GET  /v1/bundle/:userId           look up a user                      (signed)
 *   GET  /v1/aci/:aci                 look up a user by Signal account ID (signed)
 *   POST /v1/prekeys/:userId          take a pre-key bundle to start a session (signed)
 *   POST /v1/messages                 deliver a sealed-sender envelope    (signed)
 *   GET  /v1/messages                 your queued envelopes               (signed)
 *   POST /v1/messages/ack             delete envelopes you've processed   (signed)
 *   GET  /v1/ws                       WebSocket push; signed query string
 *
 * "Signed" requests carry a signature by the caller's Signal identity key
 * (see src/request-auth.ts). Only enrolled, unrevoked users get in.
 *
 * About sealed sender: the server learns who is connected when they deliver,
 * but it does not store the sender with the envelope or log it.
 */
import { PublicKey } from '@signalapp/libsignal-client';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { WebSocketServer, type WebSocket } from 'ws';
import { verifyCert, verifyRevocation, type EnrollmentCert, type Revocation, type Signed, type TrustAnchor } from '../authority.ts';
import type { TransportEnvelope } from '../layer1.ts';
import type { PublicBundle } from '../relay.ts';
import { AUTH, MAX_CLOCK_SKEW_MS, signingBytes } from '../request-auth.ts';
import type { RelayStore } from './store.ts';

export interface RelayAppOptions {
  store: RelayStore;
  /** The Authority's Ed25519 public key (base64 SPKI), used to check certificates. */
  authorityPublicKey: string;
  now?: () => number;
  /** Largest sealed message accepted, in bytes. */
  maxEnvelopeBytes?: number;
  /** Requests per user (or per IP when not signed in), per minute. */
  rateLimitPerMinute?: number;
  /** Trust X-Forwarded-For for the client IP (only behind your own proxy). */
  trustProxy?: boolean;
  log?: (entry: Record<string, unknown>) => void;
}

export interface RelayApp {
  server: Server;
  close(): Promise<void>;
}

class HttpError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

const USER_ID = /^[A-Za-z0-9._@-]{1,64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const MSG_ID = /^[0-9a-f]{32}$/;
const NONCE = /^[0-9a-f]{32}$/;
const MAX_ONE_TIME_PREKEYS = 200;

export function createRelayApp(o: RelayAppOptions): RelayApp {
  const now = o.now ?? Date.now;
  const maxEnvelopeBytes = o.maxEnvelopeBytes ?? 256 * 1024;
  const maxBodyBytes = Math.ceil(maxEnvelopeBytes * 1.4) + 64 * 1024; // base64 overhead + JSON
  const rateLimit = o.rateLimitPerMinute ?? 600;
  const log = o.log ?? ((e) => console.log(JSON.stringify(e)));
  const store = o.store;

  // Certificates are checked against the Authority's key; revocation is checked separately in the store.
  const anchor: TrustAnchor = { publicKey: o.authorityPublicKey, sealedSenderTrustRoot: '', isRevoked: () => false };

  // ----------------------------------------------------------- Helpers

  const buckets = new Map<string, { tokens: number; at: number }>();
  function rateLimitHit(key: string): void {
    const t = now();
    const b = buckets.get(key) ?? { tokens: rateLimit, at: t };
    b.tokens = Math.min(rateLimit, b.tokens + ((t - b.at) / 60_000) * rateLimit);
    b.at = t;
    if (b.tokens < 1) throw new HttpError(429, 'rate limit exceeded');
    b.tokens -= 1;
    buckets.set(key, b);
  }

  function clientIp(req: IncomingMessage): string {
    const fwd = o.trustProxy ? String(req.headers['x-forwarded-for'] ?? '').split(',')[0].trim() : '';
    return fwd || req.socket.remoteAddress || 'unknown';
  }

  async function readBody(req: IncomingMessage): Promise<Buffer> {
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of req) {
      size += (chunk as Buffer).length;
      if (size > maxBodyBytes) throw new HttpError(413, 'request body too large');
      chunks.push(chunk as Buffer);
    }
    return Buffer.concat(chunks);
  }

  function parseJson<T>(body: Buffer): T {
    try {
      return JSON.parse(body.toString('utf8')) as T;
    } catch {
      throw new HttpError(400, 'invalid JSON');
    }
  }

  /** Check a certificate is valid and not revoked. */
  async function validEnrollment(cert: Signed<EnrollmentCert>): Promise<EnrollmentCert> {
    let e: EnrollmentCert;
    try {
      e = verifyCert(anchor, cert, 'enrollment', now());
    } catch (err) {
      throw new HttpError(401, (err as Error).message);
    }
    if (await store.isRevoked(e.serial)) throw new HttpError(403, 'enrollment revoked');
    return e;
  }

  /**
   * Verify a signed request. `enrollment` is given only when publishing a bundle
   * (the user may not be registered yet); otherwise it comes from the store.
   */
  async function authenticate(
    method: string,
    pathAndQuery: string,
    get: (h: string) => string | undefined,
    body: Uint8Array,
    enrollment?: Signed<EnrollmentCert>,
  ): Promise<EnrollmentCert> {
    const user = get(AUTH.user);
    const ts = get(AUTH.timestamp);
    const nonce = get(AUTH.nonce);
    const sig = get(AUTH.signature);
    if (!user || !ts || !nonce || !sig) throw new HttpError(401, 'missing authentication');
    if (!USER_ID.test(user) || !NONCE.test(nonce)) throw new HttpError(401, 'malformed authentication');
    if (!/^\d{1,16}$/.test(ts) || Math.abs(now() - Number(ts)) > MAX_CLOCK_SKEW_MS) throw new HttpError(401, 'request timestamp out of range');

    const cert = enrollment ?? (await store.getBundle(user))?.enrollment;
    if (!cert) throw new HttpError(401, 'unknown user');
    const e = await validEnrollment(cert);
    if (e.userId !== user) throw new HttpError(401, 'certificate does not match user');

    let ok = false;
    try {
      ok = PublicKey.deserialize(Buffer.from(e.signalIdentityKey, 'base64')).verify(
        Uint8Array.from(signingBytes(method, pathAndQuery, user, ts, nonce, body)),
        Uint8Array.from(Buffer.from(sig, 'base64')),
      );
    } catch {
      ok = false;
    }
    if (!ok) throw new HttpError(401, 'bad request signature');
    if (!(await store.useNonce(nonce, Number(ts) + MAX_CLOCK_SKEW_MS, now()))) throw new HttpError(401, 'replayed request');
    return e;
  }

  async function checkBundle(user: string, b: PublicBundle): Promise<void> {
    if (!b?.enrollment?.body || !b.preKeys) throw new HttpError(400, 'malformed bundle');
    const e = b.enrollment.body;
    if (e.userId !== user || !UUID.test(e.aci)) throw new HttpError(400, 'bundle does not match user');
    const p = b.preKeys;
    if (p.identityKey !== e.signalIdentityKey) throw new HttpError(400, 'pre-keys use a different identity key');
    if (!Array.isArray(p.oneTimePreKeys) || p.oneTimePreKeys.length > MAX_ONE_TIME_PREKEYS) throw new HttpError(400, 'bad one-time pre-keys');
    for (const k of p.oneTimePreKeys) {
      if (!Number.isInteger(k?.id) || typeof k.publicKey !== 'string') throw new HttpError(400, 'bad one-time pre-key');
    }
    // Reject pre-keys not signed by the identity key (clients check too).
    try {
      const identity = PublicKey.deserialize(Buffer.from(p.identityKey, 'base64'));
      const signedOk = (pub: string, sig: string) =>
        identity.verify(Uint8Array.from(Buffer.from(pub, 'base64')), Uint8Array.from(Buffer.from(sig, 'base64')));
      if (!signedOk(p.signedPreKey.publicKey, p.signedPreKey.signature) || !signedOk(p.kyberPreKey.publicKey, p.kyberPreKey.signature)) {
        throw new Error();
      }
    } catch {
      throw new HttpError(400, 'pre-key signatures invalid');
    }
    if (b.clearance) {
      try {
        const c = verifyCert(anchor, b.clearance, 'clearance', now());
        if (c.userId !== user) throw new Error('clearance certificate is for another user');
        if (await store.isRevoked(c.serial)) throw new Error('clearance revoked');
      } catch (err) {
        throw new HttpError(400, (err as Error).message);
      }
    }
  }

  function checkEnvelope(env: TransportEnvelope): void {
    if (env?.v !== 1 || typeof env.id !== 'string' || !MSG_ID.test(env.id) || typeof env.to !== 'string' || !USER_ID.test(env.to)) {
      throw new HttpError(400, 'malformed envelope');
    }
    if (typeof env.sealed !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(env.sealed)) throw new HttpError(400, 'malformed envelope');
    if (Buffer.byteLength(env.sealed, 'base64') > maxEnvelopeBytes) throw new HttpError(413, 'envelope too large');
  }

  /** Look up someone else's bundle: must exist and not be revoked. */
  async function liveBundle(b: PublicBundle | undefined): Promise<PublicBundle> {
    if (!b || (await store.isRevoked(b.enrollment.body.serial))) throw new HttpError(404, 'no such user');
    return b;
  }

  // ---------------------------------------------------------- WebSocket

  const sockets = new Map<string, Set<{ ws: WebSocket; serial: string }>>();
  const wss = new WebSocketServer({ noServer: true, maxPayload: 1024 });

  function notify(userId: string): void {
    for (const s of sockets.get(userId) ?? []) s.ws.send(JSON.stringify({ type: 'messages' }));
  }

  function disconnectSerial(serial: string): void {
    for (const set of sockets.values()) for (const s of set) if (s.serial === serial) s.ws.close(4003, 'revoked');
  }

  const heartbeat = setInterval(() => {
    for (const set of sockets.values()) for (const s of set) s.ws.ping();
  }, 30_000);
  heartbeat.unref();

  // ------------------------------------------------------------- Routes

  type Ctx = { req: IncomingMessage; url: URL; body: Buffer; auth: () => Promise<EnrollmentCert> };
  type Handler = (c: Ctx, params: string[]) => Promise<unknown>;
  const routes: [string, RegExp, Handler][] = [
    ['GET', /^\/healthz$/, async () => {
      await store.ping();
      return { ok: true };
    }],
    ['GET', /^\/v1\/revocations$/, async () => ({ revocations: await store.revocations() })],
    ['POST', /^\/v1\/revocations$/, async ({ body }) => {
      const rev = parseJson<Signed<Revocation>>(body);
      try {
        verifyRevocation(o.authorityPublicKey, rev);
      } catch (err) {
        throw new HttpError(400, (err as Error).message);
      }
      await store.addRevocation(rev);
      disconnectSerial(rev.body.serial);
      return { ok: true };
    }],
    ['PUT', /^\/v1\/bundle$/, async ({ req, url, body }) => {
      const bundle = parseJson<PublicBundle>(body);
      const user = String(req.headers[AUTH.user] ?? '');
      await authenticate(req.method!, url.pathname + url.search, (h) => header(req, h), body, bundle?.enrollment);
      await checkBundle(user, bundle);
      try {
        await store.putBundle(user, bundle, now());
      } catch {
        throw new HttpError(409, 'account ID already registered to another user');
      }
      return { ok: true };
    }],
    ['GET', /^\/v1\/bundle\/([^/]+)$/, async ({ auth }, [id]) => {
      await auth();
      return liveBundle(await store.getBundle(id));
    }],
    ['GET', /^\/v1\/aci\/([^/]+)$/, async ({ auth }, [aci]) => {
      await auth();
      return liveBundle(await store.findByAci(aci));
    }],
    ['POST', /^\/v1\/prekeys\/([^/]+)$/, async ({ auth }, [id]) => {
      await auth();
      await liveBundle(await store.getBundle(id));
      const p = await store.takePreKeys(id);
      if (!p) throw new HttpError(404, 'no such user');
      return p;
    }],
    ['POST', /^\/v1\/messages$/, async ({ auth, body }) => {
      await auth();
      const env = parseJson<TransportEnvelope>(body);
      checkEnvelope(env);
      await liveBundle(await store.getBundle(env.to));
      if (await store.enqueue(env, now())) notify(env.to);
      return { ok: true };
    }],
    ['GET', /^\/v1\/messages$/, async ({ auth, url }) => {
      const me = await auth();
      const limit = Math.min(Number(url.searchParams.get('limit') ?? 100) || 100, 500);
      return { messages: await store.listMessages(me.userId, limit) };
    }],
    ['POST', /^\/v1\/messages\/ack$/, async ({ auth, body }) => {
      const me = await auth();
      const { ids } = parseJson<{ ids: string[] }>(body);
      if (!Array.isArray(ids) || ids.length > 500 || !ids.every((i) => typeof i === 'string' && MSG_ID.test(i))) {
        throw new HttpError(400, 'bad ids');
      }
      return { deleted: await store.ack(me.userId, ids) };
    }],
  ];

  function header(req: IncomingMessage, name: string): string | undefined {
    const v = req.headers[name];
    return Array.isArray(v) ? v[0] : v;
  }

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const started = now();
    const url = new URL(req.url ?? '/', 'http://relay');
    let status = 200;
    let route = 'unmatched';
    let payload: unknown;
    try {
      rateLimitHit(header(req, AUTH.user) ?? `ip:${clientIp(req)}`);
      const match = routes.find(([m, re]) => m === req.method && re.test(url.pathname));
      if (!match) throw new HttpError(404, 'not found');
      route = `${match[0]} ${match[1].source}`;
      const params = (url.pathname.match(match[1]) ?? []).slice(1).map(decodeURIComponent);
      const body = await readBody(req);
      const auth = () => authenticate(req.method!, url.pathname + url.search, (h) => header(req, h), body);
      payload = await match[2]({ req, url, body, auth }, params);
    } catch (err) {
      status = err instanceof HttpError ? err.status : 500;
      payload = { error: err instanceof HttpError ? err.message : 'internal error' };
      if (status === 500) log({ level: 'error', msg: (err as Error).stack ?? String(err) });
    }
    res.writeHead(status, {
      'content-type': 'application/json',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      'strict-transport-security': 'max-age=63072000',
    });
    res.end(JSON.stringify(payload));
    // No user IDs, message IDs or IPs in logs: metadata is sensitive too.
    log({ level: 'info', method: req.method, route, status, ms: now() - started });
  }

  const server = createServer((req, res) => void handle(req, res));
  server.requestTimeout = 30_000;
  server.headersTimeout = 10_000;

  server.on('upgrade', (req, socket, head) => {
    const url = new URL(req.url ?? '/', 'http://relay');
    const reject = (code: number, msg: string) => {
      socket.end(`HTTP/1.1 ${code} ${msg}\r\nConnection: close\r\n\r\n`);
    };
    if (url.pathname !== '/v1/ws') return reject(404, 'Not Found');
    // Auth goes in the query string (browsers' WebSocket API can't set headers); the
    // signature covers the path with every parameter except the signature itself.
    const sig = url.searchParams.get('sig') ?? undefined;
    url.searchParams.delete('sig');
    const q = (k: string) => url.searchParams.get(k) ?? undefined;
    const get = (h: string) =>
      ({ [AUTH.user]: q('user'), [AUTH.timestamp]: q('ts'), [AUTH.nonce]: q('nonce'), [AUTH.signature]: sig })[h];
    authenticate('GET', url.pathname + url.search, get, new Uint8Array())
      .then((e) => {
        wss.handleUpgrade(req, socket, head, (ws) => {
          const entry = { ws, serial: e.serial };
          const set = sockets.get(e.userId) ?? new Set();
          set.add(entry);
          sockets.set(e.userId, set);
          ws.on('close', () => set.delete(entry));
          ws.on('message', () => {}); // nothing to receive
          ws.send(JSON.stringify({ type: 'ready' }));
        });
      })
      .catch((err) => reject(err instanceof HttpError ? err.status : 500, 'Unauthorized'));
  });

  return {
    server,
    async close() {
      clearInterval(heartbeat);
      for (const set of sockets.values()) for (const s of set) s.ws.terminate();
      wss.close();
      server.closeAllConnections();
      await new Promise<void>((r) => server.close(() => r()));
    },
  };
}
