/**
 * Relay server tests, over real HTTP and WebSocket.
 * Runs against the in-memory store, and also against Postgres when
 * TEST_DATABASE_URL is set.
 */
import { strict as assert } from 'node:assert';
import type { AddressInfo } from 'node:net';
import { after, before, describe, test } from 'node:test';
import {
  Authority,
  enroll,
  HttpRelay,
  RemoteTrust,
  signRequest,
  signedWebSocketPath,
  type Label,
  type RequestSigner,
} from '../src/index.ts';
import { createRelayApp, type RelayApp } from '../src/server/app.ts';
import { PostgresStore } from '../src/server/postgres.ts';
import { MemoryStore, type RelayStore } from '../src/server/store.ts';
import { goodDevice, PIN } from './helpers.ts';

/** HttpRelay that keeps the signer so tests can make raw signed requests. */
class TestRelay extends HttpRelay {
  signer!: RequestSigner;
  override bindIdentity(s: RequestSigner): void {
    this.signer = s;
    super.bindIdentity(s);
  }
}

const stores: [string, () => Promise<RelayStore>][] = [['memory', async () => new MemoryStore()]];
if (process.env.TEST_DATABASE_URL) {
  stores.push([
    'postgres',
    async () => {
      const s = new PostgresStore(process.env.TEST_DATABASE_URL!);
      await s.init();
      return s;
    },
  ]);
}

for (const [storeName, makeStore] of stores) {
  describe(`relay server (${storeName} store)`, () => {
    let app: RelayApp;
    let store: RelayStore;
    let base: string;
    const authority = new Authority();
    let n = 0;

    before(async () => {
      store = await makeStore();
      app = createRelayApp({ store, authorityPublicKey: authority.publicKey, log: () => {} });
      await new Promise<void>((r) => app.server.listen(0, '127.0.0.1', () => r()));
      base = `http://127.0.0.1:${(app.server.address() as AddressInfo).port}`;
    });

    after(async () => {
      await app.close();
      await store.close();
    });

    /** Enroll a user with a unique ID (tests share one server). */
    const user = async (name: string, clearance?: Label, issuer = authority) => {
      const userId = `${name}-${storeName}-${++n}-${Date.now()}`;
      const relay = new TestRelay(base);
      const r = await enroll(issuer, { userId, relay, trust: issuer, audit: issuer.audit, device: goodDevice(`${name}-phone`, Date.now()), pin: PIN, clearance });
      return { ...r, relay, userId };
    };

    const raw = (path: string, init: RequestInit = {}) => fetch(base + path, init);

    test('health check', async () => {
      const r = await raw('/healthz');
      assert.equal(r.status, 200);
      assert.deepEqual(await r.json(), { ok: true });
    });

    test('plain and classified messages round-trip through the server', async () => {
      const alice = await user('alice', { level: 'SECRET', compartments: ['OPS'] });
      const bob = await user('bob', { level: 'SECRET', compartments: ['OPS'] });
      await alice.client.sendText(bob.userId, 'hello over the network');
      const id = await alice.client.sendClassified(bob.userId, 'convoy departs 0400', { level: 'SECRET', compartments: ['OPS'] });

      // What the server holds: no sender, no text, no label.
      const stored = JSON.stringify(await store.listMessages(bob.userId, 100));
      for (const leak of [alice.userId, alice.client.aci, 'hello over', 'convoy', 'SECRET', 'OPS']) {
        assert.ok(!stored.includes(leak), `server can see "${leak}"`);
      }

      const msgs = await bob.client.sync();
      assert.deepEqual(msgs.map((m) => m.kind), ['plain', 'classified']);
      assert.equal(msgs[0].kind === 'plain' && msgs[0].body, 'hello over the network');
      assert.equal(bob.client.openClassified(id, bob.token, PIN).text, 'convoy departs 0400');
      assert.equal((await store.listMessages(bob.userId, 100)).length, 0, 'acknowledged messages are deleted');

      // Reply: the session works both ways.
      await bob.client.sendText(alice.userId, 'received');
      assert.equal((await alice.client.sync())[0].from, bob.userId);
    });

    test('messages stay queued until acknowledged', async () => {
      const alice = await user('alice');
      const bob = await user('bob');
      await alice.client.sendText(bob.userId, 'm');
      assert.equal((await bob.relay.fetch(bob.userId)).length, 1);
      assert.equal((await bob.relay.fetch(bob.userId)).length, 1);
      await bob.client.sync();
      assert.equal((await bob.relay.fetch(bob.userId)).length, 0);
    });

    test('each one-time pre-key is handed out once, even under concurrent requests', async () => {
      const bob = await user('bob');
      const alice = await user('alice');
      const before = await store.remainingPreKeys(bob.userId);
      const taken = await Promise.all(Array.from({ length: 10 }, () => alice.relay.takePreKeys(bob.userId)));
      const ids = taken.map((t) => t.oneTimePreKey?.id);
      assert.equal(new Set(ids).size, 10, 'no duplicates');
      assert.equal(await store.remainingPreKeys(bob.userId), before - 10);
    });

    test('lookups do not reveal the one-time pre-keys', async () => {
      const alice = await user('alice');
      const bob = await user('bob');
      const b = await alice.relay.lookup(bob.userId);
      assert.equal(b?.enrollment.body.userId, bob.userId);
      assert.deepEqual(b?.preKeys.oneTimePreKeys, []);
    });

    test('unsigned, badly signed, stale and replayed requests are refused', async () => {
      const alice = await user('alice');
      const bob = await user('bob');
      assert.equal((await raw('/v1/messages')).status, 401);

      const h = signRequest(alice.relay.signer, 'GET', '/v1/messages', new Uint8Array(), Date.now());
      assert.equal((await raw('/v1/messages', { headers: h })).status, 200);
      const replay = await raw('/v1/messages', { headers: h });
      assert.equal(replay.status, 401);
      assert.match(((await replay.json()) as { error: string }).error, /replayed/);

      const forged = { ...signRequest(alice.relay.signer, 'GET', '/v1/messages', new Uint8Array(), Date.now()), 'x-mm-user': bob.userId };
      assert.equal((await raw('/v1/messages', { headers: forged })).status, 401, 'signed by alice, claiming bob');

      const stale = signRequest(alice.relay.signer, 'GET', '/v1/messages', new Uint8Array(), Date.now() - 10 * 60_000);
      assert.equal((await raw('/v1/messages', { headers: stale })).status, 401);

      // Signature covers the path: can't reuse a signature for another endpoint.
      const other = signRequest(alice.relay.signer, 'GET', '/v1/revocations', new Uint8Array(), Date.now());
      assert.equal((await raw('/v1/messages', { headers: other })).status, 401);
    });

    test("users can only read their own queue", async () => {
      const alice = await user('alice');
      const bob = await user('bob');
      const mallory = await user('mallory');
      await alice.client.sendText(bob.userId, 'for bob');
      assert.deepEqual(await mallory.relay.fetch(bob.userId), []);
      assert.equal((await bob.relay.fetch(bob.userId)).length, 1);
    });

    test("can't publish a bundle for someone else, or with a rogue authority's certificate", async () => {
      const alice = await user('alice');
      const mallory = await user('mallory');
      const aliceBundle = await mallory.relay.lookup(alice.userId);
      // Mallory signs the request with her own key but sends alice's enrollment certificate.
      const body = Buffer.from(JSON.stringify(aliceBundle));
      const h = { ...signRequest(mallory.relay.signer, 'PUT', '/v1/bundle', body, Date.now()), 'x-mm-user': alice.userId };
      assert.equal((await raw('/v1/bundle', { method: 'PUT', headers: h, body })).status, 401);

      await assert.rejects(user('rogue', undefined, new Authority()), /relay 401: bad certificate signature/);
    });

    test('revocation: only Authority-signed revocations are accepted; revoked users are cut off', async () => {
      const alice = await user('alice');
      const bob = await user('bob');
      await alice.client.sendText(bob.userId, 'before');
      await bob.client.sync();

      const forged = new Authority().revoke(alice.client.enrollment!.body.serial, 'forged');
      await assert.rejects(alice.relay.publishRevocation(forged), /bad revocation signature/);

      await bob.relay.publishRevocation(authority.revoke(alice.client.enrollment!.body.serial, 'device lost'));
      await assert.rejects(alice.relay.fetch(alice.userId), /relay 403/);
      await assert.rejects(bob.client.sendText(alice.userId, 'x'), /unknown user/); // server hides revoked users
      await assert.rejects(bob.relay.takePreKeys(alice.userId), /relay 404/);

      const trust = new RemoteTrust(authority.publicKey, authority.sealedSenderTrustRoot);
      assert.ok((await trust.refresh(bob.relay)) >= 1);
      assert.ok(trust.isRevoked(alice.client.enrollment!.body.serial));
    });

    test('oversized and malformed envelopes are refused', async () => {
      const alice = await user('alice');
      const bob = await user('bob');
      const send = (env: unknown) => {
        const body = Buffer.from(JSON.stringify(env));
        return raw('/v1/messages', { method: 'POST', headers: signRequest(alice.relay.signer, 'POST', '/v1/messages', body, Date.now()), body });
      };
      const id = '0'.repeat(32);
      assert.equal((await send({ v: 1, id, to: bob.userId, sealed: Buffer.alloc(300 * 1024).toString('base64') })).status, 413);
      assert.equal((await send({ v: 1, id: 'x', to: bob.userId, sealed: 'AAAA' })).status, 400);
      assert.equal((await send({ v: 1, id, to: 'nobody', sealed: 'AAAA' })).status, 404);
    });

    test('WebSocket pushes a notification when a message arrives', async () => {
      const alice = await user('alice');
      const bob = await user('bob');
      let notified!: () => void;
      const got = new Promise<void>((r) => (notified = r));
      let calls = 0;
      const close = await bob.relay.subscribe(() => {
        if (++calls === 2) notified(); // first call is the "ready" on connect
      });
      await alice.client.sendText(bob.userId, 'ping');
      await got;
      assert.equal((await bob.client.sync())[0].kind, 'plain');
      close();
    });

    test('WebSocket refuses a bad signature and a replayed URL', async () => {
      const bob = await user('bob');
      const wsUrl = (p: string) => base.replace('http', 'ws') + p;
      const opens = (u: string) =>
        new Promise<boolean>((r) => {
          const ws = new WebSocket(u);
          ws.addEventListener('open', () => (ws.close(), r(true)));
          ws.addEventListener('error', () => r(false));
        });
      const good = signedWebSocketPath(bob.relay.signer, Date.now());
      assert.equal(await opens(wsUrl(good)), true);
      assert.equal(await opens(wsUrl(good)), false, 'replayed');
      const tampered = signedWebSocketPath(bob.relay.signer, Date.now()).replace(/sig=[^&]+/, 'sig=' + encodeURIComponent(Buffer.alloc(64).toString('base64')));
      assert.equal(await opens(wsUrl(tampered)), false);
    });
  });
}

test('rate limiting returns 429', async () => {
  const app = createRelayApp({ store: new MemoryStore(), authorityPublicKey: new Authority().publicKey, rateLimitPerMinute: 3, log: () => {} });
  await new Promise<void>((r) => app.server.listen(0, '127.0.0.1', () => r()));
  const url = `http://127.0.0.1:${(app.server.address() as AddressInfo).port}/healthz`;
  const codes = [];
  for (let i = 0; i < 5; i++) codes.push((await fetch(url)).status);
  assert.deepEqual(codes, [200, 200, 200, 429, 429]);
  await app.close();
});

test('HttpRelay refuses plain http to a remote host', () => {
  assert.throws(() => new HttpRelay('http://relay.example.com'), /https/);
  new HttpRelay('https://relay.example.com');
});

describe('rate limiting by IP and by verified user', () => {
  const authority = new Authority();
  const start = async (opts: { rateLimitPerMinute: number; ipRateLimitPerMinute: number; clientIpHeader?: string }) => {
    const app = createRelayApp({ store: new MemoryStore(), authorityPublicKey: authority.publicKey, log: () => {}, ...opts });
    await new Promise<void>((r) => app.server.listen(0, '127.0.0.1', () => r()));
    return { app, base: `http://127.0.0.1:${(app.server.address() as AddressInfo).port}` };
  };

  test('inventing user names does not get around the IP limit', async () => {
    const { app, base } = await start({ rateLimitPerMinute: 100, ipRateLimitPerMinute: 3 });
    const codes = [];
    for (let i = 0; i < 5; i++) codes.push((await fetch(`${base}/v1/messages`, { headers: { 'x-mm-user': `fake-${i}` } })).status);
    assert.deepEqual(codes, [401, 401, 401, 429, 429]);
    await app.close();
  });

  test("an attacker claiming a user's name does not use up that user's allowance", async () => {
    const { app, base } = await start({ rateLimitPerMinute: 3, ipRateLimitPerMinute: 1000 });
    const relay = new TestRelay(base);
    const bob = await enroll(authority, { userId: 'bob', relay, trust: authority, audit: authority.audit, device: goodDevice('p', Date.now()), pin: PIN });
    for (let i = 0; i < 10; i++) await fetch(`${base}/v1/messages`, { headers: { 'x-mm-user': 'bob' } }); // unsigned spam
    assert.equal((await relay.fetch('bob')).length, 0, 'bob still gets through');
    await relay.fetch('bob');
    await assert.rejects(relay.fetch('bob'), /relay 429/, 'his own requests are limited');
    void bob;
    await app.close();
  });

  test('uses the configured client IP header (e.g. fly-client-ip)', async () => {
    const { app, base } = await start({ rateLimitPerMinute: 100, ipRateLimitPerMinute: 2, clientIpHeader: 'fly-client-ip' });
    const hit = (ip: string) => fetch(`${base}/healthz`, { headers: { 'fly-client-ip': ip } }).then((r) => r.status);
    assert.deepEqual([await hit('1.1.1.1'), await hit('1.1.1.1'), await hit('1.1.1.1')], [200, 200, 429]);
    assert.equal(await hit('2.2.2.2'), 200, 'a different client has its own allowance');
    await app.close();
  });
});
