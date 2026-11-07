import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { randomId } from '../src/crypto.ts';
import { AccessDenied, Authority, AuditLog, HardwareToken, openClassified, sealClassified, type ClassifiedHeader } from '../src/index.ts';
import { PIN, world } from './helpers.ts';

const ops = (level: 'CONFIDENTIAL' | 'SECRET' | 'TOP_SECRET', compartments = ['OPS']) => ({ level, compartments });
const rejections = (w: ReturnType<typeof world>) =>
  w.authority.audit.entries().filter((e) => e.event === 'REJECTED_MESSAGE').map((e) => e.detail ?? '');

// ------------------------------------------------------------- Layer 1 (Signal)

test('plain messages round-trip over a Signal session', async () => {
  const w = world();
  const alice = await w.user('alice');
  const bob = await w.user('bob');
  await alice.client.sendText('bob', 'hello bob');
  const [m] = await bob.client.sync();
  assert.equal(m.kind, 'plain');
  assert.equal(m.kind === 'plain' && m.body, 'hello bob');
  assert.equal(m.from, 'alice');
});

test('two-way conversation keeps working as the Double Ratchet advances', async () => {
  const w = world();
  const alice = await w.user('alice');
  const bob = await w.user('bob');
  const said: string[] = [];
  for (let i = 0; i < 4; i++) {
    await alice.client.sendText('bob', `a${i}`);
    await alice.client.sendText('bob', `a${i}'`);
    said.push(...(await bob.client.sync()).map((m) => (m.kind === 'plain' ? m.body : '')));
    await bob.client.sendText('alice', `b${i}`);
    said.push(...(await alice.client.sync()).map((m) => (m.kind === 'plain' ? m.body : '')));
  }
  assert.deepEqual(said, ["a0", "a0'", 'b0', 'a1', "a1'", 'b1', 'a2', "a2'", 'b2', 'a3', "a3'", 'b3']);
});

test('one-time pre-keys are used once each', async () => {
  const w = world();
  const bob = await w.user('bob');
  const before = w.relay.lookupSync('bob')!.preKeys.oneTimePreKeys.length;
  for (const name of ['alice', 'carol', 'dave']) {
    const u = await w.user(name);
    await u.client.sendText('bob', `hi from ${name}`);
  }
  assert.equal(w.relay.lookupSync('bob')!.preKeys.oneTimePreKeys.length, before - 3);
  assert.equal((await bob.client.sync()).length, 3);
});

test('relay server sees only recipient and ciphertext (sealed sender)', async () => {
  const w = world();
  const alice = await w.user('alice', ops('SECRET'));
  await w.user('bob', ops('SECRET'));
  await alice.client.sendText('bob', 'meet at grid 4417');
  await alice.client.sendClassified('bob', 'convoy departs 0400', { level: 'SECRET', compartments: ['OPS'] });
  const stored = JSON.stringify(w.relay.stored());
  for (const leak of ['alice', alice.client.aci, 'grid 4417', 'convoy', 'SECRET', 'OPS']) {
    assert.ok(!stored.includes(leak), `server can see "${leak}"`);
  }
});

test('server swapping in its own identity key (MITM) is refused', async () => {
  const w = world();
  const alice = await w.user('alice');
  await w.user('bob');
  await w.user('fake-bob');
  // A malicious server hands out fake-bob's pre-keys under bob's name.
  await w.relay.publish('bob', { ...w.relay.lookupSync('bob')!, preKeys: w.relay.lookupSync('fake-bob')!.preKeys });
  await assert.rejects(alice.client.sendText('bob', 'hi'), /untrusted identity/i);
  assert.equal(w.relay.stored().length, 0);
});

test('sender certificate not issued by the organisation is rejected (sealed-sender trust root)', async () => {
  const w = world();
  const bob = await w.user('bob');
  const mallory = await w.user('mallory');
  // Mallory gets a sender certificate for her own account from a rogue authority.
  const rogue = new Authority({ now: w.now });
  const rogueEnrollment = rogue.issueEnrollment('mallory', mallory.client.aci, mallory.client.signalIdentityKey, 86_400_000);
  mallory.client.installSenderCertificate(rogue.issueSenderCertificate(rogueEnrollment));
  await mallory.client.sendText('bob', 'send the codes');
  assert.equal(w.relay.stored().length, 1);
  assert.deepEqual(await bob.client.sync(), []);
  assert.equal(rejections(w).length, 1);
});

test("a valid user cannot get or use another user's sender certificate", async () => {
  const w = world();
  const bob = await w.user('bob');
  const alice = await w.user('alice');
  const mallory = await w.user('mallory');
  const aliceCert = w.authority.issueSenderCertificate(alice.client.enrollment!);
  assert.throws(() => mallory.client.installSenderCertificate(aliceCert), /another account/);
  await mallory.client.sendText('bob', 'hi');
  const [m] = await bob.client.sync();
  assert.equal(m.from, 'mallory');
});

test('replayed envelopes are rejected by the ratchet', async () => {
  const w = world();
  const alice = await w.user('alice');
  const bob = await w.user('bob');
  await alice.client.sendText('bob', 'once');
  const [env] = w.relay.stored();
  assert.equal((await bob.client.sync()).length, 1);
  assert.equal(w.relay.stored().length, 0, 'acknowledged messages are removed');
  // An attacker who recorded the envelope delivers it again.
  await w.relay.deliver(env);
  assert.equal((await bob.client.sync()).length, 0);
  assert.equal(rejections(w).length, 1);
});

test('messages stay queued until the client acknowledges them', async () => {
  const w = world();
  const alice = await w.user('alice');
  await w.user('bob');
  await alice.client.sendText('bob', 'm1');
  await w.relay.fetch('bob'); // e.g. the client crashed before processing
  assert.equal(w.relay.stored().length, 1);
});

test('revoked enrollment: no new sender certificate, and messages to/from them are refused', async () => {
  const w = world();
  const alice = await w.user('alice');
  const bob = await w.user('bob');
  await alice.client.sendText('bob', 'before');
  await bob.client.sync();
  w.authority.revoke(alice.client.enrollment!.body.serial, 'device lost');
  assert.throws(() => w.authority.issueSenderCertificate(alice.client.enrollment!), /revoked/);
  await assert.rejects(bob.client.sendText('alice', 'x'), /revoked/);
  await alice.client.sendText('bob', 'after revocation'); // still has a cert from before...
  assert.deepEqual(await bob.client.sync(), []); // ...but bob refuses it
});

test('expired sender certificate cannot be used', async () => {
  const w = world();
  const alice = await w.user('alice');
  await w.user('bob');
  w.clock.t += 2 * 86_400_000;
  await assert.rejects(alice.client.sendText('bob', 'x'), /sender certificate expired/);
  alice.client.installSenderCertificate(w.authority.issueSenderCertificate(alice.client.enrollment!));
  await alice.client.sendText('bob', 'x');
});

// ---------------------------------------------------------- Layer 2 (classified)

test('classified message opens with token + PIN and is watermarked', async () => {
  const w = world();
  const alice = await w.user('alice', ops('SECRET'));
  const bob = await w.user('bob', ops('TOP_SECRET'));
  const id = await alice.client.sendClassified('bob', 'convoy departs 0400', { level: 'SECRET', compartments: ['OPS'] });

  const [m] = await bob.client.sync();
  assert.equal(m.kind, 'classified');
  assert.equal(m.kind === 'classified' && m.label, 'SECRET//OPS');
  assert.ok(!JSON.stringify(m).includes('convoy'), 'locked message must not expose text');

  const view = bob.client.openClassified(id, bob.token, PIN);
  assert.equal(view.text, 'convoy departs 0400');
  assert.match(view.watermark, /SECRET\/\/OPS · bob · bob-phone/);
  assert.equal(view.canForward, false);
});

test('sender cannot send to a recipient whose clearance is too low', async () => {
  const w = world();
  const alice = await w.user('alice', ops('SECRET'));
  await w.user('carol', ops('CONFIDENTIAL'));
  await w.user('dave'); // no clearance
  await assert.rejects(alice.client.sendClassified('carol', 'x', { level: 'SECRET', compartments: ['OPS'] }), AccessDenied);
  await assert.rejects(alice.client.sendClassified('dave', 'x', { level: 'CONFIDENTIAL' }), AccessDenied);
  assert.equal(w.relay.stored().length, 0);
  assert.equal(w.authority.audit.entries().filter((e) => e.event === 'DENIED').length, 2, 'refused sends are audited');
});

test('missing need-to-know compartment blocks the send', async () => {
  const w = world();
  const alice = await w.user('alice', ops('TOP_SECRET', ['OPS', 'SIGINT']));
  await w.user('bob', ops('TOP_SECRET', ['OPS']));
  await assert.rejects(alice.client.sendClassified('bob', 'x', { level: 'SECRET', compartments: ['SIGINT'] }), /does not cover/);
});

test('sender cannot send above their own clearance', async () => {
  const w = world();
  const carol = await w.user('carol', ops('CONFIDENTIAL'));
  await w.user('bob', ops('TOP_SECRET'));
  await assert.rejects(carol.client.sendClassified('bob', 'x', { level: 'SECRET' }), /your clearance/);
});

test('wrong PIN fails; three wrong PINs lock the token and erase the key', async () => {
  const w = world();
  const alice = await w.user('alice', ops('SECRET'));
  const bob = await w.user('bob', ops('SECRET'));
  const id = await alice.client.sendClassified('bob', 'secret text', { level: 'SECRET' });
  await bob.client.sync();
  assert.throws(() => bob.client.openClassified(id, bob.token, '000000'), /attempts left/);
  assert.throws(() => bob.client.openClassified(id, bob.token, '000000'), /attempts left/);
  assert.throws(() => bob.client.openClassified(id, bob.token, '000000'), /locked/);
  assert.ok(bob.token.locked);
  assert.throws(() => bob.client.openClassified(id, bob.token, PIN), /locked/);
});

test("another user's token cannot open the message", async () => {
  const w = world();
  const alice = await w.user('alice', ops('SECRET'));
  const bob = await w.user('bob', ops('SECRET'));
  const eve = await w.user('eve', ops('SECRET'));
  const id = await alice.client.sendClassified('bob', 'for bob only', { level: 'SECRET' });
  await bob.client.sync();
  assert.throws(() => bob.client.openClassified(id, eve.token, PIN), /token does not belong/);
});

test('changing the label in the header makes layer 2 decryption fail (no downgrade)', () => {
  const token = new HardwareToken('bob', PIN);
  const header: ClassifiedHeader = {
    v: 1, msgId: randomId(), from: 'alice', to: 'bob', level: 'SECRET', compartments: ['OPS'],
    policy: { noForward: true, viewOnce: false }, recipientCertSerial: 'serial-1', createdAt: 0,
  };
  const env = sealClassified(header, 'secret text', token.generateClearanceKey());
  assert.equal(openClassified(env, token, PIN), 'secret text');

  for (const change of [
    (h: ClassifiedHeader) => { h.level = 'CONFIDENTIAL'; },
    (h: ClassifiedHeader) => { h.compartments = []; },
    (h: ClassifiedHeader) => { h.policy.noForward = false; },
    (h: ClassifiedHeader) => { h.to = 'eve'; },
  ]) {
    const tampered = structuredClone(env);
    change(tampered.header);
    assert.throws(() => openClassified(tampered, token, PIN));
  }
});

test('revoked clearance blocks both sending and opening', async () => {
  const w = world();
  const alice = await w.user('alice', ops('SECRET'));
  const bob = await w.user('bob', ops('SECRET'));
  const id = await alice.client.sendClassified('bob', 'before revocation', { level: 'SECRET' });
  await bob.client.sync();
  w.authority.revoke(w.relay.lookupSync('bob')!.clearance!.body.serial, 'clearance suspended');
  assert.throws(() => bob.client.openClassified(id, bob.token, PIN), /revoked/);
  await assert.rejects(alice.client.sendClassified('bob', 'after', { level: 'SECRET' }), /revoked/);
});

test('expired clearance blocks opening', async () => {
  const w = world();
  const alice = await w.user('alice', ops('SECRET'));
  const bob = await w.user('bob', ops('SECRET'), 30);
  const id = await alice.client.sendClassified('bob', 'x', { level: 'SECRET' });
  await bob.client.sync();
  w.clock.t += 31 * 86_400_000;
  assert.throws(() => bob.client.openClassified(id, bob.token, PIN), /expired/);
});

test('message expiry: cannot be opened after its time to live', async () => {
  const w = world();
  const alice = await w.user('alice', ops('SECRET'));
  const bob = await w.user('bob', ops('SECRET'));
  const id = await alice.client.sendClassified('bob', 'x', { level: 'SECRET', ttlMs: 60_000 });
  await bob.client.sync();
  w.clock.t += 61_000;
  assert.throws(() => bob.client.openClassified(id, bob.token, PIN), /expired/);
  assert.equal(bob.client.hasMessage(id), false, 'expired message is erased');
});

test('view-once: erased after the first open', async () => {
  const w = world();
  const alice = await w.user('alice', ops('SECRET'));
  const bob = await w.user('bob', ops('SECRET'));
  const id = await alice.client.sendClassified('bob', 'burn after reading', { level: 'SECRET', viewOnce: true });
  await bob.client.sync();
  assert.equal(bob.client.openClassified(id, bob.token, PIN).text, 'burn after reading');
  assert.equal(bob.client.hasMessage(id), false);
  assert.throws(() => bob.client.openClassified(id, bob.token, PIN), /already opened/);
});

test('forwarding: blocked by default, re-encrypted to new recipient when allowed', async () => {
  const w = world();
  const alice = await w.user('alice', ops('SECRET'));
  const bob = await w.user('bob', ops('SECRET'));
  const carol = await w.user('carol', ops('SECRET'));
  await w.user('dave', ops('CONFIDENTIAL'));

  const locked = await alice.client.sendClassified('bob', 'no forward', { level: 'SECRET', compartments: ['OPS'] });
  const open = await alice.client.sendClassified('bob', 'share ok', { level: 'SECRET', compartments: ['OPS'], noForward: false });
  await bob.client.sync();

  await assert.rejects(bob.client.forward(locked, 'carol', bob.token, PIN), /forwarding forbidden/);
  await assert.rejects(bob.client.forward(open, 'dave', bob.token, PIN), /does not cover/);

  const fwd = await bob.client.forward(open, 'carol', bob.token, PIN);
  await carol.client.sync();
  assert.equal(carol.client.openClassified(fwd, carol.token, PIN).text, 'share ok');
});

test('device posture: rooted or unmanaged devices cannot open classified messages', async () => {
  const w = world();
  const alice = await w.user('alice', ops('SECRET'));
  const bob = await w.user('bob', ops('SECRET'));
  const id = await alice.client.sendClassified('bob', 'x', { level: 'SECRET' });
  await bob.client.sync();
  bob.client.device = { ...bob.client.device, rooted: true, mdmEnrolled: false };
  assert.throws(() => bob.client.openClassified(id, bob.token, PIN), /rooted.*MDM|MDM.*rooted/);
  bob.client.device = { ...bob.client.device, rooted: false, mdmEnrolled: true };
  assert.equal(bob.client.openClassified(id, bob.token, PIN).text, 'x');
});

// --------------------------------------------------------------------- Audit

test('audit log records access attempts and detects tampering', async () => {
  const w = world();
  const alice = await w.user('alice', ops('SECRET'));
  const bob = await w.user('bob', ops('SECRET'));
  const id = await alice.client.sendClassified('bob', 'audited', { level: 'SECRET' });
  await bob.client.sync();
  assert.throws(() => bob.client.openClassified(id, bob.token, '111111'), /wrong PIN/);
  bob.client.openClassified(id, bob.token, PIN);

  const log = w.authority.audit;
  assert.ok(log.verify());
  const events = log.entries().map((e) => e.event);
  for (const e of ['SENT_CLASSIFIED', 'RECEIVED_CLASSIFIED', 'DENIED', 'OPENED']) assert.ok(events.includes(e as never), e);
  assert.ok(!JSON.stringify(log.entries()).includes('audited'), 'audit log must not contain message text');

  const entries = log.entries();
  entries[3].detail = 'nothing happened';
  assert.equal(AuditLog.verifyChain(entries), false);
  assert.equal(AuditLog.verifyChain(log.entries().filter((_, i) => i !== 2)), false);
});
