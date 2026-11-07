import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { AccessDenied, AuditLog, HardwareToken, openClassified, sealClassified, sealTransport, type ClassifiedHeader, type Inner } from '../src/index.ts';
import { canonical, newEd25519, randomId, signData } from '../src/crypto.ts';
import { PIN, world } from './helpers.ts';

const ops = (level: 'CONFIDENTIAL' | 'SECRET' | 'TOP_SECRET', compartments = ['OPS']) => ({ level, compartments });

test('plain messages round-trip with end-to-end encryption', () => {
  const w = world();
  const alice = w.user('alice');
  const bob = w.user('bob');
  alice.client.sendText('bob', 'hello bob');
  const [m] = bob.client.sync();
  assert.equal(m.kind, 'plain');
  assert.equal(m.kind === 'plain' && m.body, 'hello bob');
  assert.equal(m.from, 'alice');
});

test('relay server sees only recipient and ciphertext (sealed sender)', () => {
  const w = world();
  const alice = w.user('alice', ops('SECRET'));
  w.user('bob', ops('SECRET'));
  alice.client.sendText('bob', 'meet at grid 4417');
  alice.client.sendClassified('bob', 'convoy departs 0400', { level: 'SECRET', compartments: ['OPS'] });
  const stored = JSON.stringify(w.relay.stored());
  for (const leak of ['alice', 'grid 4417', 'convoy', 'SECRET', 'OPS']) {
    assert.ok(!stored.includes(leak), `server can see "${leak}"`);
  }
});

test('classified message opens with token + PIN and is watermarked', () => {
  const w = world();
  const alice = w.user('alice', ops('SECRET'));
  const bob = w.user('bob', ops('TOP_SECRET'));
  const id = alice.client.sendClassified('bob', 'convoy departs 0400', { level: 'SECRET', compartments: ['OPS'] });

  const [m] = bob.client.sync();
  assert.equal(m.kind, 'classified');
  assert.equal(m.kind === 'classified' && m.label, 'SECRET//OPS');
  assert.ok(!JSON.stringify(m).includes('convoy'), 'locked message must not expose text');

  const view = bob.client.openClassified(id, bob.token, PIN);
  assert.equal(view.text, 'convoy departs 0400');
  assert.match(view.watermark, /SECRET\/\/OPS · bob · bob-phone/);
  assert.equal(view.canForward, false);
});

test('sender cannot send to a recipient whose clearance is too low', () => {
  const w = world();
  const alice = w.user('alice', ops('SECRET'));
  w.user('carol', ops('CONFIDENTIAL'));
  w.user('dave'); // no clearance
  assert.throws(() => alice.client.sendClassified('carol', 'x', { level: 'SECRET', compartments: ['OPS'] }), AccessDenied);
  assert.throws(() => alice.client.sendClassified('dave', 'x', { level: 'CONFIDENTIAL' }), AccessDenied);
  assert.equal(w.relay.stored().length, 0);
});

test('missing need-to-know compartment blocks the send', () => {
  const w = world();
  const alice = w.user('alice', ops('TOP_SECRET', ['OPS', 'SIGINT']));
  w.user('bob', ops('TOP_SECRET', ['OPS']));
  assert.throws(() => alice.client.sendClassified('bob', 'x', { level: 'SECRET', compartments: ['SIGINT'] }), /does not cover/);
});

test('sender cannot send above their own clearance', () => {
  const w = world();
  const carol = w.user('carol', ops('CONFIDENTIAL'));
  w.user('bob', ops('TOP_SECRET'));
  assert.throws(() => carol.client.sendClassified('bob', 'x', { level: 'SECRET' }), /your clearance/);
});

test('wrong PIN fails; three wrong PINs lock the token and erase the key', () => {
  const w = world();
  const alice = w.user('alice', ops('SECRET'));
  const bob = w.user('bob', ops('SECRET'));
  const id = alice.client.sendClassified('bob', 'secret text', { level: 'SECRET' });
  bob.client.sync();
  assert.throws(() => bob.client.openClassified(id, bob.token, '000000'), /attempts left/);
  assert.throws(() => bob.client.openClassified(id, bob.token, '000000'), /attempts left/);
  assert.throws(() => bob.client.openClassified(id, bob.token, '000000'), /locked/);
  assert.ok(bob.token.locked);
  assert.throws(() => bob.client.openClassified(id, bob.token, PIN), /locked/);
});

test("another user's token cannot open the message", () => {
  const w = world();
  const alice = w.user('alice', ops('SECRET'));
  const bob = w.user('bob', ops('SECRET'));
  const eve = w.user('eve', ops('SECRET'));
  const id = alice.client.sendClassified('bob', 'for bob only', { level: 'SECRET' });
  bob.client.sync();
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

test('forged messages (signed by the wrong key) are rejected and logged', () => {
  const w = world();
  const bob = w.user('bob');
  w.user('alice');
  // An attacker knows bob's public transport key and builds a message claiming to be from alice.
  const attackerKey = newEd25519();
  const unsigned = { v: 1 as const, kind: 'plain' as const, msgId: randomId(), from: 'alice', to: 'bob', sentAt: w.clock.t, body: 'send the codes' };
  const forged = { ...unsigned, sig: signData(attackerKey.privateKey, canonical(unsigned)) } as Inner;
  w.relay.deliver(sealTransport(forged, w.relay.lookup('bob')!.enrollment.body.transportPub));
  assert.deepEqual(bob.client.sync(), []);
  assert.ok(w.authority.audit.entries().some((e) => e.event === 'REJECTED_MESSAGE' && /bad signature/.test(e.detail ?? '')));
});

test('revoked clearance blocks both sending and opening', () => {
  const w = world();
  const alice = w.user('alice', ops('SECRET'));
  const bob = w.user('bob', ops('SECRET'));
  const id = alice.client.sendClassified('bob', 'before revocation', { level: 'SECRET' });
  bob.client.sync();
  const bobSerial = w.relay.lookup('bob')!.clearance!.body.serial;
  w.authority.revoke(bobSerial, 'clearance suspended');
  assert.throws(() => bob.client.openClassified(id, bob.token, PIN), /revoked/);
  assert.throws(() => alice.client.sendClassified('bob', 'after', { level: 'SECRET' }), /revoked/);
});

test('expired clearance blocks opening', () => {
  const w = world();
  const alice = w.user('alice', ops('SECRET'));
  const bob = w.user('bob', ops('SECRET'), 30);
  const id = alice.client.sendClassified('bob', 'x', { level: 'SECRET' });
  bob.client.sync();
  w.clock.t += 31 * 86_400_000;
  assert.throws(() => bob.client.openClassified(id, bob.token, PIN), /expired/);
});

test('message expiry: cannot be opened after its time to live', () => {
  const w = world();
  const alice = w.user('alice', ops('SECRET'));
  const bob = w.user('bob', ops('SECRET'));
  const id = alice.client.sendClassified('bob', 'x', { level: 'SECRET', ttlMs: 60_000 });
  bob.client.sync();
  w.clock.t += 61_000;
  assert.throws(() => bob.client.openClassified(id, bob.token, PIN), /expired/);
  assert.equal(bob.client.hasMessage(id), false, 'expired message is erased');
});

test('view-once: erased after the first open', () => {
  const w = world();
  const alice = w.user('alice', ops('SECRET'));
  const bob = w.user('bob', ops('SECRET'));
  const id = alice.client.sendClassified('bob', 'burn after reading', { level: 'SECRET', viewOnce: true });
  bob.client.sync();
  assert.equal(bob.client.openClassified(id, bob.token, PIN).text, 'burn after reading');
  assert.equal(bob.client.hasMessage(id), false);
  assert.throws(() => bob.client.openClassified(id, bob.token, PIN), /already opened/);
});

test('forwarding: blocked by default, re-encrypted to new recipient when allowed', () => {
  const w = world();
  const alice = w.user('alice', ops('SECRET'));
  const bob = w.user('bob', ops('SECRET'));
  const carol = w.user('carol', ops('SECRET'));
  w.user('dave', ops('CONFIDENTIAL'));

  const locked = alice.client.sendClassified('bob', 'no forward', { level: 'SECRET', compartments: ['OPS'] });
  const open = alice.client.sendClassified('bob', 'share ok', { level: 'SECRET', compartments: ['OPS'], noForward: false });
  bob.client.sync();

  assert.throws(() => bob.client.forward(locked, 'carol', bob.token, PIN), /forwarding forbidden/);
  assert.throws(() => bob.client.forward(open, 'dave', bob.token, PIN), /does not cover/);

  const fwd = bob.client.forward(open, 'carol', bob.token, PIN);
  carol.client.sync();
  assert.equal(carol.client.openClassified(fwd, carol.token, PIN).text, 'share ok');
});

test('device posture: rooted or unmanaged devices cannot open classified messages', () => {
  const w = world();
  const alice = w.user('alice', ops('SECRET'));
  const bob = w.user('bob', ops('SECRET'));
  const id = alice.client.sendClassified('bob', 'x', { level: 'SECRET' });
  bob.client.sync();
  bob.client.device = { ...bob.client.device, rooted: true, mdmEnrolled: false };
  assert.throws(() => bob.client.openClassified(id, bob.token, PIN), /rooted.*MDM|MDM.*rooted/);
  bob.client.device = { ...bob.client.device, rooted: false, mdmEnrolled: true };
  assert.equal(bob.client.openClassified(id, bob.token, PIN).text, 'x');
});

test('replayed envelopes are ignored', () => {
  const w = world();
  const alice = w.user('alice');
  const bob = w.user('bob');
  alice.client.sendText('bob', 'once');
  const [env] = w.relay.fetch('bob');
  w.relay.deliver(env);
  w.relay.deliver(env);
  assert.equal(bob.client.sync().length, 1);
});

test('audit log records access attempts and detects tampering', () => {
  const w = world();
  const alice = w.user('alice', ops('SECRET'));
  const bob = w.user('bob', ops('SECRET'));
  const id = alice.client.sendClassified('bob', 'audited', { level: 'SECRET' });
  bob.client.sync();
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
