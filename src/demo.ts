/** Walkthrough of the two-layer scheme. Run: npm run demo */
import { Authority, Client, enroll, RelayServer, type DeviceState, type Label } from './index.ts';

const PIN = '482913';
const authority = new Authority();
const relay = new RelayServer();

const device = (id: string): DeviceState => ({
  deviceId: id,
  mdmEnrolled: true,
  rooted: false,
  osPatchDate: new Date(Date.now() - 7 * 86_400_000).toISOString().slice(0, 10),
  screenCaptureBlocked: true,
});

function user(userId: string, clearance?: Label) {
  const client = new Client({ userId, relay, trust: authority, audit: authority.audit, device: device(`${userId}-phone`) });
  return { client, token: enroll(authority, client, { pin: PIN, clearance }) };
}

const step = (s: string) => console.log(`\n── ${s}`);
const attempt = (what: string, fn: () => unknown) => {
  try {
    const r = fn();
    console.log(`   ✔ ${what}${r !== undefined ? `: ${typeof r === 'string' ? r : JSON.stringify(r)}` : ''}`);
  } catch (e) {
    console.log(`   ✘ ${what}: ${(e as Error).message}`);
  }
};

step('Enrolment: authority issues certificates; clearance keys are generated on hardware tokens');
const alice = user('alice', { level: 'SECRET', compartments: ['OPS'] });
const bob = user('bob', { level: 'TOP_SECRET', compartments: ['OPS'] });
const carol = user('carol', { level: 'CONFIDENTIAL', compartments: [] });
console.log('   alice SECRET//OPS · bob TOP_SECRET//OPS · carol CONFIDENTIAL');

step('Ordinary message (layer 1 only)');
alice.client.sendText('bob', 'Morning brief moved to 0800.');
for (const m of bob.client.sync()) console.log('   bob received:', m);

step('Classified message (layer 2 inside layer 1)');
const id = alice.client.sendClassified('bob', 'Convoy departs 0400 via route BLUE.', {
  level: 'SECRET',
  compartments: ['OPS'],
  ttlMs: 3_600_000,
});
console.log('   what the relay server stores:', JSON.stringify(relay.stored()[0]).slice(0, 140) + '…');
const [locked] = bob.client.sync();
console.log('   bob sees a locked banner:', locked);

step('Opening it requires the right token, PIN, device and clearance');
attempt('bob opens with wrong PIN', () => bob.client.openClassified(id, bob.token, '000000'));
attempt('bob opens with carol’s token', () => bob.client.openClassified(id, carol.token, PIN));
bob.client.device = { ...bob.client.device, rooted: true };
attempt('bob opens on a rooted phone', () => bob.client.openClassified(id, bob.token, PIN));
bob.client.device = { ...bob.client.device, rooted: false };
attempt('bob opens correctly', () => {
  const v = bob.client.openClassified(id, bob.token, PIN);
  return `"${v.text}"  [watermark: ${v.watermark}]`;
});

step('Handling rules');
attempt('bob forwards it to alice', () => bob.client.forward(id, 'alice', bob.token, PIN));
attempt('alice sends SECRET to carol (CONFIDENTIAL)', () => alice.client.sendClassified('carol', 'x', { level: 'SECRET' }));
attempt('carol sends SECRET (above her own clearance)', () => carol.client.sendClassified('bob', 'x', { level: 'SECRET' }));
const once = alice.client.sendClassified('bob', 'Authenticator for today: TANGO-7.', { level: 'SECRET', viewOnce: true });
bob.client.sync();
attempt('bob opens view-once message', () => bob.client.openClassified(once, bob.token, PIN).text);
attempt('bob opens it again', () => bob.client.openClassified(once, bob.token, PIN).text);

step('Revocation: clearance suspended');
const later = alice.client.sendClassified('bob', 'New grid reference.', { level: 'SECRET' });
bob.client.sync();
authority.revoke(relay.lookup('bob')!.clearance!.body.serial, 'clearance suspended pending review');
attempt('bob opens after revocation', () => bob.client.openClassified(later, bob.token, PIN));
attempt('alice sends to bob after revocation', () => alice.client.sendClassified('bob', 'x', { level: 'SECRET' }));

step('Audit log (events only, no content; hash-chained)');
for (const e of authority.audit.entries()) {
  console.log(`   #${String(e.seq).padStart(2)} ${e.actor.padEnd(9)} ${e.event.padEnd(19)} ${(e.label ?? '').padEnd(12)} ${e.detail ?? ''}`);
}
console.log(`   chain intact: ${authority.audit.verify()}`);
