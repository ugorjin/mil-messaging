/**
 * End-to-end demo against a running relay server.
 *
 *   RELAY_URL=http://localhost:8080 npm run net-demo
 *
 * Uses the Authority keys in authority.secret.json (or AUTHORITY_SECRETS) to
 * enroll two users, then sends a plain and a classified message through the
 * server, with push notification over the WebSocket.
 */
import { readFileSync } from 'node:fs';
import { Authority, enroll, HttpRelay, RemoteTrust, type DeviceState } from './index.ts';

const relayUrl = process.env.RELAY_URL ?? 'http://localhost:8080';
const authority = new Authority({ secrets: readFileSync(process.env.AUTHORITY_SECRETS ?? 'authority.secret.json', 'utf8') });
const PIN = '482913';
const run = Date.now().toString(36);

const device = (id: string): DeviceState => ({
  deviceId: id,
  mdmEnrolled: true,
  rooted: false,
  osPatchDate: new Date(Date.now() - 7 * 86_400_000).toISOString().slice(0, 10),
  screenCaptureBlocked: true,
});

async function user(name: string) {
  const relay = new HttpRelay(relayUrl);
  // A real app ships with the Authority's public keys and refreshes revocations from the relay.
  const trust = new RemoteTrust(authority.publicKey, authority.sealedSenderTrustRoot);
  await trust.refresh(relay);
  const userId = `${name}-${run}`;
  const r = await enroll(authority, {
    userId,
    relay,
    trust,
    audit: authority.audit,
    device: device(`${name}-phone`),
    pin: PIN,
    clearance: { level: 'SECRET', compartments: ['OPS'] },
  });
  return { ...r, relay, userId };
}

console.log(`relay: ${relayUrl}`);
const alice = await user('alice');
const bob = await user('bob');
console.log(`enrolled ${alice.userId} and ${bob.userId} (SECRET//OPS)`);

let wake!: () => void;
let pushes = 0;
const arrived = new Promise<void>((r) => (wake = r));
const unsubscribe = await bob.relay.subscribe(() => {
  if (++pushes > 1) wake();
});

await alice.client.sendText(bob.userId, 'Morning brief moved to 0800.');
const id = await alice.client.sendClassified(bob.userId, 'Convoy departs 0400 via route BLUE.', { level: 'SECRET', compartments: ['OPS'], ttlMs: 3_600_000 });
await arrived;
console.log('bob: push notification received');

for (const m of await bob.client.sync()) {
  if (m.kind === 'plain') console.log(`bob received from ${m.from}: "${m.body}"`);
  else console.log(`bob received a locked ${m.label} message from ${m.from}`);
}
const view = bob.client.openClassified(id, bob.token, PIN);
console.log(`bob opened it: "${view.text}"\n  watermark: ${view.watermark}`);

await bob.client.sendText(alice.userId, 'Copy. Acknowledged.');
console.log(`alice received: "${(await alice.client.sync()).map((m) => (m.kind === 'plain' ? m.body : m.label)).join(', ')}"`);
unsubscribe();
