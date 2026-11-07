/**
 * Authority command-line tool.
 *
 *   npm run authority -- init [file]                       create keys (default: authority.secret.json)
 *   npm run authority -- public [file]                     print the public keys / AUTHORITY_PUBLIC_KEY
 *   npm run authority -- revoke <serial> <relay-url> [reason] [file]   sign a revocation and publish it
 *
 * The secrets file holds the Authority's private keys. Keep it offline, out of
 * git and out of the container image. In production these keys live in an HSM.
 */
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { Authority } from '../authority.ts';
import { HttpRelay } from '../http-relay.ts';

const DEFAULT_FILE = 'authority.secret.json';
const [cmd, ...args] = process.argv.slice(2);

const load = (file: string) => {
  if (!existsSync(file)) throw new Error(`${file} not found; run: npm run authority -- init`);
  return new Authority({ secrets: readFileSync(file, 'utf8') });
};

const printPublic = (a: Authority) => {
  console.log(`AUTHORITY_PUBLIC_KEY=${a.publicKey}`);
  console.log(`SEALED_SENDER_TRUST_ROOT=${a.sealedSenderTrustRoot}`);
};

switch (cmd) {
  case 'init': {
    const file = args[0] ?? DEFAULT_FILE;
    if (existsSync(file)) throw new Error(`${file} already exists; refusing to overwrite`);
    const a = new Authority();
    writeFileSync(file, a.exportSecrets(), { mode: 0o600 });
    console.error(`wrote ${file} (private keys, mode 600)`);
    printPublic(a);
    break;
  }
  case 'public':
    printPublic(load(args[0] ?? DEFAULT_FILE));
    break;
  case 'revoke': {
    const [serial, relayUrl, reason = 'unspecified', file = DEFAULT_FILE] = args;
    if (!serial || !relayUrl) throw new Error('usage: revoke <serial> <relay-url> [reason] [file]');
    await new HttpRelay(relayUrl).publishRevocation(load(file).revoke(serial, reason));
    console.log(`revoked ${serial}`);
    break;
  }
  default:
    console.error('usage: npm run authority -- init|public|revoke ...');
    process.exit(1);
}
