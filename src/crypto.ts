/**
 * Cryptographic primitives. Everything is built on Node's built-in `crypto`
 * (OpenSSL): X25519, Ed25519, HKDF-SHA256, AES-256-GCM.
 *
 * PROTOTYPE NOTE: a production build would use audited protocol libraries
 * (libsignal / OpenMLS) and FIPS 140-3 validated modules, with hybrid
 * post-quantum key exchange (X25519 + ML-KEM-768).
 */
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  sign,
  verify,
  type KeyObject,
} from 'node:crypto';

export interface KeyPair {
  publicKey: KeyObject;
  privateKey: KeyObject;
}

export const newX25519 = (): KeyPair => generateKeyPairSync('x25519');
export const newEd25519 = (): KeyPair => generateKeyPairSync('ed25519');

export const exportPub = (k: KeyObject): string =>
  k.export({ format: 'der', type: 'spki' }).toString('base64');

export const importPub = (b64: string): KeyObject =>
  createPublicKey({ key: Buffer.from(b64, 'base64'), format: 'der', type: 'spki' });

export const sha256 = (data: Buffer | string): Buffer => createHash('sha256').update(data).digest();

export const randomId = (): string => randomBytes(16).toString('hex');

function hkdf(ikm: Buffer, salt: Buffer, info: string): Buffer {
  return Buffer.from(hkdfSync('sha256', ikm, salt, Buffer.from(info, 'utf8'), 32));
}

// ---------------------------------------------------------------- AEAD

export interface Sealed {
  iv: string;
  ct: string;
  tag: string;
}

export function seal(key: Buffer, plaintext: Buffer, aad: Buffer): Sealed {
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
  c.setAAD(aad);
  const ct = Buffer.concat([c.update(plaintext), c.final()]);
  return { iv: iv.toString('base64'), ct: ct.toString('base64'), tag: c.getAuthTag().toString('base64') };
}

/** Throws if the ciphertext, tag or associated data was modified. */
export function open(key: Buffer, s: Sealed, aad: Buffer): Buffer {
  const d = createDecipheriv('aes-256-gcm', key, Buffer.from(s.iv, 'base64'), { authTagLength: 16 });
  d.setAAD(aad);
  d.setAuthTag(Buffer.from(s.tag, 'base64'));
  return Buffer.concat([d.update(Buffer.from(s.ct, 'base64')), d.final()]);
}

// ---------------------------------------------- Public-key encryption (ECIES)

/** A secret encrypted to an X25519 public key using an ephemeral key pair. */
export interface Wrapped {
  epk: string; // ephemeral public key
  box: Sealed;
}

function kek(shared: Buffer, epk: string, recipientPub: string, info: string): Buffer {
  // The salt binds both public keys so the derived key is specific to this exchange.
  return hkdf(shared, sha256(epk + '|' + recipientPub), info);
}

export function wrapTo(recipientPubB64: string, secret: Buffer, info: string, aad: Buffer): Wrapped {
  const eph = newX25519();
  const epk = exportPub(eph.publicKey);
  const shared = diffieHellman({ privateKey: eph.privateKey, publicKey: importPub(recipientPubB64) });
  const key = kek(shared, epk, recipientPubB64, info);
  try {
    return { epk, box: seal(key, secret, aad) };
  } finally {
    shared.fill(0);
    key.fill(0);
  }
}

export function unwrapWith(priv: KeyObject, recipientPubB64: string, w: Wrapped, info: string, aad: Buffer): Buffer {
  const shared = diffieHellman({ privateKey: priv, publicKey: importPub(w.epk) });
  const key = kek(shared, w.epk, recipientPubB64, info);
  try {
    return open(key, w.box, aad);
  } finally {
    shared.fill(0);
    key.fill(0);
  }
}

// ---------------------------------------------------------------- Signatures

export const signData = (priv: KeyObject, data: Buffer): string => sign(null, data, priv).toString('base64');

export function verifyData(pubB64: string, data: Buffer, sig: string): boolean {
  try {
    return verify(null, data, importPub(pubB64), Buffer.from(sig, 'base64'));
  } catch {
    return false;
  }
}

// ------------------------------------------------------- Canonical encoding

/** Deterministic JSON (sorted keys) so signatures and AAD are stable. */
export function canonical(v: unknown): Buffer {
  return Buffer.from(stringify(v), 'utf8');
}

function stringify(v: unknown): string {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(stringify).join(',') + ']';
  const obj = v as Record<string, unknown>;
  const keys = Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + stringify(obj[k])).join(',') + '}';
}
