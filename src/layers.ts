/**
 * The two encryption layers.
 *
 * Layer 2 (classified envelope) — only for classified messages:
 *   - a fresh random 256-bit message key encrypts the text (AES-256-GCM);
 *   - that key is encrypted to the recipient's clearance public key, whose
 *     private half only exists on their hardware token;
 *   - the header (sender, recipient, label, handling rules, cert serial) is
 *     authenticated as associated data, so changing the label (e.g.
 *     downgrading SECRET to CONFIDENTIAL) makes decryption fail.
 *
 * Layer 1 (transport) — for every message:
 *   - the whole signed inner message (including any layer 2 envelope) is
 *     encrypted to the recipient's transport key;
 *   - the sender's identity is inside the encryption ("sealed sender"), so the
 *     relay server sees only the recipient and an opaque blob.
 *
 * PROTOTYPE NOTE: layer 1 uses a fresh ephemeral key per message (ECIES). That
 * protects old messages if a *sender's* key leaks, but not a recipient's. Real
 * deployments should use the Signal Double Ratchet (1:1) or MLS (groups) here.
 */
import type { Label } from './classification.ts';
import { canonical, open, seal, unwrapWith, wrapTo, type Sealed, type Wrapped } from './crypto.ts';
import { randomBytes, type KeyObject } from 'node:crypto';
import type { HardwareToken } from './token.ts';

// ------------------------------------------------------------------ Types

export interface HandlingPolicy {
  /** Recipient may not forward the message. */
  noForward: boolean;
  /** The message is erased after the first successful open. */
  viewOnce: boolean;
  /** After this time (ms since epoch) the message can no longer be opened. */
  expiresAt?: number;
}

export interface ClassifiedHeader extends Label {
  v: 1;
  msgId: string;
  from: string;
  to: string;
  policy: HandlingPolicy;
  /** Serial of the recipient clearance certificate the key was wrapped to. */
  recipientCertSerial: string;
  createdAt: number;
}

export interface ClassifiedEnvelope {
  header: ClassifiedHeader;
  content: Sealed;
  wrappedKey: Wrapped;
}

interface InnerBase {
  v: 1;
  msgId: string;
  from: string;
  to: string;
  sentAt: number;
}

export type InnerUnsigned =
  | (InnerBase & { kind: 'plain'; body: string })
  | (InnerBase & { kind: 'classified'; classified: ClassifiedEnvelope });

/** The inner message, signed with the sender's identity key. */
export type Inner = InnerUnsigned & { sig: string };

/** What the relay server stores and forwards. */
export interface TransportEnvelope {
  v: 1;
  id: string;
  to: string;
  payload: Wrapped;
}

// ---------------------------------------------------------------- Layer 2

const l2Info = (h: ClassifiedHeader): string => `mil-messaging/v1/layer2/${h.level}`;

export function sealClassified(header: ClassifiedHeader, text: string, recipientClearancePub: string): ClassifiedEnvelope {
  const aad = canonical(header);
  const messageKey = randomBytes(32);
  try {
    const content = seal(messageKey, Buffer.from(text, 'utf8'), aad);
    const wrappedKey = wrapTo(recipientClearancePub, messageKey, l2Info(header), aad);
    return { header, content, wrappedKey };
  } finally {
    messageKey.fill(0);
  }
}

/** Needs the recipient's token and PIN. Throws if anything was tampered with. */
export function openClassified(env: ClassifiedEnvelope, token: HardwareToken, pin: string): string {
  const aad = canonical(env.header);
  const messageKey = token.unwrap(pin, env.wrappedKey, l2Info(env.header), aad);
  try {
    return open(messageKey, env.content, aad).toString('utf8');
  } finally {
    messageKey.fill(0);
  }
}

// ---------------------------------------------------------------- Layer 1

const L1_INFO = 'mil-messaging/v1/layer1';
const l1Aad = (id: string, to: string): Buffer => canonical({ v: 1, id, to });

export function sealTransport(inner: Inner, recipientTransportPub: string): TransportEnvelope {
  return {
    v: 1,
    id: inner.msgId,
    to: inner.to,
    payload: wrapTo(recipientTransportPub, canonical(inner), L1_INFO, l1Aad(inner.msgId, inner.to)),
  };
}

export function openTransport(env: TransportEnvelope, transportPriv: KeyObject, transportPub: string): Inner {
  const plain = unwrapWith(transportPriv, transportPub, env.payload, L1_INFO, l1Aad(env.id, env.to));
  return JSON.parse(plain.toString('utf8')) as Inner;
}
