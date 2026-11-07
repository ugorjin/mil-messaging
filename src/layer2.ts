/**
 * Layer 2: the classified envelope, used only for classified messages.
 *
 *  - a fresh random 256-bit message key encrypts the text (AES-256-GCM);
 *  - that key is encrypted to the recipient's clearance public key, whose
 *    private half only exists on their hardware token;
 *  - the header (sender, recipient, label, handling rules, cert serial) is
 *    authenticated as associated data, so changing the label (e.g.
 *    downgrading SECRET to CONFIDENTIAL) makes decryption fail.
 *
 * The whole envelope is then sent inside layer 1 (the Signal session).
 */
import type { Label } from './classification.ts';
import { canonical, open, seal, wrapTo, type Sealed, type Wrapped } from './crypto.ts';
import { randomBytes } from 'node:crypto';
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
