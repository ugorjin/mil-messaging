/**
 * A messaging client (one per user device).
 *
 * Sending a classified message (fails closed: any check failing aborts the send):
 *   1. the sender's own clearance must cover the label (no "write up" you can't read);
 *   2. the recipient's clearance cert must be validly signed, unexpired, unrevoked
 *      and cover the label;
 *   3. layer 2: encrypt to the recipient's clearance key; layer 1: encrypt to their
 *      transport key; sign with the sender's identity key.
 *
 * Opening a classified message (each failure is denied and written to the audit log):
 *   handling rules (view-once, expiry) → device posture → own clearance still
 *   valid and covering the label → hardware token present + correct PIN →
 *   decrypt → watermark the view.
 */
import type { AuditLog } from './audit.ts';
import { verifyCert, type ClearanceCert, type EnrollmentCert, type Signed, type TrustAnchor } from './authority.ts';
import { dominates, formatLabel, isLevel, LEVELS, type Label } from './classification.ts';
import { canonical, exportPub, newEd25519, newX25519, randomId, signData, verifyData } from './crypto.ts';
import { deviceViolations, type DeviceState } from './device.ts';
import {
  openClassified,
  openTransport,
  sealClassified,
  sealTransport,
  type ClassifiedHeader,
  type HandlingPolicy,
  type Inner,
  type InnerUnsigned,
} from './layers.ts';
import type { RelayServer } from './relay.ts';
import type { HardwareToken } from './token.ts';

export class AccessDenied extends Error {}

export interface ClientOptions {
  userId: string;
  relay: RelayServer;
  trust: TrustAnchor;
  audit: AuditLog;
  device: DeviceState;
  now?: () => number;
}

export interface SendClassifiedOptions extends Partial<HandlingPolicy> {
  level: Label['level'];
  compartments?: string[];
  /** Time to live; sets `expiresAt`. */
  ttlMs?: number;
}

export type ReceivedMessage =
  | { kind: 'plain'; msgId: string; from: string; sentAt: number; body: string }
  /** A classified message arrives locked: only its header (the banner) is readable. */
  | { kind: 'classified'; msgId: string; from: string; sentAt: number; label: string; policy: HandlingPolicy };

export interface ClassifiedView {
  msgId: string;
  from: string;
  label: string;
  text: string;
  /** Shown over the text, so a photo of the screen identifies who leaked it. */
  watermark: string;
  canForward: boolean;
}

export class Client {
  readonly userId: string;
  #relay: RelayServer;
  #trust: TrustAnchor;
  #audit: AuditLog;
  #now: () => number;
  device: DeviceState;

  #identity = newEd25519();
  #transport = newX25519();
  #enrollment: Signed<EnrollmentCert> | undefined;
  #clearance: Signed<ClearanceCert> | undefined;

  #inbox = new Map<string, Inner>();
  #seen = new Set<string>();
  #consumed = new Set<string>();

  constructor(o: ClientOptions) {
    this.userId = o.userId;
    this.#relay = o.relay;
    this.#trust = o.trust;
    this.#audit = o.audit;
    this.device = o.device;
    this.#now = o.now ?? Date.now;
  }

  get identityPub(): string {
    return exportPub(this.#identity.publicKey);
  }

  get transportPub(): string {
    return exportPub(this.#transport.publicKey);
  }

  /** Install certificates from the authority and publish the public bundle. */
  installCertificates(enrollment: Signed<EnrollmentCert>, clearance?: Signed<ClearanceCert>): void {
    const e = verifyCert(this.#trust, enrollment, 'enrollment', this.#now());
    if (e.userId !== this.userId || e.identityPub !== this.identityPub || e.transportPub !== this.transportPub) {
      throw new Error('enrollment certificate does not match this client');
    }
    if (clearance && clearance.body.userId !== this.userId) throw new Error('clearance certificate is for another user');
    this.#enrollment = enrollment;
    this.#clearance = clearance;
    this.#relay.publish(this.userId, { enrollment, clearance });
  }

  // ------------------------------------------------------------- Sending

  sendText(to: string, body: string): string {
    return this.#send({ kind: 'plain', ...this.#base(to), body });
  }

  sendClassified(to: string, text: string, o: SendClassifiedOptions): string {
    if (!isLevel(o.level) || o.level === 'UNCLASSIFIED') throw new Error(`classified level must be one of ${LEVELS.slice(1).join(', ')}`);
    const label: Label = { level: o.level, compartments: [...new Set(o.compartments ?? [])].sort() };
    const now = this.#now();

    const own = this.#ownClearance();
    if (!dominates(own, label)) throw new AccessDenied(`your clearance (${formatLabel(own)}) does not cover ${formatLabel(label)}`);

    const recipient = this.#peerClearance(to);
    if (!dominates(recipient, label)) {
      throw new AccessDenied(`${to}'s clearance (${formatLabel(recipient)}) does not cover ${formatLabel(label)}`);
    }

    const base = this.#base(to);
    const header: ClassifiedHeader = {
      v: 1,
      msgId: base.msgId,
      from: this.userId,
      to,
      ...label,
      policy: {
        noForward: o.noForward ?? true,
        viewOnce: o.viewOnce ?? false,
        expiresAt: o.expiresAt ?? (o.ttlMs !== undefined ? now + o.ttlMs : undefined),
      },
      recipientCertSerial: recipient.serial,
      createdAt: now,
    };
    const classified = sealClassified(header, text, recipient.clearancePub);
    this.#log('SENT_CLASSIFIED', base.msgId, formatLabel(label), `to ${to}`);
    return this.#send({ kind: 'classified', ...base, classified });
  }

  #base(to: string) {
    return { v: 1 as const, msgId: randomId(), from: this.userId, to, sentAt: this.#now() };
  }

  #send(inner: InnerUnsigned): string {
    if (!this.#enrollment) throw new Error('client not enrolled');
    const peer = this.#peerEnrollment(inner.to);
    const signed = { ...inner, sig: signData(this.#identity.privateKey, canonical(inner)) } as Inner;
    this.#relay.deliver(sealTransport(signed, peer.transportPub));
    return inner.msgId;
  }

  // ----------------------------------------------------------- Receiving

  /** Fetch new messages. Invalid ones are dropped and logged. */
  sync(): ReceivedMessage[] {
    const out: ReceivedMessage[] = [];
    for (const env of this.#relay.fetch(this.userId)) {
      let inner: Inner;
      try {
        inner = openTransport(env, this.#transport.privateKey, this.transportPub);
        this.#checkInner(inner, env.id);
      } catch (err) {
        this.#log('REJECTED_MESSAGE', env.id, undefined, (err as Error).message);
        continue;
      }
      if (this.#seen.has(inner.msgId)) continue; // replay
      this.#seen.add(inner.msgId);
      this.#inbox.set(inner.msgId, inner);

      if (inner.kind === 'plain') {
        out.push({ kind: 'plain', msgId: inner.msgId, from: inner.from, sentAt: inner.sentAt, body: inner.body });
      } else {
        const h = inner.classified.header;
        this.#log('RECEIVED_CLASSIFIED', h.msgId, formatLabel(h), `from ${h.from}`);
        out.push({ kind: 'classified', msgId: h.msgId, from: h.from, sentAt: inner.sentAt, label: formatLabel(h), policy: h.policy });
      }
    }
    return out;
  }

  #checkInner(inner: Inner, envelopeId: string): void {
    if (inner.to !== this.userId || inner.msgId !== envelopeId) throw new Error('envelope/addressing mismatch');
    const sender = this.#peerEnrollment(inner.from);
    const { sig, ...unsigned } = inner;
    if (!verifyData(sender.identityPub, canonical(unsigned), sig)) throw new Error(`bad signature claiming to be from ${inner.from}`);
    if (inner.kind === 'classified') {
      const h = inner.classified.header;
      if (h.from !== inner.from || h.to !== this.userId || h.msgId !== inner.msgId) throw new Error('classified header mismatch');
    }
  }

  // ---------------------------------------------------- Opening classified

  openClassified(msgId: string, token: HardwareToken, pin: string): ClassifiedView {
    const now = this.#now();
    if (this.#consumed.has(msgId)) this.#deny(msgId, undefined, 'view-once message already opened');
    const inner = this.#inbox.get(msgId);
    if (!inner || inner.kind !== 'classified') throw new Error(`no classified message ${msgId}`);
    const env = inner.classified;
    const h = env.header;
    const label = formatLabel(h);

    if (h.policy.expiresAt !== undefined && now > h.policy.expiresAt) {
      this.#erase(msgId);
      this.#deny(msgId, label, 'message expired');
    }

    const problems = deviceViolations(this.device, now);
    if (problems.length) this.#deny(msgId, label, `device check failed: ${problems.join('; ')}`);

    let own: ClearanceCert;
    try {
      own = this.#ownClearance();
    } catch (err) {
      this.#deny(msgId, label, (err as Error).message);
    }
    if (!dominates(own, h)) this.#deny(msgId, label, `clearance ${formatLabel(own)} does not cover ${label}`);
    if (own.serial !== h.recipientCertSerial) this.#deny(msgId, label, 'message was encrypted to a different clearance certificate');
    if (token.ownerId !== this.userId || token.clearancePublicKey !== own.clearancePub) {
      this.#deny(msgId, label, 'token does not belong to this user');
    }

    let text: string;
    try {
      text = openClassified(env, token, pin);
    } catch (err) {
      this.#deny(msgId, label, `decryption failed: ${(err as Error).message}`);
    }

    this.#log('OPENED', msgId, label, `on ${this.device.deviceId}`);
    if (h.policy.viewOnce) {
      this.#erase(msgId);
      this.#consumed.add(msgId);
    }
    return {
      msgId,
      from: h.from,
      label,
      text,
      watermark: `${label} · ${this.userId} · ${this.device.deviceId} · ${new Date(now).toISOString()}`,
      canForward: !h.policy.noForward,
    };
  }

  /**
   * Forward a message. Plain messages are re-sent as-is. A classified message is
   * re-encrypted to the new recipient (so it needs the token and PIN, and the
   * new recipient's clearance must cover the label) unless forwarding is forbidden.
   */
  forward(msgId: string, to: string, token?: HardwareToken, pin?: string): string {
    const inner = this.#inbox.get(msgId);
    if (!inner) throw new Error(`no message ${msgId}`);
    if (inner.kind === 'plain') return this.sendText(to, inner.body);

    const h = inner.classified.header;
    if (h.policy.noForward) this.#deny(msgId, formatLabel(h), `forwarding forbidden (attempted to ${to})`);
    if (!token || pin === undefined) throw new AccessDenied('forwarding a classified message requires your token and PIN');
    const view = this.openClassified(msgId, token, pin);
    return this.sendClassified(to, view.text, { level: h.level, compartments: h.compartments, ...h.policy });
  }

  /** Locally readable (encrypted) messages; used to show view-once erasure. */
  hasMessage(msgId: string): boolean {
    return this.#inbox.has(msgId);
  }

  // ------------------------------------------------------------- Helpers

  #ownClearance(): ClearanceCert {
    if (!this.#clearance) throw new AccessDenied('you hold no clearance');
    return verifyCert(this.#trust, this.#clearance, 'clearance', this.#now());
  }

  #peerEnrollment(userId: string): EnrollmentCert {
    const b = this.#relay.lookup(userId);
    if (!b) throw new Error(`unknown user ${userId}`);
    const e = verifyCert(this.#trust, b.enrollment, 'enrollment', this.#now());
    if (e.userId !== userId) throw new Error(`certificate for ${e.userId} published as ${userId}`);
    return e;
  }

  #peerClearance(userId: string): ClearanceCert {
    const b = this.#relay.lookup(userId);
    if (!b?.clearance) throw new AccessDenied(`${userId} holds no clearance`);
    let c: ClearanceCert;
    try {
      c = verifyCert(this.#trust, b.clearance, 'clearance', this.#now());
    } catch (err) {
      throw new AccessDenied(`${userId}'s clearance is not valid: ${(err as Error).message}`);
    }
    if (c.userId !== userId) throw new AccessDenied(`clearance for ${c.userId} published as ${userId}`);
    return c;
  }

  #erase(msgId: string): void {
    this.#inbox.delete(msgId);
  }

  #log(event: Parameters<AuditLog['append']>[0]['event'], msgId?: string, label?: string, detail?: string): void {
    this.#audit.append({ ts: this.#now(), actor: this.userId, event, msgId, label, detail });
  }

  #deny(msgId: string, label: string | undefined, reason: string): never {
    this.#log('DENIED', msgId, label, reason);
    throw new AccessDenied(reason);
  }
}
