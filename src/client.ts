/**
 * A messaging client (one per user device).
 *
 * Sending a classified message (fails closed: any check failing aborts the send):
 *   1. the sender's own clearance must cover the label (you can't send what you can't read);
 *   2. the recipient's clearance cert must be validly signed, unexpired, unrevoked
 *      and cover the label;
 *   3. layer 2: encrypt to the recipient's clearance key;
 *      layer 1: send inside the Signal session, with sealed sender.
 *
 * Opening a classified message (each failure is denied and written to the audit log):
 *   handling rules (view-once, expiry) → device posture → own clearance still
 *   valid and covering the label → hardware token present + correct PIN →
 *   decrypt → watermark the view.
 */
import { PublicKey, type SenderCertificate } from '@signalapp/libsignal-client';
import { randomUUID } from 'node:crypto';
import type { AuditLog, AuditRecord } from './audit.ts';
import { verifyCert, type ClearanceCert, type EnrollmentCert, type Signed, type TrustAnchor } from './authority.ts';
import { dominates, formatLabel, isLevel, LEVELS, type Label } from './classification.ts';
import { canonical, randomId } from './crypto.ts';
import { deviceViolations, type DeviceState } from './device.ts';
import { decodePublicKey, encodePublicKey, SignalEndpoint, type Inner } from './layer1.ts';
import { openClassified, sealClassified, type ClassifiedHeader, type HandlingPolicy } from './layer2.ts';
import type { Relay } from './relay.ts';
import type { HardwareToken } from './token.ts';

export class AccessDenied extends Error {}

export interface ClientOptions {
  userId: string;
  relay: Relay;
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
  device: DeviceState;
  #relay: Relay;
  #trust: TrustAnchor;
  #trustRoot: PublicKey;
  #audit: AuditLog;
  #now: () => number;

  #signal: SignalEndpoint;
  #enrollment: Signed<EnrollmentCert> | undefined;
  #clearance: Signed<ClearanceCert> | undefined;
  #senderCert: SenderCertificate | undefined;

  #inbox = new Map<string, Inner>();
  #seen = new Set<string>();
  #consumed = new Set<string>();

  private constructor(o: ClientOptions, signal: SignalEndpoint) {
    this.userId = o.userId;
    this.device = o.device;
    this.#relay = o.relay;
    this.#trust = o.trust;
    this.#trustRoot = decodePublicKey(o.trust.sealedSenderTrustRoot);
    this.#audit = o.audit;
    this.#now = o.now ?? Date.now;
    this.#signal = signal;
  }

  /** Create a client and generate its Signal identity and pre-keys. */
  static async create(o: ClientOptions): Promise<Client> {
    let self: Client | undefined;
    const signal = await SignalEndpoint.create(randomUUID(), async (aci) => (self ? self.#certifiedIdentity(aci) : undefined));
    self = new Client(o, signal);
    o.relay.bindIdentity?.({ userId: o.userId, sign: (data) => signal.sign(data) });
    return self;
  }

  get aci(): string {
    return this.#signal.aci;
  }

  get signalIdentityKey(): string {
    return encodePublicKey(this.#signal.identityKey);
  }

  /** Install certificates from the authority and publish the public bundle. */
  async installCertificates(enrollment: Signed<EnrollmentCert>, senderCert: SenderCertificate, clearance?: Signed<ClearanceCert>): Promise<void> {
    const e = verifyCert(this.#trust, enrollment, 'enrollment', this.#now());
    if (e.userId !== this.userId || e.aci !== this.aci || e.signalIdentityKey !== this.signalIdentityKey) {
      throw new Error('enrollment certificate does not match this client');
    }
    if (clearance && clearance.body.userId !== this.userId) throw new Error('clearance certificate is for another user');
    this.#enrollment = enrollment;
    this.#clearance = clearance;
    this.installSenderCertificate(senderCert);
    await this.#relay.publish(this.userId, { enrollment, clearance, preKeys: this.#signal.publicPreKeys() });
  }

  /** Sender certificates are short-lived; the app fetches a new one before it expires. */
  installSenderCertificate(cert: SenderCertificate): void {
    if (cert.senderUuid() !== this.aci) throw new Error('sender certificate is for another account');
    this.#senderCert = cert;
  }

  get enrollment(): Signed<EnrollmentCert> | undefined {
    return this.#enrollment;
  }

  // ------------------------------------------------------------- Sending

  sendText(to: string, body: string): Promise<string> {
    return this.#send({ kind: 'plain', ...this.#base(to), body });
  }

  async sendClassified(to: string, text: string, o: SendClassifiedOptions): Promise<string> {
    if (!isLevel(o.level) || o.level === 'UNCLASSIFIED') throw new Error(`classified level must be one of ${LEVELS.slice(1).join(', ')}`);
    const label: Label = { level: o.level, compartments: [...new Set(o.compartments ?? [])].sort() };
    const labelText = formatLabel(label);
    const now = this.#now();
    const refuse: (reason: string) => never = (reason) => this.#deny(undefined, labelText, `send to ${to} refused: ${reason}`);

    let own: ClearanceCert;
    try {
      own = this.#ownClearance();
    } catch (err) {
      refuse((err as Error).message);
    }
    if (!dominates(own, label)) refuse(`your clearance (${formatLabel(own)}) does not cover ${labelText}`);

    let recipient: ClearanceCert;
    try {
      recipient = await this.#peerClearance(to);
    } catch (err) {
      refuse((err as Error).message);
    }
    if (!dominates(recipient, label)) refuse(`${to}'s clearance (${formatLabel(recipient)}) does not cover ${labelText}`);

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
    const id = await this.#send({ kind: 'classified', ...base, classified });
    this.#log({ event: 'SENT_CLASSIFIED', msgId: id, label: labelText, detail: `to ${to}` });
    return id;
  }

  #base(to: string) {
    return { v: 1 as const, msgId: randomId(), from: this.userId, to, sentAt: this.#now() };
  }

  async #send(inner: Inner): Promise<string> {
    if (!this.#enrollment || !this.#senderCert) throw new Error('client not enrolled');
    if (this.#senderCert.expiration() <= this.#now()) throw new Error('sender certificate expired; fetch a new one from the authority');
    const peer = await this.#peerEnrollment(inner.to);
    const sealed = await this.#signal.encrypt(
      peer.aci,
      canonical(inner),
      this.#senderCert,
      () => this.#relay.takePreKeys(inner.to),
      this.#now(),
    );
    await this.#relay.deliver({ v: 1, id: inner.msgId, to: inner.to, sealed });
    return inner.msgId;
  }

  // ----------------------------------------------------------- Receiving

  /** Fetch new messages. Invalid ones are dropped and logged. */
  async sync(): Promise<ReceivedMessage[]> {
    const out: ReceivedMessage[] = [];
    const envelopes = await this.#relay.fetch(this.userId);
    for (const env of envelopes) {
      let inner: Inner;
      try {
        const { senderAci, plaintext } = await this.#signal.decrypt(env.sealed, this.#trustRoot, this.#now());
        inner = JSON.parse(plaintext.toString('utf8')) as Inner;
        await this.#checkInner(inner, env.id, senderAci);
      } catch (err) {
        this.#log({ event: 'REJECTED_MESSAGE', msgId: env.id, detail: (err as Error).message });
        continue;
      }
      if (this.#seen.has(inner.msgId)) continue; // replay
      this.#seen.add(inner.msgId);
      this.#inbox.set(inner.msgId, inner);

      if (inner.kind === 'plain') {
        out.push({ kind: 'plain', msgId: inner.msgId, from: inner.from, sentAt: inner.sentAt, body: inner.body });
      } else {
        const h = inner.classified.header;
        this.#log({ event: 'RECEIVED_CLASSIFIED', msgId: h.msgId, label: formatLabel(h), detail: `from ${h.from}` });
        out.push({ kind: 'classified', msgId: h.msgId, from: h.from, sentAt: inner.sentAt, label: formatLabel(h), policy: h.policy });
      }
    }
    // Acknowledge only after processing, so a crash mid-sync doesn't lose messages.
    if (envelopes.length) await this.#relay.ack(this.userId, envelopes.map((e) => e.id));
    return out;
  }

  /** libsignal has proved which account sent it; check that matches who the message claims to be from. */
  async #checkInner(inner: Inner, envelopeId: string, senderAci: string): Promise<void> {
    if (inner.to !== this.userId || inner.msgId !== envelopeId) throw new Error('envelope/addressing mismatch');
    const sender = await this.#peerEnrollment(inner.from);
    if (sender.aci !== senderAci) throw new Error(`sender mismatch: message claims to be from ${inner.from}`);
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
      this.#inbox.delete(msgId);
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

    this.#log({ event: 'OPENED', msgId, label, detail: `on ${this.device.deviceId}` });
    if (h.policy.viewOnce) {
      this.#inbox.delete(msgId);
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
  async forward(msgId: string, to: string, token?: HardwareToken, pin?: string): Promise<string> {
    const inner = this.#inbox.get(msgId);
    if (!inner) throw new Error(`no message ${msgId}`);
    if (inner.kind === 'plain') return this.sendText(to, inner.body);

    const h = inner.classified.header;
    if (h.policy.noForward) this.#deny(msgId, formatLabel(h), `forwarding forbidden (attempted to ${to})`);
    if (!token || pin === undefined) throw new AccessDenied('forwarding a classified message requires your token and PIN');
    const view = this.openClassified(msgId, token, pin);
    return this.sendClassified(to, view.text, { level: h.level, compartments: h.compartments, ...h.policy });
  }

  /** Whether the (still encrypted) message is held locally; used to show erasure. */
  hasMessage(msgId: string): boolean {
    return this.#inbox.has(msgId);
  }

  // ------------------------------------------------------------- Helpers

  /** The identity key the authority certified for a Signal account, if still valid. */
  async #certifiedIdentity(aci: string): Promise<PublicKey | undefined> {
    const b = await this.#relay.findByAci(aci);
    if (!b) return undefined;
    try {
      const e = verifyCert(this.#trust, b.enrollment, 'enrollment', this.#now());
      return e.aci === aci ? decodePublicKey(e.signalIdentityKey) : undefined;
    } catch {
      return undefined;
    }
  }

  #ownClearance(): ClearanceCert {
    if (!this.#clearance) throw new AccessDenied('you hold no clearance');
    return verifyCert(this.#trust, this.#clearance, 'clearance', this.#now());
  }

  async #peerEnrollment(userId: string): Promise<EnrollmentCert> {
    const b = await this.#relay.lookup(userId);
    if (!b) throw new Error(`unknown user ${userId}`);
    const e = verifyCert(this.#trust, b.enrollment, 'enrollment', this.#now());
    if (e.userId !== userId) throw new Error(`certificate for ${e.userId} published as ${userId}`);
    return e;
  }

  async #peerClearance(userId: string): Promise<ClearanceCert> {
    const b = await this.#relay.lookup(userId);
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

  #log(r: Omit<AuditRecord, 'ts' | 'actor'>): void {
    this.#audit.append({ ts: this.#now(), actor: this.userId, ...r });
  }

  #deny(msgId: string | undefined, label: string | undefined, reason: string): never {
    this.#log({ event: 'DENIED', msgId, label, detail: reason });
    throw new AccessDenied(reason);
  }
}
