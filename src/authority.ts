/**
 * The organisation's Clearance Authority: a stand-in for its PKI / key
 * management service (in production, backed by an HSM).
 *
 * It issues two kinds of signed certificates:
 *  - EnrollmentCert: binds a user ID to their Signal account ID (aci) and
 *    Signal identity key. Clients trust a peer's identity key only if it
 *    matches this certificate.
 *  - ClearanceCert: binds a user ID to a clearance level, compartments and the
 *    public half of a clearance key that only exists on their hardware token.
 *
 * It is also the trust root for Signal sealed sender: it issues short-lived
 * SenderCertificates (only to enrolled, unrevoked users), which recipients check
 * to learn who sent a message.
 */
import { PrivateKey, PublicKey, ServerCertificate, SenderCertificate } from '@signalapp/libsignal-client';
import { formatLabel, type Label, type Level } from './classification.ts';
import { AuditLog } from './audit.ts';
import { DEVICE_ID } from './layer1.ts';
import { canonical, exportPub, newEd25519, randomId, signData, verifyData } from './crypto.ts';

export interface EnrollmentCert {
  kind: 'enrollment';
  serial: string;
  userId: string;
  aci: string;
  signalIdentityKey: string;
  notAfter: number;
}

export interface ClearanceCert {
  kind: 'clearance';
  serial: string;
  userId: string;
  level: Level;
  compartments: string[];
  clearancePub: string;
  notAfter: number;
}

export interface Signed<T> {
  body: T;
  sig: string;
}

/** What clients need to trust: the authority's public key and its revocation status. */
export interface TrustAnchor {
  readonly publicKey: string;
  /** Sealed-sender trust root (libsignal public key, base64). */
  readonly sealedSenderTrustRoot: string;
  isRevoked(serial: string): boolean;
}

export class CertificateError extends Error {}

export class Authority implements TrustAnchor {
  readonly audit = new AuditLog();
  readonly publicKey: string;
  readonly sealedSenderTrustRoot: string;
  #signingKey = newEd25519();
  #trustRoot = PrivateKey.generate();
  #serverKey = PrivateKey.generate();
  #serverCert = ServerCertificate.new(1, this.#serverKey.getPublicKey(), this.#trustRoot);
  #revoked = new Set<string>();
  #now: () => number;

  constructor(opts: { now?: () => number } = {}) {
    this.#now = opts.now ?? Date.now;
    this.publicKey = exportPub(this.#signingKey.publicKey);
    this.sealedSenderTrustRoot = Buffer.from(this.#trustRoot.getPublicKey().serialize()).toString('base64');
  }

  #sign<T>(body: T): Signed<T> {
    return { body, sig: signData(this.#signingKey.privateKey, canonical(body)) };
  }

  issueEnrollment(userId: string, aci: string, signalIdentityKey: string, validMs: number): Signed<EnrollmentCert> {
    const cert = this.#sign<EnrollmentCert>({
      kind: 'enrollment',
      serial: randomId(),
      userId,
      aci,
      signalIdentityKey,
      notAfter: this.#now() + validMs,
    });
    this.audit.append({ ts: this.#now(), actor: 'authority', event: 'CERT_ISSUED', detail: `enrollment ${userId}` });
    return cert;
  }

  issueClearance(userId: string, label: Label, clearancePub: string, validMs: number): Signed<ClearanceCert> {
    const cert = this.#sign<ClearanceCert>({
      kind: 'clearance',
      serial: randomId(),
      userId,
      level: label.level,
      compartments: [...label.compartments].sort(),
      clearancePub,
      notAfter: this.#now() + validMs,
    });
    this.audit.append({
      ts: this.#now(),
      actor: 'authority',
      event: 'CERT_ISSUED',
      label: formatLabel(label),
      detail: `clearance ${userId}`,
    });
    return cert;
  }

  /**
   * Issue a short-lived sealed-sender certificate. Refused if the enrollment is
   * revoked or expired, so a revoked user's messages stop being accepted once
   * their current certificate runs out.
   */
  issueSenderCertificate(enrollment: Signed<EnrollmentCert>, validMs = 86_400_000): SenderCertificate {
    const e = verifyCert(this, enrollment, 'enrollment', this.#now());
    const identity = PublicKey.deserialize(Buffer.from(e.signalIdentityKey, 'base64'));
    return SenderCertificate.new(e.aci, null, DEVICE_ID, identity, this.#now() + validMs, this.#serverCert, this.#serverKey);
  }

  revoke(serial: string, reason = 'unspecified'): void {
    this.#revoked.add(serial);
    this.audit.append({ ts: this.#now(), actor: 'authority', event: 'CERT_REVOKED', detail: `${serial}: ${reason}` });
  }

  isRevoked(serial: string): boolean {
    return this.#revoked.has(serial);
  }
}

/** Check signature, expiry and revocation. Returns the certificate body or throws. */
export function verifyCert<T extends { serial: string; notAfter: number; kind: string }>(
  trust: TrustAnchor,
  cert: Signed<T>,
  kind: T['kind'],
  now: number,
): T {
  if (cert.body.kind !== kind) throw new CertificateError(`expected ${kind} certificate`);
  if (!verifyData(trust.publicKey, canonical(cert.body), cert.sig)) throw new CertificateError('bad certificate signature');
  if (now > cert.body.notAfter) throw new CertificateError('certificate expired');
  if (trust.isRevoked(cert.body.serial)) throw new CertificateError('certificate revoked');
  return cert.body;
}
