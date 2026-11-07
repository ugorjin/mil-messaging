/**
 * The organisation's Clearance Authority: a stand-in for its PKI / key
 * management service (in production, backed by an HSM).
 *
 * It issues two kinds of signed certificates:
 *  - EnrollmentCert: binds a user ID to their identity (signing) key and
 *    transport (layer 1) key.
 *  - ClearanceCert: binds a user ID to a clearance level, compartments and the
 *    public half of a clearance key that only exists on their hardware token.
 */
import { formatLabel, type Label, type Level } from './classification.ts';
import { AuditLog } from './audit.ts';
import { canonical, exportPub, newEd25519, randomId, signData, verifyData } from './crypto.ts';

export interface EnrollmentCert {
  kind: 'enrollment';
  serial: string;
  userId: string;
  identityPub: string;
  transportPub: string;
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
  isRevoked(serial: string): boolean;
}

export class CertificateError extends Error {}

export class Authority implements TrustAnchor {
  readonly audit = new AuditLog();
  readonly publicKey: string;
  #signingKey = newEd25519();
  #revoked = new Set<string>();
  #now: () => number;

  constructor(opts: { now?: () => number } = {}) {
    this.#now = opts.now ?? Date.now;
    this.publicKey = exportPub(this.#signingKey.publicKey);
  }

  #sign<T>(body: T): Signed<T> {
    return { body, sig: signData(this.#signingKey.privateKey, canonical(body)) };
  }

  issueEnrollment(userId: string, identityPub: string, transportPub: string, validMs: number): Signed<EnrollmentCert> {
    const cert = this.#sign<EnrollmentCert>({
      kind: 'enrollment',
      serial: randomId(),
      userId,
      identityPub,
      transportPub,
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
