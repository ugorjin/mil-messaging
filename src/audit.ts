/**
 * Tamper-evident audit log. Each entry includes the hash of the previous entry,
 * so editing, deleting or reordering any entry breaks the chain.
 *
 * It records events (who, what, when, label), never message content.
 */
import { canonical, sha256 } from './crypto.ts';

export type AuditEvent =
  | 'CERT_ISSUED'
  | 'CERT_REVOKED'
  | 'SENT_CLASSIFIED'
  | 'RECEIVED_CLASSIFIED'
  | 'OPENED'
  | 'DENIED'
  | 'REJECTED_MESSAGE';

export interface AuditRecord {
  ts: number;
  actor: string;
  event: AuditEvent;
  msgId?: string;
  label?: string;
  detail?: string;
}

export interface AuditEntry extends AuditRecord {
  seq: number;
  prevHash: string;
  hash: string;
}

const GENESIS = '0'.repeat(64);

const hashEntry = (e: Omit<AuditEntry, 'hash'>): string => sha256(canonical(e)).toString('hex');

export class AuditLog {
  #entries: AuditEntry[] = [];

  append(r: AuditRecord): AuditEntry {
    const prevHash = this.#entries.at(-1)?.hash ?? GENESIS;
    const body = { ...r, seq: this.#entries.length, prevHash };
    const entry: AuditEntry = { ...body, hash: hashEntry(body) };
    this.#entries.push(entry);
    return entry;
  }

  /** A copy of the entries (changing it does not change the log). */
  entries(): AuditEntry[] {
    return this.#entries.map((e) => ({ ...e }));
  }

  verify(): boolean {
    return AuditLog.verifyChain(this.#entries);
  }

  static verifyChain(entries: AuditEntry[]): boolean {
    let prev = GENESIS;
    for (const [i, e] of entries.entries()) {
      const { hash, ...body } = e;
      if (e.seq !== i || e.prevHash !== prev || hashEntry(body) !== hash) return false;
      prev = hash;
    }
    return true;
  }
}
