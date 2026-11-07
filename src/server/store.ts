/**
 * Server-side storage. `MemoryStore` is for tests and single-instance trials;
 * `PostgresStore` (postgres.ts) is for real deployments.
 *
 * Everything stored is either public (certificates, public pre-keys,
 * revocations) or opaque ciphertext. Envelopes don't say who sent them.
 */
import type { Revocation, Signed } from '../authority.ts';
import type { FetchedPreKeys, TransportEnvelope } from '../layer1.ts';
import type { PublicBundle } from '../relay.ts';

export interface RelayStore {
  init(): Promise<void>;
  close(): Promise<void>;
  ping(): Promise<void>;
  /** Replace a user's bundle, including their whole set of one-time pre-keys. */
  putBundle(userId: string, bundle: PublicBundle, now: number): Promise<void>;
  /** The bundle without one-time pre-keys (those are only handed out by takePreKeys). */
  getBundle(userId: string): Promise<PublicBundle | undefined>;
  findByAci(aci: string): Promise<PublicBundle | undefined>;
  /** Atomically remove and return one one-time pre-key with the rest of the bundle. */
  takePreKeys(userId: string): Promise<FetchedPreKeys | undefined>;
  remainingPreKeys(userId: string): Promise<number>;
  /** Store an envelope. Returns false if one with the same ID is already queued. */
  enqueue(env: TransportEnvelope, now: number): Promise<boolean>;
  listMessages(userId: string, limit: number): Promise<TransportEnvelope[]>;
  ack(userId: string, ids: string[]): Promise<number>;
  addRevocation(rev: Signed<Revocation>): Promise<void>;
  isRevoked(serial: string): Promise<boolean>;
  revocations(): Promise<Signed<Revocation>[]>;
  /** Record a request nonce. Returns false if it was already used. */
  useNonce(nonce: string, expiresAt: number, now: number): Promise<boolean>;
  /** Delete expired nonces and messages older than the retention period. */
  purge(now: number, messageRetentionMs: number): Promise<void>;
}

const withoutOneTime = (b: PublicBundle): PublicBundle => ({ ...structuredClone(b), preKeys: { ...structuredClone(b.preKeys), oneTimePreKeys: [] } });

export class MemoryStore implements RelayStore {
  #bundles = new Map<string, PublicBundle>();
  #messages = new Map<string, Map<string, { env: TransportEnvelope; at: number }>>();
  #revocations = new Map<string, Signed<Revocation>>();
  #nonces = new Map<string, number>();

  async init(): Promise<void> {}
  async close(): Promise<void> {}
  async ping(): Promise<void> {}

  async putBundle(userId: string, bundle: PublicBundle): Promise<void> {
    for (const [id, b] of this.#bundles) {
      if (id !== userId && b.enrollment.body.aci === bundle.enrollment.body.aci) throw new Error('aci already registered');
    }
    this.#bundles.set(userId, structuredClone(bundle));
  }

  async getBundle(userId: string): Promise<PublicBundle | undefined> {
    const b = this.#bundles.get(userId);
    return b && withoutOneTime(b);
  }

  async findByAci(aci: string): Promise<PublicBundle | undefined> {
    for (const b of this.#bundles.values()) if (b.enrollment.body.aci === aci) return withoutOneTime(b);
    return undefined;
  }

  async takePreKeys(userId: string): Promise<FetchedPreKeys | undefined> {
    const b = this.#bundles.get(userId);
    if (!b) return undefined;
    const { oneTimePreKeys, ...rest } = b.preKeys;
    return structuredClone({ ...rest, oneTimePreKey: oneTimePreKeys.shift() });
  }

  async remainingPreKeys(userId: string): Promise<number> {
    return this.#bundles.get(userId)?.preKeys.oneTimePreKeys.length ?? 0;
  }

  async enqueue(env: TransportEnvelope, now: number): Promise<boolean> {
    const q = this.#messages.get(env.to) ?? new Map();
    this.#messages.set(env.to, q);
    if (q.has(env.id)) return false;
    q.set(env.id, { env: structuredClone(env), at: now });
    return true;
  }

  async listMessages(userId: string, limit: number): Promise<TransportEnvelope[]> {
    return [...(this.#messages.get(userId)?.values() ?? [])].slice(0, limit).map((m) => structuredClone(m.env));
  }

  async ack(userId: string, ids: string[]): Promise<number> {
    const q = this.#messages.get(userId);
    let n = 0;
    for (const id of ids) if (q?.delete(id)) n++;
    return n;
  }

  async addRevocation(rev: Signed<Revocation>): Promise<void> {
    this.#revocations.set(rev.body.serial, structuredClone(rev));
  }

  async isRevoked(serial: string): Promise<boolean> {
    return this.#revocations.has(serial);
  }

  async revocations(): Promise<Signed<Revocation>[]> {
    return [...this.#revocations.values()].map((r) => structuredClone(r));
  }

  async useNonce(nonce: string, expiresAt: number, now: number): Promise<boolean> {
    const exp = this.#nonces.get(nonce);
    if (exp !== undefined && exp > now) return false;
    this.#nonces.set(nonce, expiresAt);
    return true;
  }

  async purge(now: number, messageRetentionMs: number): Promise<void> {
    for (const [n, exp] of this.#nonces) if (exp <= now) this.#nonces.delete(n);
    for (const q of this.#messages.values()) {
      for (const [id, m] of q) if (m.at < now - messageRetentionMs) q.delete(id);
    }
  }

  /** Everything stored, for tests that check what the server can see. */
  dump(): unknown {
    return { bundles: [...this.#bundles.values()], messages: [...this.#messages.values()].flatMap((q) => [...q.values()]) };
  }
}
