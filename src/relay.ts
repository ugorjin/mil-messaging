/**
 * The relay: holds public key bundles (certificates and Signal pre-keys) and
 * queues sealed-sender envelopes per recipient. It never holds a private key,
 * so it cannot read messages, and the stored envelopes don't say who sent them.
 *
 * `Relay` is what a client talks to. Two implementations:
 *  - `RelayServer` (this file): in memory, used by tests and the demo;
 *  - `HttpRelay` (src/http-relay.ts): talks to the real server in src/server/.
 */
import type { ClearanceCert, EnrollmentCert, Signed } from './authority.ts';
import type { FetchedPreKeys, PublicPreKeys, TransportEnvelope } from './layer1.ts';

export interface PublicBundle {
  enrollment: Signed<EnrollmentCert>;
  clearance?: Signed<ClearanceCert>;
  preKeys: PublicPreKeys;
}

/** Signs relay requests with the device's Signal identity key (proves who is asking). */
export interface RequestSigner {
  userId: string;
  sign(data: Uint8Array): Uint8Array;
}

export interface Relay {
  /** Called once by the client so a networked relay can sign its requests. */
  bindIdentity?(signer: RequestSigner): void;
  publish(userId: string, bundle: PublicBundle): Promise<void>;
  lookup(userId: string): Promise<PublicBundle | undefined>;
  findByAci(aci: string): Promise<PublicBundle | undefined>;
  /** A pre-key bundle with at most one one-time pre-key, which is removed from the server. */
  takePreKeys(userId: string): Promise<FetchedPreKeys>;
  deliver(env: TransportEnvelope): Promise<void>;
  /** Queued envelopes for the caller. They stay queued until acknowledged. */
  fetch(userId: string): Promise<TransportEnvelope[]>;
  ack(userId: string, ids: string[]): Promise<void>;
}

export class RelayServer implements Relay {
  #bundles = new Map<string, PublicBundle>();
  #queues = new Map<string, Map<string, TransportEnvelope>>();

  async publish(userId: string, bundle: PublicBundle): Promise<void> {
    this.#bundles.set(userId, structuredClone(bundle));
  }

  async lookup(userId: string): Promise<PublicBundle | undefined> {
    return this.lookupSync(userId);
  }

  /** Synchronous access for tests. */
  lookupSync(userId: string): PublicBundle | undefined {
    const b = this.#bundles.get(userId);
    return b && structuredClone(b);
  }

  async findByAci(aci: string): Promise<PublicBundle | undefined> {
    for (const b of this.#bundles.values()) if (b.enrollment.body.aci === aci) return structuredClone(b);
    return undefined;
  }

  async takePreKeys(userId: string): Promise<FetchedPreKeys> {
    const b = this.#bundles.get(userId);
    if (!b) throw new Error(`unknown user ${userId}`);
    const { oneTimePreKeys, ...rest } = b.preKeys;
    return structuredClone({ ...rest, oneTimePreKey: oneTimePreKeys.shift() });
  }

  /** Envelopes are keyed by ID, so delivering the same one twice stores it once. */
  async deliver(env: TransportEnvelope): Promise<void> {
    const q = this.#queues.get(env.to) ?? new Map<string, TransportEnvelope>();
    if (!q.has(env.id)) q.set(env.id, structuredClone(env));
    this.#queues.set(env.to, q);
  }

  async fetch(userId: string): Promise<TransportEnvelope[]> {
    return [...(this.#queues.get(userId)?.values() ?? [])].map((e) => structuredClone(e));
  }

  async ack(userId: string, ids: string[]): Promise<void> {
    const q = this.#queues.get(userId);
    for (const id of ids) q?.delete(id);
  }

  /** Everything the server can currently see. Used in tests and the demo. */
  stored(): TransportEnvelope[] {
    return [...this.#queues.values()].flatMap((q) => [...q.values()]).map((e) => structuredClone(e));
  }
}
