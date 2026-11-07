/**
 * The relay server (stand-in for a self-hosted message server).
 *
 * It holds public key bundles (certificates and Signal pre-keys) and queues
 * sealed-sender envelopes per recipient. It
 * never holds a private key, so it cannot read messages; it does not even learn
 * who sent a message (sealed sender).
 *
 * PROTOTYPE NOTE: no transport security, authentication, rate limiting or
 * message-size padding. Production adds mutual TLS, device authentication for
 * fetch, padding to fixed size buckets, and on-premises / air-gapped hosting.
 */
import type { ClearanceCert, EnrollmentCert, Signed } from './authority.ts';
import type { FetchedPreKeys, PublicPreKeys, TransportEnvelope } from './layer1.ts';

export interface PublicBundle {
  enrollment: Signed<EnrollmentCert>;
  clearance?: Signed<ClearanceCert>;
  preKeys: PublicPreKeys;
}

export class RelayServer {
  #bundles = new Map<string, PublicBundle>();
  #queues = new Map<string, TransportEnvelope[]>();

  publish(userId: string, bundle: PublicBundle): void {
    this.#bundles.set(userId, bundle);
  }

  lookup(userId: string): PublicBundle | undefined {
    return this.#bundles.get(userId);
  }

  /** Find a user by Signal account ID. Untrusted: callers verify the certificate. */
  findByAci(aci: string): PublicBundle | undefined {
    for (const b of this.#bundles.values()) if (b.enrollment.body.aci === aci) return b;
    return undefined;
  }

  /** Hand out a pre-key bundle with at most one one-time pre-key, which is then removed. */
  takePreKeys(userId: string): FetchedPreKeys {
    const b = this.#bundles.get(userId);
    if (!b) throw new Error(`unknown user ${userId}`);
    const { oneTimePreKeys, ...rest } = b.preKeys;
    return structuredClone({ ...rest, oneTimePreKey: oneTimePreKeys.shift() });
  }

  deliver(env: TransportEnvelope): void {
    const q = this.#queues.get(env.to) ?? [];
    q.push(structuredClone(env));
    this.#queues.set(env.to, q);
  }

  /** Remove and return everything queued for a user. */
  fetch(userId: string): TransportEnvelope[] {
    const q = this.#queues.get(userId) ?? [];
    this.#queues.delete(userId);
    return q;
  }

  /** Everything the server can currently see. Used in tests and the demo. */
  stored(): TransportEnvelope[] {
    return [...this.#queues.values()].flat().map((e) => structuredClone(e));
  }
}
