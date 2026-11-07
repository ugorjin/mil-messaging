/**
 * The relay server (stand-in for a self-hosted message server).
 *
 * It holds public key bundles and queues encrypted envelopes per recipient. It
 * never holds a private key, so it cannot read messages; it does not even learn
 * who sent a message (sealed sender).
 *
 * PROTOTYPE NOTE: no transport security, authentication, rate limiting or
 * message-size padding. Production adds mutual TLS, device authentication for
 * fetch, padding to fixed size buckets, and on-premises / air-gapped hosting.
 */
import type { ClearanceCert, EnrollmentCert, Signed } from './authority.ts';
import type { TransportEnvelope } from './layers.ts';

export interface PublicBundle {
  enrollment: Signed<EnrollmentCert>;
  clearance?: Signed<ClearanceCert>;
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
