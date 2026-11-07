/**
 * Trust anchor for a networked client: the Authority's public keys (installed
 * with the app) plus a revocation list fetched from the relay. Each revocation
 * is checked against the Authority's signature, so the relay can't invent
 * revocations; it could only withhold them, which is why clients should refresh
 * often and production should also use short-lived certificates.
 */
import { verifyRevocation, type Revocation, type Signed, type TrustAnchor } from './authority.ts';

export class RemoteTrust implements TrustAnchor {
  readonly publicKey: string;
  readonly sealedSenderTrustRoot: string;
  #revoked = new Set<string>();

  constructor(publicKey: string, sealedSenderTrustRoot: string) {
    this.publicKey = publicKey;
    this.sealedSenderTrustRoot = sealedSenderTrustRoot;
  }

  isRevoked(serial: string): boolean {
    return this.#revoked.has(serial);
  }

  /** Add revocations from the relay; ones with a bad signature are ignored. Returns how many were accepted. */
  async refresh(source: { revocations(): Promise<Signed<Revocation>[]> }): Promise<number> {
    let n = 0;
    for (const rev of await source.revocations()) {
      try {
        this.#revoked.add(verifyRevocation(this.publicKey, rev).serial);
        n++;
      } catch {
        // forged or corrupted: ignore
      }
    }
    return n;
  }
}
