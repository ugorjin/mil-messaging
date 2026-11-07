/**
 * A simulated hardware security token (smart card / CAC / YubiKey / Secure Enclave).
 *
 * The clearance private key is created inside the token and is never exported.
 * The only operation it offers is "unwrap this message key", and only after the
 * correct PIN. Too many wrong PINs lock the token and erase the key.
 *
 * PROTOTYPE NOTE: here the key is a private JS field in process memory. On a real
 * token it lives in tamper-resistant hardware, and the PIN check, retry counter
 * and user-presence check (touch or biometric) are enforced by the chip.
 */
import { timingSafeEqual } from 'node:crypto';
import { exportPub, newX25519, sha256, unwrapWith, type KeyPair, type Wrapped } from './crypto.ts';

export class TokenError extends Error {}

export class HardwareToken {
  static readonly MAX_PIN_ATTEMPTS = 3;

  readonly ownerId: string;
  #pinHash: Buffer;
  #failures = 0;
  #locked = false;
  #key: KeyPair | undefined;
  #pub: string | undefined;

  constructor(ownerId: string, pin: string) {
    if (!/^\d{6,}$/.test(pin)) throw new TokenError('PIN must be at least 6 digits');
    this.ownerId = ownerId;
    this.#pinHash = sha256('token-pin|' + pin);
  }

  get locked(): boolean {
    return this.#locked;
  }

  get clearancePublicKey(): string | undefined {
    return this.#pub;
  }

  /** Generate the clearance key pair on the token. Returns only the public key. */
  generateClearanceKey(): string {
    if (this.#locked) throw new TokenError('token locked');
    this.#key = newX25519();
    this.#pub = exportPub(this.#key.publicKey);
    return this.#pub;
  }

  unwrap(pin: string, wrapped: Wrapped, info: string, aad: Buffer): Buffer {
    this.#checkPin(pin);
    if (!this.#key || !this.#pub) throw new TokenError('no clearance key on token');
    return unwrapWith(this.#key.privateKey, this.#pub, wrapped, info, aad);
  }

  #checkPin(pin: string): void {
    if (this.#locked) throw new TokenError('token locked');
    if (timingSafeEqual(sha256('token-pin|' + pin), this.#pinHash)) {
      this.#failures = 0;
      return;
    }
    this.#failures++;
    if (this.#failures >= HardwareToken.MAX_PIN_ATTEMPTS) {
      this.#locked = true;
      this.#key = undefined; // erase the key
      throw new TokenError('wrong PIN; token locked and key erased');
    }
    throw new TokenError(`wrong PIN (${HardwareToken.MAX_PIN_ATTEMPTS - this.#failures} attempts left)`);
  }
}
