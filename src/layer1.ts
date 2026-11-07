/**
 * Layer 1: the Signal protocol, via libsignal (@signalapp/libsignal-client),
 * the same library the Signal apps use.
 *
 *  - Sessions start with PQXDH: X25519 plus Kyber (ML-KEM) pre-keys, so traffic
 *    recorded today stays safe against a future quantum computer.
 *  - Messages then use the Double Ratchet: forward secrecy (a stolen key can't
 *    decrypt earlier messages) and post-compromise security (the session heals
 *    after a key is stolen).
 *  - Every message is wrapped in sealed sender: the relay sees only the
 *    recipient. The sender's identity is inside the encryption, proved by a
 *    short-lived sender certificate from the organisation's Authority.
 *  - Identity keys are trusted only if they match the user's enrollment
 *    certificate from the Authority (not trust-on-first-use), so a server
 *    that swaps in its own keys is refused.
 *
 * PROTOTYPE NOTE: stores are in memory. Production stores them encrypted on
 * the device (keys in the Secure Enclave / Android Keystore) and replenishes
 * one-time pre-keys and rotates signed pre-keys on a schedule.
 */
import {
  Direction,
  IdentityChange,
  IdentityKeyPair,
  IdentityKeyStore,
  KEMKeyPair,
  KEMPublicKey,
  KyberPreKeyRecord,
  KyberPreKeyStore,
  PreKeyBundle,
  PreKeyRecord,
  PreKeyStore,
  PrivateKey,
  ProtocolAddress,
  PublicKey,
  SenderCertificate,
  SessionRecord,
  SessionStore,
  SignedPreKeyRecord,
  SignedPreKeyStore,
  processPreKeyBundle,
  sealedSenderDecryptMessage,
  sealedSenderEncryptMessage,
} from '@signalapp/libsignal-client';
import { randomInt } from 'node:crypto';
import type { ClassifiedEnvelope } from './layer2.ts';

export const DEVICE_ID = 1;

const b64 = (b: Uint8Array): string => Buffer.from(b).toString('base64');
const unb64 = (s: string): Uint8Array<ArrayBuffer> => Uint8Array.from(Buffer.from(s, 'base64'));
const addrKey = (a: ProtocolAddress): string => `${a.name()}.${a.deviceId()}`;

export const encodePublicKey = (k: PublicKey): string => b64(k.serialize());
export const decodePublicKey = (s: string): PublicKey => PublicKey.deserialize(unb64(s));

// ----------------------------------------------------------- What it carries

interface InnerBase {
  v: 1;
  msgId: string;
  from: string;
  to: string;
  sentAt: number;
}

/** The application message carried inside the Signal session. */
export type Inner =
  | (InnerBase & { kind: 'plain'; body: string })
  | (InnerBase & { kind: 'classified'; classified: ClassifiedEnvelope });

/** What the relay server stores and forwards. */
export interface TransportEnvelope {
  v: 1;
  id: string;
  to: string;
  /** Sealed-sender Signal message, base64. */
  sealed: string;
}

/** The public pre-key bundle a user publishes so others can start a session. */
export interface PublicPreKeys {
  registrationId: number;
  deviceId: number;
  identityKey: string;
  signedPreKey: { id: number; publicKey: string; signature: string };
  kyberPreKey: { id: number; publicKey: string; signature: string };
  oneTimePreKeys: { id: number; publicKey: string }[];
}

/** One bundle handed out by the server: at most one one-time pre-key, used once. */
export type FetchedPreKeys = Omit<PublicPreKeys, 'oneTimePreKeys'> & { oneTimePreKey?: { id: number; publicKey: string } };

// ------------------------------------------------------------- Key stores

/** Looks up the identity key the Authority certified for a user ID (aci). */
export type ExpectedIdentity = (aci: string) => Promise<PublicKey | undefined>;

class Identities extends IdentityKeyStore {
  #pair: IdentityKeyPair;
  #registrationId: number;
  #known = new Map<string, PublicKey>();
  #expected: ExpectedIdentity;

  constructor(pair: IdentityKeyPair, registrationId: number, expected: ExpectedIdentity) {
    super();
    this.#pair = pair;
    this.#registrationId = registrationId;
    this.#expected = expected;
  }
  async getIdentityKey(): Promise<PrivateKey> {
    return this.#pair.privateKey;
  }
  async getLocalRegistrationId(): Promise<number> {
    return this.#registrationId;
  }
  async saveIdentity(name: ProtocolAddress, key: PublicKey): Promise<IdentityChange> {
    const prev = this.#known.get(addrKey(name));
    this.#known.set(addrKey(name), key);
    return prev && !prev.equals(key) ? IdentityChange.ReplacedExisting : IdentityChange.NewOrUnchanged;
  }
  /** Fail closed: only the key in the Authority-signed enrollment certificate is trusted. */
  async isTrustedIdentity(name: ProtocolAddress, key: PublicKey, _direction: Direction): Promise<boolean> {
    const expected = await this.#expected(name.name());
    return expected !== undefined && expected.equals(key);
  }
  async getIdentity(name: ProtocolAddress): Promise<PublicKey | null> {
    return this.#known.get(addrKey(name)) ?? null;
  }
}

class Sessions extends SessionStore {
  #s = new Map<string, Uint8Array<ArrayBuffer>>();
  async saveSession(name: ProtocolAddress, record: SessionRecord): Promise<void> {
    this.#s.set(addrKey(name), Uint8Array.from(record.serialize()));
  }
  async getSession(name: ProtocolAddress): Promise<SessionRecord | null> {
    const r = this.#s.get(addrKey(name));
    return r ? SessionRecord.deserialize(r) : null;
  }
  async getExistingSessions(addresses: ProtocolAddress[]): Promise<SessionRecord[]> {
    return Promise.all(addresses.map(async (a) => {
      const s = await this.getSession(a);
      if (!s) throw new Error(`no session for ${addrKey(a)}`);
      return s;
    }));
  }
}

class PreKeys extends PreKeyStore {
  #k = new Map<number, Uint8Array<ArrayBuffer>>();
  async savePreKey(id: number, record: PreKeyRecord): Promise<void> {
    this.#k.set(id, Uint8Array.from(record.serialize()));
  }
  async getPreKey(id: number): Promise<PreKeyRecord> {
    const r = this.#k.get(id);
    if (!r) throw new Error(`no pre-key ${id}`);
    return PreKeyRecord.deserialize(r);
  }
  async removePreKey(id: number): Promise<void> {
    this.#k.delete(id); // one-time pre-keys are deleted after use
  }
}

class SignedPreKeys extends SignedPreKeyStore {
  #k = new Map<number, Uint8Array<ArrayBuffer>>();
  async saveSignedPreKey(id: number, record: SignedPreKeyRecord): Promise<void> {
    this.#k.set(id, Uint8Array.from(record.serialize()));
  }
  async getSignedPreKey(id: number): Promise<SignedPreKeyRecord> {
    const r = this.#k.get(id);
    if (!r) throw new Error(`no signed pre-key ${id}`);
    return SignedPreKeyRecord.deserialize(r);
  }
}

class KyberPreKeys extends KyberPreKeyStore {
  #k = new Map<number, Uint8Array<ArrayBuffer>>();
  #used = new Set<string>();
  async saveKyberPreKey(id: number, record: KyberPreKeyRecord): Promise<void> {
    this.#k.set(id, Uint8Array.from(record.serialize()));
  }
  async getKyberPreKey(id: number): Promise<KyberPreKeyRecord> {
    const r = this.#k.get(id);
    if (!r) throw new Error(`no Kyber pre-key ${id}`);
    return KyberPreKeyRecord.deserialize(r);
  }
  /** Last-resort Kyber key: reject a second session start with the same base key (replay). */
  async markKyberPreKeyUsed(id: number, signedPreKeyId: number, baseKey: PublicKey): Promise<void> {
    const k = `${id}|${signedPreKeyId}|${encodePublicKey(baseKey)}`;
    if (this.#used.has(k)) throw new Error('replayed session start');
    this.#used.add(k);
  }
}

// ---------------------------------------------------------------- Endpoint

/** One user's device in the Signal protocol. */
export class SignalEndpoint {
  readonly aci: string;
  readonly address: ProtocolAddress;
  readonly identityKey: PublicKey;
  #identityPrivate: PrivateKey;
  #identities: Identities;
  #sessions = new Sessions();
  #preKeys = new PreKeys();
  #signedPreKeys = new SignedPreKeys();
  #kyberPreKeys = new KyberPreKeys();
  #public: PublicPreKeys;

  private constructor(aci: string, pair: IdentityKeyPair, registrationId: number, expected: ExpectedIdentity, pub: PublicPreKeys) {
    this.aci = aci;
    this.address = ProtocolAddress.new(aci, DEVICE_ID);
    this.identityKey = pair.publicKey;
    this.#identityPrivate = pair.privateKey;
    this.#identities = new Identities(pair, registrationId, expected);
    this.#public = pub;
  }

  /** Generate the identity key and pre-keys (signed EC, signed Kyber, and one-time EC). */
  static async create(aci: string, expected: ExpectedIdentity, oneTimeCount = 20): Promise<SignalEndpoint> {
    const pair = IdentityKeyPair.generate();
    const registrationId = randomInt(1, 16380);
    const now = Date.now();

    const spk = PrivateKey.generate();
    const spkSig = pair.privateKey.sign(spk.getPublicKey().serialize());
    const kyber = KEMKeyPair.generate();
    const kyberSig = pair.privateKey.sign(kyber.getPublicKey().serialize());
    const oneTime = Array.from({ length: oneTimeCount }, (_, i) => ({ id: i + 1, key: PrivateKey.generate() }));

    const pub: PublicPreKeys = {
      registrationId,
      deviceId: DEVICE_ID,
      identityKey: encodePublicKey(pair.publicKey),
      signedPreKey: { id: 1, publicKey: encodePublicKey(spk.getPublicKey()), signature: b64(spkSig) },
      kyberPreKey: { id: 1, publicKey: b64(kyber.getPublicKey().serialize()), signature: b64(kyberSig) },
      oneTimePreKeys: oneTime.map((k) => ({ id: k.id, publicKey: encodePublicKey(k.key.getPublicKey()) })),
    };
    const ep = new SignalEndpoint(aci, pair, registrationId, expected, pub);
    await ep.#signedPreKeys.saveSignedPreKey(1, SignedPreKeyRecord.new(1, now, spk.getPublicKey(), spk, spkSig));
    await ep.#kyberPreKeys.saveKyberPreKey(1, KyberPreKeyRecord.new(1, now, kyber, kyberSig));
    for (const k of oneTime) await ep.#preKeys.savePreKey(k.id, PreKeyRecord.new(k.id, k.key.getPublicKey(), k.key));
    return ep;
  }

  /** Sign with the identity key (used to authenticate requests to the relay). */
  sign(data: Uint8Array): Uint8Array {
    return this.#identityPrivate.sign(Uint8Array.from(data));
  }

  publicPreKeys(): PublicPreKeys {
    return structuredClone(this.#public);
  }

  async hasSession(recipientAci: string): Promise<boolean> {
    return (await this.#sessions.getSession(ProtocolAddress.new(recipientAci, DEVICE_ID))) !== null;
  }

  /**
   * Encrypt to a recipient. If there is no session yet, `fetchPreKeys` is called
   * once to start one (PQXDH). libsignal checks the pre-key signatures, and our
   * identity store checks the identity key against the Authority's certificate.
   */
  async encrypt(
    recipientAci: string,
    plaintext: Uint8Array,
    senderCert: SenderCertificate,
    fetchPreKeys: () => Promise<FetchedPreKeys>,
    now: number,
  ): Promise<string> {
    const addr = ProtocolAddress.new(recipientAci, DEVICE_ID);
    if (!(await this.hasSession(recipientAci))) {
      const p = await fetchPreKeys();
      const bundle = PreKeyBundle.new(
        p.registrationId,
        p.deviceId,
        p.oneTimePreKey?.id ?? null,
        p.oneTimePreKey ? decodePublicKey(p.oneTimePreKey.publicKey) : null,
        p.signedPreKey.id,
        decodePublicKey(p.signedPreKey.publicKey),
        unb64(p.signedPreKey.signature),
        decodePublicKey(p.identityKey),
        p.kyberPreKey.id,
        KEMPublicKey.deserialize(unb64(p.kyberPreKey.publicKey)),
        unb64(p.kyberPreKey.signature),
      );
      await processPreKeyBundle(bundle, addr, this.address, this.#sessions, this.#identities, new Date(now));
    }
    return b64(await sealedSenderEncryptMessage(Uint8Array.from(plaintext), addr, senderCert, this.#sessions, this.#identities));
  }

  /**
   * Decrypt a sealed-sender message. libsignal checks the sender certificate
   * against the trust root and its expiry, and that it matches the identity key
   * that encrypted the message; the ratchet rejects duplicates (replays).
   */
  async decrypt(sealed: string, trustRoot: PublicKey, now: number): Promise<{ senderAci: string; plaintext: Buffer }> {
    const r = await sealedSenderDecryptMessage(
      unb64(sealed),
      trustRoot,
      now,
      null,
      this.aci,
      DEVICE_ID,
      this.#sessions,
      this.#identities,
      this.#preKeys,
      this.#signedPreKeys,
      this.#kyberPreKeys,
    );
    return { senderAci: r.senderUuid(), plaintext: Buffer.from(r.message()) };
  }
}
