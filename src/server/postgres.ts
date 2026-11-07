/**
 * Postgres storage for the relay. Tables are created on startup.
 *
 * Times are stored as epoch milliseconds (bigint).
 */
import pg from 'pg';
import type { Revocation, Signed } from '../authority.ts';
import type { FetchedPreKeys, PublicPreKeys, TransportEnvelope } from '../layer1.ts';
import type { PublicBundle } from '../relay.ts';
import type { RelayStore } from './store.ts';

const SCHEMA = `
CREATE TABLE IF NOT EXISTS bundles (
  user_id     text PRIMARY KEY,
  aci         text NOT NULL UNIQUE,
  enrollment  jsonb NOT NULL,
  clearance   jsonb,
  prekeys     jsonb NOT NULL,          -- public pre-keys without the one-time keys
  updated_at  bigint NOT NULL
);
CREATE TABLE IF NOT EXISTS one_time_prekeys (
  user_id     text NOT NULL REFERENCES bundles(user_id) ON DELETE CASCADE,
  key_id      integer NOT NULL,
  public_key  text NOT NULL,
  PRIMARY KEY (user_id, key_id)
);
CREATE TABLE IF NOT EXISTS messages (
  recipient   text NOT NULL,
  id          text NOT NULL,
  envelope    jsonb NOT NULL,
  received_at bigint NOT NULL,
  PRIMARY KEY (recipient, id)
);
CREATE INDEX IF NOT EXISTS messages_received_at ON messages (received_at);
CREATE TABLE IF NOT EXISTS revocations (
  serial      text PRIMARY KEY,
  record      jsonb NOT NULL
);
CREATE TABLE IF NOT EXISTS request_nonces (
  nonce       text PRIMARY KEY,
  expires_at  bigint NOT NULL
);
`;

type BundleRow = { enrollment: PublicBundle['enrollment']; clearance: PublicBundle['clearance'] | null; prekeys: Omit<PublicPreKeys, 'oneTimePreKeys'> };

const toBundle = (r: BundleRow): PublicBundle => ({
  enrollment: r.enrollment,
  clearance: r.clearance ?? undefined,
  preKeys: { ...r.prekeys, oneTimePreKeys: [] },
});

export class PostgresStore implements RelayStore {
  #pool: pg.Pool;

  constructor(connectionString: string, poolSize = 10) {
    this.#pool = new pg.Pool({ connectionString, max: poolSize });
  }

  async init(): Promise<void> {
    await this.#pool.query(SCHEMA);
  }

  async close(): Promise<void> {
    await this.#pool.end();
  }

  async ping(): Promise<void> {
    await this.#pool.query('SELECT 1');
  }

  async #tx<T>(fn: (c: pg.PoolClient) => Promise<T>): Promise<T> {
    const c = await this.#pool.connect();
    try {
      await c.query('BEGIN');
      const r = await fn(c);
      await c.query('COMMIT');
      return r;
    } catch (err) {
      await c.query('ROLLBACK');
      throw err;
    } finally {
      c.release();
    }
  }

  async putBundle(userId: string, bundle: PublicBundle, now: number): Promise<void> {
    const { oneTimePreKeys, ...prekeys } = bundle.preKeys;
    await this.#tx(async (c) => {
      await c.query(
        `INSERT INTO bundles (user_id, aci, enrollment, clearance, prekeys, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (user_id) DO UPDATE
           SET aci = EXCLUDED.aci, enrollment = EXCLUDED.enrollment, clearance = EXCLUDED.clearance,
               prekeys = EXCLUDED.prekeys, updated_at = EXCLUDED.updated_at`,
        [userId, bundle.enrollment.body.aci, bundle.enrollment, bundle.clearance ?? null, prekeys, now],
      );
      await c.query('DELETE FROM one_time_prekeys WHERE user_id = $1', [userId]);
      if (oneTimePreKeys.length) {
        await c.query(
          `INSERT INTO one_time_prekeys (user_id, key_id, public_key)
           SELECT $1, * FROM unnest($2::integer[], $3::text[])`,
          [userId, oneTimePreKeys.map((k) => k.id), oneTimePreKeys.map((k) => k.publicKey)],
        );
      }
    });
  }

  async getBundle(userId: string): Promise<PublicBundle | undefined> {
    const r = await this.#pool.query<BundleRow>('SELECT enrollment, clearance, prekeys FROM bundles WHERE user_id = $1', [userId]);
    return r.rows[0] && toBundle(r.rows[0]);
  }

  async findByAci(aci: string): Promise<PublicBundle | undefined> {
    const r = await this.#pool.query<BundleRow>('SELECT enrollment, clearance, prekeys FROM bundles WHERE aci = $1', [aci]);
    return r.rows[0] && toBundle(r.rows[0]);
  }

  async takePreKeys(userId: string): Promise<FetchedPreKeys | undefined> {
    return this.#tx(async (c) => {
      const b = await c.query<BundleRow>('SELECT enrollment, clearance, prekeys FROM bundles WHERE user_id = $1', [userId]);
      if (!b.rows[0]) return undefined;
      // SKIP LOCKED: two senders at once never get the same one-time key.
      const k = await c.query<{ key_id: number; public_key: string }>(
        `DELETE FROM one_time_prekeys
         WHERE user_id = $1 AND key_id = (
           SELECT key_id FROM one_time_prekeys WHERE user_id = $1 ORDER BY key_id LIMIT 1 FOR UPDATE SKIP LOCKED)
         RETURNING key_id, public_key`,
        [userId],
      );
      const one = k.rows[0];
      return { ...b.rows[0].prekeys, oneTimePreKey: one ? { id: one.key_id, publicKey: one.public_key } : undefined };
    });
  }

  async remainingPreKeys(userId: string): Promise<number> {
    const r = await this.#pool.query<{ n: string }>('SELECT count(*) AS n FROM one_time_prekeys WHERE user_id = $1', [userId]);
    return Number(r.rows[0].n);
  }

  async enqueue(env: TransportEnvelope, now: number): Promise<boolean> {
    const r = await this.#pool.query(
      'INSERT INTO messages (recipient, id, envelope, received_at) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING',
      [env.to, env.id, env, now],
    );
    return r.rowCount === 1;
  }

  async listMessages(userId: string, limit: number): Promise<TransportEnvelope[]> {
    const r = await this.#pool.query<{ envelope: TransportEnvelope }>(
      'SELECT envelope FROM messages WHERE recipient = $1 ORDER BY received_at, id LIMIT $2',
      [userId, limit],
    );
    return r.rows.map((x) => x.envelope);
  }

  async ack(userId: string, ids: string[]): Promise<number> {
    const r = await this.#pool.query('DELETE FROM messages WHERE recipient = $1 AND id = ANY($2::text[])', [userId, ids]);
    return r.rowCount ?? 0;
  }

  async addRevocation(rev: Signed<Revocation>): Promise<void> {
    await this.#pool.query('INSERT INTO revocations (serial, record) VALUES ($1, $2) ON CONFLICT DO NOTHING', [rev.body.serial, rev]);
  }

  async isRevoked(serial: string): Promise<boolean> {
    const r = await this.#pool.query('SELECT 1 FROM revocations WHERE serial = $1', [serial]);
    return (r.rowCount ?? 0) > 0;
  }

  async revocations(): Promise<Signed<Revocation>[]> {
    const r = await this.#pool.query<{ record: Signed<Revocation> }>('SELECT record FROM revocations ORDER BY serial');
    return r.rows.map((x) => x.record);
  }

  async useNonce(nonce: string, expiresAt: number, now: number): Promise<boolean> {
    const r = await this.#pool.query(
      `INSERT INTO request_nonces (nonce, expires_at) VALUES ($1, $2)
       ON CONFLICT (nonce) DO UPDATE SET expires_at = EXCLUDED.expires_at WHERE request_nonces.expires_at <= $3`,
      [nonce, expiresAt, now],
    );
    return r.rowCount === 1;
  }

  async purge(now: number, messageRetentionMs: number): Promise<void> {
    await this.#pool.query('DELETE FROM request_nonces WHERE expires_at <= $1', [now]);
    await this.#pool.query('DELETE FROM messages WHERE received_at < $1', [now - messageRetentionMs]);
  }
}
