/**
 * Relay server entry point. Configuration comes from environment variables:
 *
 *   AUTHORITY_PUBLIC_KEY   required. The Authority's public key (npm run authority -- init prints it).
 *   DATABASE_URL           Postgres connection string. Without it, data is kept in memory
 *                          and lost on restart (only for trying things out).
 *   PORT                   default 8080
 *   HOST                   default 0.0.0.0
 *   MAX_ENVELOPE_BYTES     default 262144
 *   MESSAGE_RETENTION_DAYS undelivered messages are deleted after this, default 30
 *   RATE_LIMIT_PER_MINUTE  per authenticated user, default 600
 *   IP_RATE_LIMIT_PER_MINUTE per client IP, default RATE_LIMIT_PER_MINUTE
 *   TRUST_PROXY            "true" to use X-Forwarded-For (only behind your own proxy)
 *   CLIENT_IP_HEADER       header with the real client IP set by your proxy (Fly.io: fly-client-ip)
 *
 * TLS is expected to be terminated in front of this process (a load balancer or
 * reverse proxy). Never expose it over plain HTTP outside a private network.
 */
import { createRelayApp } from './app.ts';
import { PostgresStore } from './postgres.ts';
import { MemoryStore, type RelayStore } from './store.ts';

const env = process.env;
const log = (e: Record<string, unknown>) => console.log(JSON.stringify({ ts: new Date().toISOString(), ...e }));

const authorityPublicKey = env.AUTHORITY_PUBLIC_KEY?.trim();
if (!authorityPublicKey) {
  log({ level: 'fatal', msg: 'AUTHORITY_PUBLIC_KEY is required' });
  process.exit(1);
}

const store: RelayStore = env.DATABASE_URL ? new PostgresStore(env.DATABASE_URL) : new MemoryStore();
if (!env.DATABASE_URL) log({ level: 'warn', msg: 'DATABASE_URL not set: using in-memory storage (data is lost on restart)' });

const retentionMs = Number(env.MESSAGE_RETENTION_DAYS ?? 30) * 86_400_000;
const port = Number(env.PORT ?? 8080);
const host = env.HOST ?? '0.0.0.0';

for (let attempt = 1; ; attempt++) {
  try {
    await store.init();
    break;
  } catch (err) {
    if (attempt >= 10) throw err;
    log({ level: 'warn', msg: `database not ready (${(err as Error).message}); retrying`, attempt });
    await new Promise((r) => setTimeout(r, 2000));
  }
}

const app = createRelayApp({
  store,
  authorityPublicKey,
  maxEnvelopeBytes: env.MAX_ENVELOPE_BYTES ? Number(env.MAX_ENVELOPE_BYTES) : undefined,
  rateLimitPerMinute: env.RATE_LIMIT_PER_MINUTE ? Number(env.RATE_LIMIT_PER_MINUTE) : undefined,
  ipRateLimitPerMinute: env.IP_RATE_LIMIT_PER_MINUTE ? Number(env.IP_RATE_LIMIT_PER_MINUTE) : undefined,
  trustProxy: env.TRUST_PROXY === 'true',
  clientIpHeader: env.CLIENT_IP_HEADER || undefined,
  log,
});

const purge = setInterval(() => {
  store.purge(Date.now(), retentionMs).catch((err) => log({ level: 'error', msg: `purge failed: ${(err as Error).message}` }));
}, 10 * 60_000);

app.server.listen(port, host, () => log({ level: 'info', msg: `relay listening on ${host}:${port}` }));

async function shutdown(signal: string) {
  log({ level: 'info', msg: `${signal} received, shutting down` });
  clearInterval(purge);
  await app.close();
  await store.close();
  process.exit(0);
}
process.on('SIGTERM', () => void shutdown('SIGTERM'));
process.on('SIGINT', () => void shutdown('SIGINT'));
