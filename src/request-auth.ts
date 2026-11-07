/**
 * Request authentication shared by the relay server and HttpRelay.
 *
 * Every request (except public endpoints) is signed with the device's Signal
 * identity key over the method, path, user, time, a random nonce and the body
 * hash. The server checks the signature against the identity key in the
 * user's Authority-signed enrollment certificate, rejects old timestamps and
 * rejects reused nonces (so a captured request can't be replayed).
 */
import { randomBytes } from 'node:crypto';
import { sha256 } from './crypto.ts';
import type { RequestSigner } from './relay.ts';

export const AUTH = {
  user: 'x-mm-user',
  timestamp: 'x-mm-timestamp',
  nonce: 'x-mm-nonce',
  signature: 'x-mm-signature',
} as const;

export const MAX_CLOCK_SKEW_MS = 5 * 60_000;

export function signingBytes(method: string, pathAndQuery: string, user: string, timestamp: string, nonce: string, body: Uint8Array): Buffer {
  return Buffer.from(
    ['mil-messaging-request-v1', method.toUpperCase(), pathAndQuery, user, timestamp, nonce, sha256(Buffer.from(body)).toString('hex')].join('\n'),
    'utf8',
  );
}

export const newNonce = (): string => randomBytes(16).toString('hex');

export function signRequest(signer: RequestSigner, method: string, pathAndQuery: string, body: Uint8Array, now: number): Record<string, string> {
  const timestamp = String(now);
  const nonce = newNonce();
  const sig = signer.sign(signingBytes(method, pathAndQuery, signer.userId, timestamp, nonce, body));
  return {
    [AUTH.user]: signer.userId,
    [AUTH.timestamp]: timestamp,
    [AUTH.nonce]: nonce,
    [AUTH.signature]: Buffer.from(sig).toString('base64'),
  };
}

/**
 * Signed WebSocket path. Auth goes in the query string (the browser WebSocket API
 * can't set headers); the signature covers the path and every parameter before it.
 */
export function signedWebSocketPath(signer: RequestSigner, now: number): string {
  const ts = String(now);
  const nonce = newNonce();
  const path = `/v1/ws?user=${encodeURIComponent(signer.userId)}&ts=${ts}&nonce=${nonce}`;
  const sig = signer.sign(signingBytes('GET', path, signer.userId, ts, nonce, new Uint8Array()));
  return `${path}&sig=${encodeURIComponent(Buffer.from(sig).toString('base64'))}`;
}
