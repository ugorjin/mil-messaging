/**
 * Client side of the network relay (src/server/). Implements the same `Relay`
 * interface as the in-memory relay, signing every request with the device's
 * Signal identity key.
 */
import type { Revocation, Signed } from './authority.ts';
import type { FetchedPreKeys, TransportEnvelope } from './layer1.ts';
import type { PublicBundle, Relay, RequestSigner } from './relay.ts';
import { signedWebSocketPath, signRequest } from './request-auth.ts';

export class RelayHttpError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export class HttpRelay implements Relay {
  #base: URL;
  #signer: RequestSigner | undefined;
  #now: () => number;

  constructor(baseUrl: string, opts: { now?: () => number } = {}) {
    this.#base = new URL(baseUrl);
    if (this.#base.protocol !== 'https:' && !['localhost', '127.0.0.1', '[::1]'].includes(this.#base.hostname)) {
      throw new Error('the relay must be reached over https');
    }
    this.#now = opts.now ?? Date.now;
  }

  bindIdentity(signer: RequestSigner): void {
    this.#signer = signer;
  }

  async #request<T>(method: string, path: string, body?: unknown, signed = true): Promise<T> {
    const url = new URL(path, this.#base);
    const data = body === undefined ? new Uint8Array() : Buffer.from(JSON.stringify(body), 'utf8');
    const headers: Record<string, string> = { 'content-type': 'application/json' };
    if (signed) {
      if (!this.#signer) throw new Error('relay identity not bound');
      Object.assign(headers, signRequest(this.#signer, method, url.pathname + url.search, data, this.#now()));
    }
    const res = await fetch(url, { method, headers, body: body === undefined ? undefined : data });
    const json = (await res.json().catch(() => ({}))) as { error?: string };
    if (!res.ok) throw new RelayHttpError(res.status, `relay ${res.status}: ${json.error ?? res.statusText}`);
    return json as T;
  }

  async #maybe<T>(p: Promise<T>): Promise<T | undefined> {
    try {
      return await p;
    } catch (err) {
      if (err instanceof RelayHttpError && err.status === 404) return undefined;
      throw err;
    }
  }

  async publish(_userId: string, bundle: PublicBundle): Promise<void> {
    await this.#request('PUT', '/v1/bundle', bundle);
  }

  lookup(userId: string): Promise<PublicBundle | undefined> {
    return this.#maybe(this.#request<PublicBundle>('GET', `/v1/bundle/${encodeURIComponent(userId)}`));
  }

  findByAci(aci: string): Promise<PublicBundle | undefined> {
    return this.#maybe(this.#request<PublicBundle>('GET', `/v1/aci/${encodeURIComponent(aci)}`));
  }

  takePreKeys(userId: string): Promise<FetchedPreKeys> {
    return this.#request<FetchedPreKeys>('POST', `/v1/prekeys/${encodeURIComponent(userId)}`, {});
  }

  async deliver(env: TransportEnvelope): Promise<void> {
    await this.#request('POST', '/v1/messages', env);
  }

  async fetch(_userId: string): Promise<TransportEnvelope[]> {
    return (await this.#request<{ messages: TransportEnvelope[] }>('GET', '/v1/messages')).messages;
  }

  async ack(_userId: string, ids: string[]): Promise<void> {
    for (let i = 0; i < ids.length; i += 500) await this.#request('POST', '/v1/messages/ack', { ids: ids.slice(i, i + 500) });
  }

  async revocations(): Promise<Signed<Revocation>[]> {
    return (await this.#request<{ revocations: Signed<Revocation>[] }>('GET', '/v1/revocations', undefined, false)).revocations;
  }

  async publishRevocation(rev: Signed<Revocation>): Promise<void> {
    await this.#request('POST', '/v1/revocations', rev, false);
  }

  /**
   * Open the push channel. `onMessages` is called whenever new messages are
   * waiting (and once on connect). Returns a function that closes it.
   */
  async subscribe(onMessages: () => void): Promise<() => void> {
    if (!this.#signer) throw new Error('relay identity not bound');
    const url = new URL(signedWebSocketPath(this.#signer, this.#now()), this.#base);
    url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(url);
    await new Promise<void>((resolve, reject) => {
      ws.addEventListener('message', (ev) => {
        const m = JSON.parse(String(ev.data)) as { type: string };
        if (m.type === 'ready') resolve();
        onMessages();
      });
      ws.addEventListener('error', () => reject(new Error('relay WebSocket connection failed')), { once: true });
    });
    return () => ws.close();
  }
}
