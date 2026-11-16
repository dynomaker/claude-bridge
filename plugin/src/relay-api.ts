import { canonicalJson, signDetached } from '@claude-bridge/core';
import type { Keypair, PublicIdentity } from '@claude-bridge/core';

export type Share = { session: string; allow: string[]; track: string };
export type Fetch = typeof fetch;

const url = (base: string, path: string) => base.replace(/\/+$/, '') + path;

async function call<T>(f: Fetch, base: string, path: string, init?: RequestInit): Promise<T> {
  const res = await f(url(base, path), { ...init, signal: AbortSignal.timeout(10_000) });
  if (!res.ok) {
    let msg = res.statusText;
    try {
      msg = ((await res.json()) as { error?: string }).error ?? msg;
    } catch {
      /* keep statusText */
    }
    throw new Error(`relay ${path} failed: ${res.status} ${msg}`);
  }
  return (await res.json()) as T;
}

function signedPost<T>(f: Fetch, base: string, path: string, keys: Keypair, body: Record<string, unknown>, now: number) {
  const unsigned = { ...body, ts: now };
  const sig = signDetached(Buffer.from(canonicalJson(unsigned), 'utf8'), keys.signSec);
  return call<T>(f, base, path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ ...unsigned, sig }),
  });
}

export function register(
  relayUrl: string,
  invite: string,
  keys: Pick<Keypair, 'signPub' | 'boxPub'>,
  f: Fetch = fetch,
): Promise<PublicIdentity> {
  return call(f, relayUrl, '/v1/register', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ invite, signPub: keys.signPub, boxPub: keys.boxPub }),
  });
}

export function getIdentity(relayUrl: string, id: string, f: Fetch = fetch): Promise<PublicIdentity> {
  return call(f, relayUrl, `/v1/identities/${encodeURIComponent(id)}`);
}

export async function putShare(
  relayUrl: string,
  owner: string,
  keys: Keypair,
  share: Share,
  f: Fetch = fetch,
  now: number = Date.now(),
): Promise<void> {
  await signedPost(f, relayUrl, '/v1/shares', keys, { owner, ...share }, now);
}

export async function deleteShare(
  relayUrl: string,
  owner: string,
  keys: Keypair,
  session: string,
  f: Fetch = fetch,
  now: number = Date.now(),
): Promise<void> {
  await signedPost(f, relayUrl, '/v1/shares/delete', keys, { owner, session }, now);
}

export async function listShares(
  relayUrl: string,
  owner: string,
  keys: Keypair,
  f: Fetch = fetch,
  now: number = Date.now(),
): Promise<Share[]> {
  const r = await signedPost<{ shares: Share[] }>(f, relayUrl, '/v1/shares/list', keys, { owner }, now);
  return r.shares;
}
