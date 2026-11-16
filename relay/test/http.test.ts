import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { canonicalJson, generateKeypair, ready, signDetached } from '@claude-bridge/core';
import type { Keypair } from '@claude-bridge/core';
import { createHttpHandler } from '../src/http.js';
import { Store } from '../src/store.js';

const T0 = 1_700_000_000_000;
let alice: Keypair;
let clock = T0;
const closers: (() => void)[] = [];

beforeAll(async () => {
  await ready();
  alice = generateKeypair();
});
afterEach(() => closers.splice(0).forEach((c) => c()));

async function start() {
  clock = T0;
  const store = new Store(':memory:');
  const server = createServer(createHttpHandler(store, { now: () => clock }));
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  closers.push(() => server.close(), () => store.close());
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const post = (path: string, body: unknown) =>
    fetch(base + path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const register = (invite: string) => post('/v1/register', { invite, signPub: alice.signPub, boxPub: alice.boxPub });
  const sign = (body: Record<string, unknown>, key = alice.signSec) => ({
    ...body,
    sig: signDetached(Buffer.from(canonicalJson(body)), key),
  });
  return { store, base, post, register, sign };
}

describe('http api', () => {
  it('serves healthz', async () => {
    const { base } = await start();
    const r = await fetch(`${base}/healthz`);
    expect(r.status).toBe(200);
    expect(await r.text()).toBe('ok');
  });

  it('registers with a valid invite and rejects reuse', async () => {
    const { store, register, base } = await start();
    const code = store.createInvite('alice');
    const r = await register(code);
    expect(r.status).toBe(200);
    expect(await r.json()).toEqual({ id: 'alice', signPub: alice.signPub, boxPub: alice.boxPub });
    expect((await register(code)).status).toBe(400);
    expect((await fetch(`${base}/v1/identities/alice`)).status).toBe(200);
    expect((await fetch(`${base}/v1/identities/nobody`)).status).toBe(404);
  });

  it('rejects malformed bodies with 400 and oversize bodies with 413', async () => {
    const { post, base } = await start();
    expect((await post('/v1/register', { invite: 1 })).status).toBe(400);
    const bad = await fetch(`${base}/v1/register`, { method: 'POST', body: '{nope' });
    expect(bad.status).toBe(400);
    const big = await post('/v1/register', { invite: 'x'.repeat(70_000), signPub: 'a', boxPub: 'b' });
    expect(big.status).toBe(413);
  });

  it('sets, lists and deletes shares with a valid signature', async () => {
    const { store, register, post, sign } = await start();
    await register(store.createInvite('alice'));
    store.redeemInvite(store.createInvite('bob'), 'sb', 'bb');
    const body = { owner: 'alice', session: 's1', allow: ['bob'], track: 'review', ts: T0 };
    expect((await post('/v1/shares', sign(body))).status).toBe(200);
    expect(store.canSend('bob', 'alice', 's1')).toBe(true);
    const list = await post('/v1/shares/list', sign({ owner: 'alice', ts: T0 }));
    expect(await list.json()).toEqual({ shares: [{ session: 's1', allow: ['bob'], track: 'review' }] });
    expect((await post('/v1/shares/delete', sign({ owner: 'alice', session: 's1', ts: T0 }))).status).toBe(200);
    expect(store.canSend('bob', 'alice', 's1')).toBe(false);
  });

  it('rejects a bad signature, a wrong key, tampering and unknown owners with 401', async () => {
    const { store, register, post, sign } = await start();
    await register(store.createInvite('alice'));
    const body = { owner: 'alice', session: 's1', allow: ['bob'], track: 'r', ts: T0 };
    expect((await post('/v1/shares', { ...sign(body), sig: 'AAAA' })).status).toBe(401);
    expect((await post('/v1/shares', sign(body, generateKeypair().signSec))).status).toBe(401);
    expect((await post('/v1/shares', { ...sign(body), allow: ['mallory'] })).status).toBe(401);
    expect((await post('/v1/shares', sign({ ...body, owner: 'ghost' }))).status).toBe(401);
    expect(store.canSend('bob', 'alice', 's1')).toBe(false);
  });

  it('rejects a stale or future timestamp but allows 60s skew', async () => {
    const { store, register, post, sign } = await start();
    await register(store.createInvite('alice'));
    const at = (ts: number) => sign({ owner: 'alice', session: 's1', allow: [], track: 'r', ts });
    expect((await post('/v1/shares', at(T0 - 120_000))).status).toBe(401);
    expect((await post('/v1/shares', at(T0 + 120_000))).status).toBe(401);
    expect((await post('/v1/shares', at(T0 - 60_000))).status).toBe(200);
  });

  it('rejects a revoked owner with 401', async () => {
    const { store, register, post, sign } = await start();
    await register(store.createInvite('alice'));
    store.revokeIdentity('alice');
    expect((await post('/v1/shares/list', sign({ owner: 'alice', ts: T0 }))).status).toBe(401);
  });
});
