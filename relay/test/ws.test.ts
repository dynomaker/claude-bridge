import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import WebSocket from 'ws';
import { generateKeypair, ready, signDetached } from '@claude-bridge/core';
import type { Keypair, Outer } from '@claude-bridge/core';
import { startRelay } from '../src/main.js';
import { deliverQueued } from '../src/ws.js';
import { Store } from '../src/store.js';

const T0 = 1_700_000_000_000;
const DAY = 86_400_000;
type Msg = Record<string, unknown> & { type: string };

let keys: Record<string, Keypair>;
let clock = T0;
let cleanup: (() => Promise<void> | void)[] = [];

beforeAll(async () => {
  await ready();
  keys = { alice: generateKeypair(), bob: generateKeypair(), carol: generateKeypair() };
});
afterEach(async () => {
  for (const c of cleanup.reverse()) await c();
  cleanup = [];
});

class Client {
  msgs: Msg[] = [];
  private waiters: (() => void)[] = [];
  closed = false;
  constructor(readonly ws: WebSocket) {
    ws.on('message', (d) => {
      this.msgs.push(JSON.parse(d.toString()) as Msg);
      this.waiters.splice(0).forEach((w) => w());
    });
    ws.on('close', () => {
      this.closed = true;
      this.waiters.splice(0).forEach((w) => w());
    });
  }
  send(m: unknown) {
    this.ws.send(JSON.stringify(m));
  }
  async next(type?: string): Promise<Msg> {
    for (;;) {
      const i = this.msgs.findIndex((m) => !type || m.type === type);
      if (i >= 0) return this.msgs.splice(i, 1)[0]!;
      if (this.closed) throw new Error('closed while waiting');
      await new Promise<void>((r) => {
        this.waiters.push(r);
        setTimeout(r, 2000);
      });
      if (!this.msgs.length && !this.closed) throw new Error('timeout waiting for ' + (type ?? 'message'));
    }
  }
  async waitClosed(): Promise<void> {
    if (!this.closed) await new Promise<void>((r) => this.ws.once('close', () => r()));
  }
}

async function setup(extra: { authTimeoutMs?: number; pingIntervalMs?: number } = {}) {
  clock = T0;
  const dir = mkdtempSync(join(tmpdir(), 'relay-'));
  const dbPath = join(dir, 'relay.db');
  const store = new Store(dbPath);
  for (const n of ['alice', 'bob', 'carol']) store.redeemInvite(store.createInvite(n), keys[n]!.signPub, keys[n]!.boxPub);
  const relay = await startRelay({ port: 0, dbPath, now: () => clock, ...extra });
  cleanup.push(() => rmSync(dir, { recursive: true, force: true }), () => store.close(), () => relay.close());

  const connect = async (wsOpts: { autoPong?: boolean } = {}): Promise<{ c: Client; nonce: string }> => {
    const ws = new WebSocket(`ws://127.0.0.1:${relay.port}/v1/ws`, wsOpts);
    const c = new Client(ws);
    cleanup.push(() => ws.terminate());
    const ch = await c.next('challenge');
    return { c, nonce: ch.nonce as string };
  };
  const login = async (id: string, session?: string, wsOpts: { autoPong?: boolean } = {}): Promise<Client> => {
    const { c, nonce } = await connect(wsOpts);
    c.send({ type: 'auth', id, sig: signDetached(Buffer.from(nonce, 'utf8'), keys[id]!.signSec) });
    if (session) {
      c.send({ type: 'claim', session });
      expect((await c.next()).type).toBe('claimed');
    } else {
      // an authed socket answers an unknown request, proving auth finished
      c.send({ type: 'ping?' });
      expect((await c.next('error')).code).toBe('bad_request');
    }
    return c;
  };
  return { store, relay, connect, login };
}

const outer = (from: string, fromSession: string, to: string, session: string, ct = 'Y3Q='): Outer => ({
  from, fromSession, to, session, ct,
});
const send = (c: Client, o: Outer, threadId: string, opens: boolean) => c.send({ type: 'send', outer: o, threadId, opens });

describe('relay websocket', () => {
  it('closes on a bad auth signature', async () => {
    const { connect } = await setup();
    const { c, nonce } = await connect();
    c.send({ type: 'auth', id: 'alice', sig: signDetached(Buffer.from(nonce, 'utf8'), keys.bob!.signSec) });
    await c.waitClosed();
  });

  it('closes a revoked identity', async () => {
    const { connect, store } = await setup();
    store.revokeIdentity('alice');
    const { c, nonce } = await connect();
    c.send({ type: 'auth', id: 'alice', sig: signDetached(Buffer.from(nonce, 'utf8'), keys.alice!.signSec) });
    await c.waitClosed();
  });

  it('rejects a second claim of the same (identity, session) while the first stays live', async () => {
    const { login, store } = await setup();
    store.setShare('bob', 's1', ['alice'], 't');
    const first = await login('bob', 's1');
    const second = await login('bob');
    second.send({ type: 'claim', session: 's1' });
    expect(await second.next('error')).toMatchObject({ code: 'session_taken' });
    const a = await login('alice', 'a1');
    send(a, outer('alice', 'a1', 'bob', 's1'), 't1', true);
    expect((await a.next()).type).toBe('ack');
    expect(await first.next('deliver')).toMatchObject({ outer: { from: 'alice', session: 's1' } });
    expect(second.msgs).toEqual([]);
  });

  it('releases a claim when the socket closes', async () => {
    const { login } = await setup();
    const first = await login('bob', 's1');
    first.ws.close();
    await first.waitClosed();
    const again = await login('bob');
    for (let i = 0; i < 20; i++) {
      again.send({ type: 'claim', session: 's1' });
      const m = await again.next();
      if (m.type === 'claimed') return;
      await new Promise((r) => setTimeout(r, 25));
    }
    throw new Error('claim never released');
  });

  it('allows only one claim per socket', async () => {
    const { login } = await setup();
    const c = await login('bob', 's1');
    c.send({ type: 'claim', session: 's2' });
    expect(await c.next('error')).toMatchObject({ code: 'forbidden' });
  });

  it('forbids a send without a share', async () => {
    const { login } = await setup();
    const a = await login('alice', 'a1');
    send(a, outer('alice', 'a1', 'bob', 's1'), 't1', true);
    expect(await a.next()).toMatchObject({ type: 'error', code: 'forbidden' });
  });

  it('forbids spoofed from and unclaimed or foreign fromSession', async () => {
    const { login, store } = await setup();
    store.setShare('bob', 's1', ['alice', 'carol'], 't');
    const a = await login('alice', 'a1');
    send(a, outer('carol', 'a1', 'bob', 's1'), 't1', true);
    expect(await a.next()).toMatchObject({ code: 'forbidden' });
    send(a, outer('alice', 'other', 'bob', 's1'), 't1', true);
    expect(await a.next()).toMatchObject({ code: 'forbidden' });
    const unclaimed = await login('alice');
    send(unclaimed, outer('alice', 'a1', 'bob', 's1'), 't1', true);
    expect(await unclaimed.next('error')).toMatchObject({ code: 'forbidden' });
  });

  it('delivers to an online receiver and queues per session for an offline one', async () => {
    const { login, store } = await setup();
    store.setShare('bob', 's1', ['alice'], 't');
    store.setShare('bob', 's2', ['alice'], 't');
    const a = await login('alice', 'a1');
    const bob1 = await login('bob', 's1');
    send(a, outer('alice', 'a1', 'bob', 's1', 'b25l'), 't1', true);
    expect((await a.next()).type).toBe('ack');
    expect(await bob1.next('deliver')).toEqual({
      type: 'deliver',
      outer: outer('alice', 'a1', 'bob', 's1', 'b25l'),
    });
    send(a, outer('alice', 'a1', 'bob', 's2', 'dHdv'), 't2', true);
    expect((await a.next()).type).toBe('ack');
    expect(bob1.msgs).toEqual([]);
    const bob2 = await login('bob', 's2');
    expect(await bob2.next('deliver')).toMatchObject({ outer: { ct: 'dHdv', fromSession: 'a1' } });
    // drained exactly once
    bob2.ws.close();
    await bob2.waitClosed();
    const again = await login('bob', 's2');
    await new Promise((r) => setTimeout(r, 50));
    expect(again.msgs).toEqual([]);
  });

  it('routes thread messages both ways only between its two endpoints', async () => {
    const { login, store } = await setup();
    store.setShare('bob', 's1', ['alice', 'carol'], 't');
    const a = await login('alice', 'a1');
    const b = await login('bob', 's1');
    const c = await login('carol', 'c1');
    send(a, outer('alice', 'a1', 'bob', 's1'), 'th', true);
    expect((await a.next()).type).toBe('ack');
    await b.next('deliver');
    send(b, outer('bob', 's1', 'alice', 'a1', 'cmVwbHk='), 'th', false);
    expect((await b.next()).type).toBe('ack');
    expect(await a.next('deliver')).toMatchObject({ outer: { from: 'bob', fromSession: 's1', ct: 'cmVwbHk=' } });
    send(a, outer('alice', 'a1', 'bob', 's1', 'bW9yZQ=='), 'th', false);
    expect((await a.next()).type).toBe('ack');
    // carol has a valid share to the same session but a foreign threadId
    send(c, outer('carol', 'c1', 'bob', 's1'), 'th', false);
    expect(await c.next()).toMatchObject({ code: 'forbidden' });
    // and cannot hijack the thread id by opening it
    send(c, outer('carol', 'c1', 'bob', 's1'), 'th', true);
    expect(await c.next()).toMatchObject({ code: 'forbidden' });
    // a wrong session endpoint of a legitimate participant is also foreign
    const a2 = await login('alice', 'a2');
    send(a2, outer('alice', 'a2', 'bob', 's1'), 'th', false);
    expect(await a2.next()).toMatchObject({ code: 'forbidden' });
  });

  it('forbids a thread idle for more than 24h', async () => {
    const { login, store } = await setup();
    store.setShare('bob', 's1', ['alice'], 't');
    const a = await login('alice', 'a1');
    send(a, outer('alice', 'a1', 'bob', 's1'), 'th', true);
    expect((await a.next()).type).toBe('ack');
    clock = T0 + DAY + 1;
    send(a, outer('alice', 'a1', 'bob', 's1'), 'th', false);
    expect(await a.next()).toMatchObject({ code: 'forbidden' });
  });

  it('rate limits the 31st send within a minute', async () => {
    const { login, store } = await setup();
    store.setShare('bob', 's1', ['alice'], 't');
    const a = await login('alice', 'a1');
    for (let i = 0; i < 30; i++) {
      send(a, outer('alice', 'a1', 'bob', 's1'), 'th', i === 0);
      expect((await a.next()).type).toBe('ack');
    }
    send(a, outer('alice', 'a1', 'bob', 's1'), 'th', false);
    expect(await a.next()).toMatchObject({ code: 'rate_limited' });
    clock += 60_001;
    send(a, outer('alice', 'a1', 'bob', 's1'), 'th', false);
    expect((await a.next()).type).toBe('ack');
  });

  it('rejects an oversized ciphertext', async () => {
    const { login, store } = await setup();
    store.setShare('bob', 's1', ['alice'], 't');
    const a = await login('alice', 'a1');
    const ok = Buffer.alloc(64 * 1024).toString('base64');
    send(a, outer('alice', 'a1', 'bob', 's1', ok), 'th', true);
    expect((await a.next()).type).toBe('ack');
    const big = Buffer.alloc(65 * 1024).toString('base64');
    send(a, outer('alice', 'a1', 'bob', 's1', big), 'th', false);
    expect(await a.next()).toMatchObject({ code: 'too_large' });
    a.ws.send('x'.repeat(200 * 1024));
    expect(await a.next()).toMatchObject({ code: 'too_large' });
  });

  it('ends a thread when the share is removed', async () => {
    const { login, store } = await setup();
    store.setShare('bob', 's1', ['alice'], 't');
    const a = await login('alice', 'a1');
    await login('bob', 's1');
    send(a, outer('alice', 'a1', 'bob', 's1'), 'th', true);
    expect((await a.next()).type).toBe('ack');
    store.deleteShare('bob', 's1');
    send(a, outer('alice', 'a1', 'bob', 's1'), 'th', false);
    expect(await a.next()).toMatchObject({ code: 'forbidden' });
  });

  it('removing a share keeps a reply queued in a thread the session opened itself (D)', async () => {
    const { login, store } = await setup();
    store.setShare('bob', 's1', ['alice'], 't');
    store.setShare('alice', 'a1', ['bob'], 't');
    const a = await login('alice', 'a1');
    const b = await login('bob', 's1');
    send(b, outer('bob', 's1', 'alice', 'a1', 'dGFzaw=='), 'out', true);
    expect((await b.next()).type).toBe('ack');
    expect((await a.next('deliver')).outer).toMatchObject({ from: 'bob', ct: 'dGFzaw==' });
    b.ws.close();
    await b.waitClosed();
    send(a, outer('alice', 'a1', 'bob', 's1', 'cmVzdWx0'), 'out', false);
    expect((await a.next()).type).toBe('ack');
    store.deleteShare('bob', 's1');
    const b2 = await login('bob', 's1');
    expect((await b2.next('deliver')).outer).toMatchObject({ from: 'alice', ct: 'cmVzdWx0' });
  });

  it('terminates a holder that stops answering pings, releasing its claim', async () => {
    const { login } = await setup({ pingIntervalMs: 100 });
    const stale = await login('bob', 's1', { autoPong: false });
    await stale.waitClosed();
    const fresh = await login('bob', 's1');
    expect(fresh.closed).toBe(false);
  });

  it('hands a claim to a new socket when the holder has a missed pong', async () => {
    const { login } = await setup({ pingIntervalMs: 1000 });
    const stale = await login('bob', 's1', { autoPong: false });
    await new Promise((r) => setTimeout(r, 1200)); // one tick passed, ping unanswered, not yet terminated
    expect(stale.closed).toBe(false);
    const fresh = await login('bob', 's1');
    expect(fresh.closed).toBe(false);
    await stale.waitClosed();
  });

  it('keeps a responsive holder across several heartbeats', async () => {
    const { login } = await setup({ pingIntervalMs: 50 });
    const c = await login('bob', 's1');
    await new Promise((r) => setTimeout(r, 300));
    expect(c.closed).toBe(false);
  });

  it('re-enqueues unsent envelopes with their original enqueue time', () => {
    const store = new Store(':memory:');
    store.redeemInvite(store.createInvite('alice'), 'sa', 'ba');
    const o = (ct: string): Outer => ({ from: 'alice', fromSession: 'a1', to: 'bob', session: 's1', ct });
    store.enqueue(o('1'), 1000);
    store.enqueue(o('2'), 2000);
    store.enqueue(o('3'), 3000);
    const sent: string[] = [];
    deliverQueued(store, 'bob', 's1', 4000, (x) => (x.ct === '2' ? false : (sent.push(x.ct), true)));
    expect(sent).toEqual(['1']);
    expect(store.drain('bob', 's1', 4000).map((q) => [q.outer.ct, q.enqueuedAt])).toEqual([
      ['2', 2000],
      ['3', 3000],
    ]);
    store.close();
  });

  it('closes unauthenticated sockets after the auth timeout', async () => {
    const { connect } = await setup({ authTimeoutMs: 200 });
    const { c } = await connect();
    const t0 = Date.now();
    await c.waitClosed();
    expect(Date.now() - t0).toBeGreaterThanOrEqual(150);
  });
});
