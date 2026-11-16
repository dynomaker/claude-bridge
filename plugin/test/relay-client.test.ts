import { createServer } from 'node:http';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { Duplex } from 'node:stream';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { generateKeypair, ready } from '@claude-bridge/core';
import type { Keypair } from '@claude-bridge/core';
import { createHttpHandler } from '../../relay/src/http.js';
import { Store } from '../../relay/src/store.js';
import { attachWs } from '../../relay/src/ws.js';
import { RelayClient, wsUrl } from '../src/relay-client.js';

let cleanup: (() => unknown)[] = [];
let keys: Keypair;

beforeAll(async () => {
  await ready();
  keys = generateKeypair();
});
afterEach(async () => {
  for (const c of cleanup.reverse()) await c();
  cleanup = [];
});

async function relay(): Promise<{ url: string; server: Server; kick(): void }> {
  const store = new Store(':memory:');
  store.redeemInvite(store.createInvite('alice'), keys.signPub, keys.boxPub);
  const server = createServer(createHttpHandler(store));
  const ws = attachWs(server, store, { now: Date.now });
  const upgraded = new Set<Duplex>();
  server.on('upgrade', (_req, socket) => upgraded.add(socket));
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  cleanup.push(() => store.close(), () => new Promise<void>((r) => server.close(() => r())), () => { ws.close(); server.closeAllConnections(); });
  return { url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, server, kick: () => upgraded.forEach((s) => s.destroy()) };
}

const client = (url: string, session: string) => {
  const c = new RelayClient({ relayUrl: url, id: 'alice', keys, session, minBackoffMs: 20, maxBackoffMs: 100, log: () => undefined });
  cleanup.push(() => c.close());
  return c;
};

describe('RelayClient', () => {
  it('maps relay URLs to the websocket endpoint', () => {
    expect(wsUrl('https://relay.example.com/')).toBe('wss://relay.example.com/v1/ws');
    expect(wsUrl('http://127.0.0.1:8787')).toBe('ws://127.0.0.1:8787/v1/ws');
    expect(() => wsUrl('ftp://x')).toThrow();
  });

  it('authenticates, claims, and reconnects after the connection drops', async () => {
    const r = await relay();
    const c = client(r.url, 's1');
    await c.connect();
    expect(c.isReady).toBe(true);
    const again = new Promise<void>((res) => c.once('ready', () => res()));
    r.kick();
    await again;
    expect(c.isReady).toBe(true);
  });

  it('does not steal a session held by another live process', async () => {
    const r = await relay();
    const first = client(r.url, 's1');
    await first.connect();
    const second = client(r.url, 's1');
    let readied = false;
    void second.connect().then(() => (readied = true));
    await new Promise((res) => setTimeout(res, 200));
    expect(readied).toBe(false);
    expect(first.isReady).toBe(true);
  });
});
