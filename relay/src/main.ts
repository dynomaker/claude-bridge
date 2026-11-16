import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { pathToFileURL } from 'node:url';
import { createHttpHandler } from './http.js';
import { Store } from './store.js';
import { attachWs } from './ws.js';

const PURGE_INTERVAL_MS = 10 * 60_000;

export type RelayOptions = { port: number; dbPath: string; now?: () => number; authTimeoutMs?: number; pingIntervalMs?: number };

export async function startRelay(opts: RelayOptions): Promise<{ close(): Promise<void>; port: number }> {
  const now = opts.now ?? Date.now;
  const store = new Store(opts.dbPath);
  const server = createServer(createHttpHandler(store, { now }));
  const ws = attachWs(server, store, { now, authTimeoutMs: opts.authTimeoutMs, pingIntervalMs: opts.pingIntervalMs });
  const purge = setInterval(() => store.purgeExpired(now()), PURGE_INTERVAL_MS);
  purge.unref();
  try {
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(opts.port, '0.0.0.0', resolve);
    });
  } catch (e) {
    clearInterval(purge);
    store.close();
    throw e;
  }
  return {
    port: (server.address() as AddressInfo).port,
    async close() {
      clearInterval(purge);
      ws.close();
      server.closeAllConnections();
      await new Promise<void>((r) => server.close(() => r()));
      store.close();
    },
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const port = Number(process.env.PORT ?? 8787);
  const dbPath = process.env.DB_PATH ?? '/data/relay.db';
  const relay = await startRelay({ port, dbPath });
  console.log(`relay listening on ${relay.port}`);
  const stop = () => void relay.close().then(() => process.exit(0));
  process.on('SIGTERM', stop);
  process.on('SIGINT', stop);
}
