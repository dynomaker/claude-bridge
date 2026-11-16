import { randomBytes } from 'node:crypto';
import type { Server } from 'node:http';
import { WebSocketServer, WebSocket } from 'ws';
import { z } from 'zod';
import { verifyDetached } from '@claude-bridge/core';
import type { Outer } from '@claude-bridge/core';
import { RateLimiter } from './ratelimit.js';
import type { Store } from './store.js';

export const MAX_CT_BYTES = 64 * 1024;
/** Raw frame cap: base64 of a max ciphertext plus JSON overhead fits comfortably; anything larger is rejected. */
export const MAX_FRAME_BYTES = 128 * 1024;
export const RATE_LIMIT = 30;
export const RATE_WINDOW_MS = 60_000;

const name = z.string().min(1).max(128);
const authMsg = z.object({ type: z.literal('auth'), id: name, sig: z.string().min(1).max(256) });
const claimMsg = z.object({ type: z.literal('claim'), session: name });
const sendMsg = z.object({
  type: z.literal('send'),
  outer: z.object({ from: name, fromSession: name, to: name, session: name, ct: z.string().min(1) }).strict(),
  threadId: name,
  opens: z.boolean(),
});

type ErrorCode = 'forbidden' | 'too_large' | 'rate_limited' | 'session_taken' | 'bad_request';

const base64Bytes = (s: string): number => Math.floor((s.length * 3) / 4) - (s.endsWith('==') ? 2 : s.endsWith('=') ? 1 : 0);
const key = (id: string, session: string): string => `${id}\u0000${session}`;

export type WsOptions = { now: () => number; authTimeoutMs?: number; pingIntervalMs?: number };

/**
 * Sends everything queued for (id, session) through `send`. `drain` deletes first, so on a failed send the
 * unsent remainder is put back with its original enqueue time (the 24h TTL is not extended).
 */
export function deliverQueued(
  store: Store,
  id: string,
  session: string,
  now: number,
  send: (outer: Outer) => boolean,
): void {
  const pending = store.drain(id, session, now);
  for (let i = 0; i < pending.length; i++) {
    if (!send(pending[i]!.outer)) {
      for (const q of pending.slice(i)) store.enqueue(q.outer, q.enqueuedAt, q.threadId);
      return;
    }
  }
}

/** Attaches the `/v1/ws` endpoint to an HTTP server. The relay only routes ciphertext and routing metadata. */
export function attachWs(server: Server, store: Store, opts: WsOptions): { close(): void } {
  const wss = new WebSocketServer({ noServer: true, maxPayload: 1024 * 1024 });
  const limiter = new RateLimiter(RATE_LIMIT, RATE_WINDOW_MS);
  const authTimeoutMs = opts.authTimeoutMs ?? 10_000;
  /** (identity, session) -> the single socket that claimed it. */
  const claims = new Map<string, WebSocket>();
  /** false while a ping is outstanding (no pong since the last tick). */
  const alive = new WeakMap<WebSocket, boolean>();
  const heartbeat = setInterval(() => {
    for (const c of wss.clients) {
      if (alive.get(c) === false) {
        c.terminate();
        continue;
      }
      alive.set(c, false);
      try {
        c.ping();
      } catch {
        c.terminate();
      }
    }
  }, opts.pingIntervalMs ?? 30_000);
  heartbeat.unref();

  server.on('upgrade', (req, socket, head) => {
    if ((req.url ?? '').split('?')[0] !== '/v1/ws') {
      socket.destroy();
      return;
    }
    wss.handleUpgrade(req, socket, head, (ws) => onConnection(ws));
  });

  function reply(ws: WebSocket, m: unknown): boolean {
    if (ws.readyState !== WebSocket.OPEN) return false;
    try {
      ws.send(JSON.stringify(m));
      return true;
    } catch {
      return false;
    }
  }
  const fail = (ws: WebSocket, code: ErrorCode) => reply(ws, { type: 'error', code });

  /** Live delivery to the claiming socket, else queue for it. */
  function route(outer: Outer, threadId: string): void {
    const target = claims.get(key(outer.to, outer.session));
    if (target && reply(target, { type: 'deliver', outer })) return;
    store.enqueue(outer, opts.now(), threadId);
  }

  function drainTo(ws: WebSocket, id: string, session: string): void {
    deliverQueued(store, id, session, opts.now(), (outer) => reply(ws, { type: 'deliver', outer }));
  }

  function onConnection(ws: WebSocket): void {
    alive.set(ws, true);
    ws.on('pong', () => alive.set(ws, true));
    const nonce = randomBytes(32).toString('base64');
    let id: string | undefined;
    let claimed: string | undefined;
    const timer = setTimeout(() => {
      if (!id) ws.close(1008, 'auth timeout');
    }, authTimeoutMs);

    ws.on('close', () => {
      clearTimeout(timer);
      if (id && claimed && claims.get(key(id, claimed)) === ws) claims.delete(key(id, claimed));
    });
    ws.on('error', () => ws.terminate());
    reply(ws, { type: 'challenge', nonce });

    ws.on('message', (data, isBinary) => {
      const raw = Array.isArray(data) ? Buffer.concat(data) : Buffer.from(data as Buffer);
      if (raw.length > MAX_FRAME_BYTES) return void fail(ws, 'too_large');
      let msg: unknown;
      try {
        if (isBinary) throw new Error('binary');
        msg = JSON.parse(raw.toString('utf8'));
      } catch {
        if (!id) return void ws.close(1008, 'bad frame');
        return void fail(ws, 'bad_request');
      }

      if (!id) {
        const a = authMsg.safeParse(msg);
        const ident = a.success ? store.getIdentity(a.data.id) : undefined;
        if (!a.success || !ident || !verifyDetached(Buffer.from(nonce, 'utf8'), a.data.sig, ident.signPub)) {
          return void ws.close(1008, 'auth failed');
        }
        id = ident.id;
        clearTimeout(timer);
        return;
      }
      if (!store.getIdentity(id)) return void ws.close(1008, 'revoked');

      const type = (msg as { type?: unknown } | null)?.type;
      if (type === 'claim') return handleClaim(ws, id, msg);
      if (type === 'send') return handleSend(ws, id, msg);
      fail(ws, 'bad_request');
    });

    function handleClaim(w: WebSocket, me: string, m: unknown): void {
      const c = claimMsg.safeParse(m);
      if (!c.success) return void fail(w, 'bad_request');
      const { session } = c.data;
      if (claimed !== undefined && claimed !== session) return void fail(w, 'forbidden');
      const holder = claims.get(key(me, session));
      if (holder && holder !== w && holder.readyState === WebSocket.OPEN) {
        if (alive.get(holder) !== false) return void fail(w, 'session_taken');
        holder.terminate(); // missed a pong: stale, hand the session over
        claims.delete(key(me, session));
      }
      claims.set(key(me, session), w);
      claimed = session;
      reply(w, { type: 'claimed', session });
      drainTo(w, me, session);
    }

    function handleSend(w: WebSocket, me: string, m: unknown): void {
      const s = sendMsg.safeParse(m);
      if (!s.success) return void fail(w, 'bad_request');
      const { outer, threadId, opens } = s.data;
      if (base64Bytes(outer.ct) > MAX_CT_BYTES) return void fail(w, 'too_large');
      if (outer.from !== me || claimed === undefined || outer.fromSession !== claimed) return void fail(w, 'forbidden');
      if (!limiter.allow(me, opts.now())) return void fail(w, 'rate_limited');

      if (opens) {
        if (!store.canSend(me, outer.to, outer.session)) return void fail(w, 'forbidden');
        try {
          store.openThread(threadId, me, claimed, outer.to, outer.session, opts.now());
        } catch {
          return void fail(w, 'forbidden');
        }
      } else if (!store.touchThread(threadId, me, claimed, outer.to, outer.session, opts.now())) {
        return void fail(w, 'forbidden');
      }
      route(outer, threadId);
      reply(w, { type: 'ack' });
    }
  }

  return {
    close() {
      clearInterval(heartbeat);
      for (const c of wss.clients) c.terminate();
      wss.close();
    },
  };
}
