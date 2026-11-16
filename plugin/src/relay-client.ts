import { EventEmitter } from 'node:events';
import WebSocket from 'ws';
import { signDetached } from '@claude-bridge/core';
import type { Keypair, Outer } from '@claude-bridge/core';

export type RelayClientOpts = {
  relayUrl: string;
  id: string;
  keys: Keypair;
  session: string;
  log?: (line: string) => void;
  minBackoffMs?: number;
  maxBackoffMs?: number;
  /** How long a request (claim/send) waits for the relay's answer. */
  requestTimeoutMs?: number;
};

type Pending = { resolve: () => void; reject: (e: Error) => void; timer: NodeJS.Timeout };

/** `http(s)://host[/base]` -> `ws(s)://host[/base]/v1/ws`. */
export function wsUrl(relayUrl: string): string {
  const u = relayUrl.replace(/\/+$/, '');
  if (!/^https?:\/\//.test(u)) throw new Error(`relay URL must be http(s): ${relayUrl}`);
  return u.replace(/^http/, 'ws') + '/v1/ws';
}

export class RelayError extends Error {
  constructor(readonly code: string) {
    super(`relay error: ${code}`);
    this.name = 'RelayError';
  }
}

/**
 * WebSocket client for the relay. Authenticates, claims one session, reconnects with backoff (1s -> 30s).
 * Events: 'deliver' (outer), 'ready' (after each successful claim), 'error' (Error).
 * The relay answers claim/send frames strictly in order, so answers are matched FIFO.
 */
export class RelayClient extends EventEmitter {
  private ws?: WebSocket;
  private ready = false;
  private stopped = false;
  private backoff: number;
  private reconnectTimer?: NodeJS.Timeout;
  private pending: Pending[] = [];
  private readonly minBackoff: number;
  private readonly maxBackoff: number;
  private readonly requestTimeout: number;
  private readonly log: (line: string) => void;
  private session: string;

  constructor(private readonly opts: RelayClientOpts) {
    super();
    this.minBackoff = opts.minBackoffMs ?? 1000;
    this.maxBackoff = opts.maxBackoffMs ?? 30_000;
    this.requestTimeout = opts.requestTimeoutMs ?? 10_000;
    this.backoff = this.minBackoff;
    this.log = opts.log ?? ((l) => process.stderr.write(`bridge: ${l}\n`));
    this.session = opts.session;
  }

  get isReady(): boolean {
    return this.ready;
  }

  /** Start connecting (and keep reconnecting). Resolves on the first successful claim. */
  connect(): Promise<void> {
    this.stopped = false;
    const first = this.whenReady(Number.POSITIVE_INFINITY);
    this.open();
    return first;
  }

  /** Claims `session` on the current socket (the relay refuses switching to a different session). */
  claim(session: string): Promise<void> {
    this.session = session;
    return this.request({ type: 'claim', session });
  }

  /** Send an envelope; resolves on relay ack, rejects with RelayError on a relay error code. */
  async send(outer: Outer, threadId: string, opens: boolean): Promise<void> {
    if (!this.ready) await this.whenReady(this.requestTimeout);
    return this.request({ type: 'send', outer, threadId, opens });
  }

  close(): void {
    this.stopped = true;
    clearTimeout(this.reconnectTimer);
    this.ready = false;
    this.ws?.terminate();
    this.ws = undefined;
    this.failPending(new Error('relay client closed'));
  }

  private whenReady(timeoutMs: number): Promise<void> {
    if (this.ready) return Promise.resolve();
    return new Promise((resolve, reject) => {
      const onReady = () => {
        clearTimeout(timer);
        resolve();
      };
      const timer = Number.isFinite(timeoutMs)
        ? setTimeout(() => {
            this.off('ready', onReady);
            reject(new Error('relay not connected'));
          }, timeoutMs)
        : undefined;
      this.once('ready', onReady);
    });
  }

  private request(frame: object): Promise<void> {
    const ws = this.ws;
    if (!ws || ws.readyState !== WebSocket.OPEN) return Promise.reject(new Error('relay not connected'));
    return new Promise((resolve, reject) => {
      const p: Pending = {
        resolve,
        reject,
        timer: setTimeout(() => {
          // Answers are FIFO: once one is lost the rest cannot be matched, so drop the socket.
          const i = this.pending.indexOf(p);
          if (i >= 0) this.pending.splice(i, 1);
          reject(new Error('relay request timed out'));
          ws.terminate();
        }, this.requestTimeout),
      };
      this.pending.push(p);
      try {
        ws.send(JSON.stringify(frame));
      } catch (e) {
        this.pending.splice(this.pending.indexOf(p), 1);
        clearTimeout(p.timer);
        reject(e as Error);
      }
    });
  }

  private settle(err?: Error): void {
    const p = this.pending.shift();
    if (!p) return;
    clearTimeout(p.timer);
    if (err) p.reject(err);
    else p.resolve();
  }

  private failPending(err: Error): void {
    for (const p of this.pending.splice(0)) {
      clearTimeout(p.timer);
      p.reject(err);
    }
  }

  private open(): void {
    if (this.stopped) return;
    let ws: WebSocket;
    try {
      ws = new WebSocket(wsUrl(this.opts.relayUrl), { maxPayload: 1024 * 1024 });
    } catch (e) {
      if (this.listenerCount('error') > 0) this.emit('error', e as Error);
      return this.scheduleReconnect();
    }
    this.ws = ws;
    ws.on('message', (data) => this.onFrame(ws, data.toString()));
    ws.on('error', (e) => {
      if (this.listenerCount('error') > 0) this.emit('error', e);
    });
    ws.on('close', () => {
      if (this.ws !== ws) return;
      this.ws = undefined;
      this.ready = false;
      this.failPending(new Error('relay connection closed'));
      this.scheduleReconnect();
    });
  }

  private onFrame(ws: WebSocket, raw: string): void {
    let m: { type?: unknown; nonce?: unknown; code?: unknown; outer?: unknown };
    try {
      m = JSON.parse(raw);
    } catch {
      return;
    }
    switch (m.type) {
      case 'challenge': {
        if (typeof m.nonce !== 'string') return void ws.terminate();
        const sig = signDetached(Buffer.from(m.nonce, 'utf8'), this.opts.keys.signSec);
        ws.send(JSON.stringify({ type: 'auth', id: this.opts.id, sig }));
        // Auth has no positive answer; the claim answer confirms both.
        this.claim(this.session).then(
          () => {
            this.ready = true;
            this.backoff = this.minBackoff;
            this.emit('ready');
          },
          (e: Error) => {
            if (e instanceof RelayError && e.code === 'session_taken') {
              this.log(`session "${this.session}" is held by another live process; retrying later`);
            } else if (this.listenerCount('error') > 0) this.emit('error', e);
            ws.close();
          },
        );
        return;
      }
      case 'deliver':
        if (m.outer && typeof m.outer === 'object') this.emit('deliver', m.outer as Outer);
        return;
      case 'claimed':
      case 'ack':
        return this.settle();
      case 'error':
        return this.settle(new RelayError(String(m.code)));
      default:
        return;
    }
  }

  private scheduleReconnect(): void {
    if (this.stopped) return;
    const delay = this.backoff;
    this.backoff = Math.min(this.maxBackoff, this.backoff * 2);
    this.reconnectTimer = setTimeout(() => this.open(), delay);
    this.reconnectTimer.unref();
  }
}
