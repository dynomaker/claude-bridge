import type { IncomingMessage, ServerResponse } from 'node:http';
import { z } from 'zod';
import { canonicalJson, verifyDetached } from '@claude-bridge/core';
import type { Store } from './store.js';

export const MAX_BODY_BYTES = 64 * 1024;
export const MAX_SKEW_MS = 60_000;

class HttpError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

const name = z.string().min(1).max(128);
const signed = { ts: z.number().finite(), sig: z.string().min(1).max(256) };
const registerBody = z.object({ invite: z.string().min(1).max(256), signPub: z.string().min(1).max(256), boxPub: z.string().min(1).max(256) }).strict();
const shareBody = z.object({ owner: name, session: name, allow: z.array(name).max(256), track: z.string().max(256), ...signed }).strict();
const shareDeleteBody = z.object({ owner: name, session: name, ...signed }).strict();
const shareListBody = z.object({ owner: name, ...signed }).strict();

async function readJson(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const c of req) {
    size += (c as Buffer).length;
    if (size > MAX_BODY_BYTES) throw new HttpError(413, 'body too large');
    chunks.push(c as Buffer);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new HttpError(400, 'invalid json');
  }
}

function parse<T extends z.ZodTypeAny>(schema: T, body: unknown): z.infer<T> {
  const r = schema.safeParse(body);
  if (!r.success) throw new HttpError(400, 'invalid body');
  return r.data;
}

export function createHttpHandler(
  store: Store,
  opts: { now?: () => number } = {},
): (req: IncomingMessage, res: ServerResponse) => void {
  const now = opts.now ?? Date.now;

  /** Owner-signed request: fresh timestamp, known non-revoked owner, valid signature over the body minus `sig`. */
  function authOwner(body: { owner: string; ts: number; sig: string }): void {
    if (Math.abs(now() - body.ts) > MAX_SKEW_MS) throw new HttpError(401, 'stale timestamp');
    const id = store.getIdentity(body.owner);
    if (!id) throw new HttpError(401, 'unauthorized');
    const { sig, ...rest } = body;
    if (!verifyDetached(Buffer.from(canonicalJson(rest), 'utf8'), sig, id.signPub)) throw new HttpError(401, 'unauthorized');
  }

  async function route(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const path = (req.url ?? '').split('?')[0];
    const method = req.method ?? 'GET';
    const send = (status: number, body: unknown) => {
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(JSON.stringify(body));
    };

    if (method === 'GET' && path === '/healthz') {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('ok');
      return;
    }
    const idMatch = /^\/v1\/identities\/([^/]+)$/.exec(path);
    if (method === 'GET' && idMatch) {
      let id: string;
      try {
        id = decodeURIComponent(idMatch[1]!);
      } catch {
        throw new HttpError(400, 'bad id');
      }
      const ident = store.getIdentity(id);
      if (!ident) throw new HttpError(404, 'not found');
      return send(200, ident);
    }
    if (method !== 'POST') throw new HttpError(404, 'not found');

    switch (path) {
      case '/v1/register': {
        const b = parse(registerBody, await readJson(req));
        try {
          return send(200, store.redeemInvite(b.invite, b.signPub, b.boxPub));
        } catch {
          throw new HttpError(400, 'invalid or used invite');
        }
      }
      case '/v1/shares': {
        const b = parse(shareBody, await readJson(req));
        authOwner(b);
        store.setShare(b.owner, b.session, b.allow, b.track);
        return send(200, { ok: true });
      }
      case '/v1/shares/delete': {
        const b = parse(shareDeleteBody, await readJson(req));
        authOwner(b);
        store.deleteShare(b.owner, b.session);
        return send(200, { ok: true });
      }
      case '/v1/shares/list': {
        const b = parse(shareListBody, await readJson(req));
        authOwner(b);
        return send(200, { shares: store.listShares(b.owner) });
      }
      default:
        throw new HttpError(404, 'not found');
    }
  }

  return (req, res) => {
    route(req, res).catch((e: unknown) => {
      const status = e instanceof HttpError ? e.status : 500;
      if (res.headersSent) return res.destroy();
      res.writeHead(status, { 'content-type': 'application/json', ...(status === 413 ? { connection: 'close' } : {}) });
      res.end(JSON.stringify({ error: e instanceof HttpError ? e.message : 'internal error' }));
    });
  };
}
