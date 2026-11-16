import { randomBytes } from 'node:crypto';
import { rmSync } from 'node:fs';
import { fingerprint, ready, seal } from '@claude-bridge/core';
import type { Inner, Keypair, Kind, Outer } from '@claude-bridge/core';
import { audit } from './audit.js';
import { readSessionConfig } from './cli.js';
import type { SessionConfig } from './cli.js';
import { startControl } from './control.js';
import { handleDeliver } from './inbound.js';
import { injectNext } from './inject.js';
import { loadConfig, pinnedPeer, resolvePeer } from './keystore.js';
import { assertSafeName, sessionDir, withBridgeHome } from './paths.js';
import { getIdentity } from './relay-api.js';
import type { Fetch } from './relay-api.js';
import { RelayClient } from './relay-client.js';
import { classify } from './policy/classifier.js';
import { DEFAULT_THRESHOLD } from './policy/gate.js';
import type { ClassifyFn } from './policy/gate.js';
import { loadPolicy } from './policy/rules.js';
import { parentClaudePid, processAlive, TaskStore } from './tasks.js';
import type { ActiveRec, TaskRec, TaskStatus } from './tasks.js';

export const MAX_TEXT_BYTES = 32 * 1024;
export const ENVELOPE_TTL_MS = 86_400_000;
/** How long a sender marker set by an injected result gates the session (unless the owner or a bridge_send clears it). */
export const RESULT_MARKER_TTL_MS = 10 * 60_000;

/** A `notifications/claude/channel` payload; every meta value is a string. */
export type ChannelEvent = { content: string; meta: Record<string, string> };

export type BridgeOpts = { session?: string; home?: string };
export type BridgeDeps = {
  notify(ev: ChannelEvent): void | Promise<void>;
  classify?: ClassifyFn;
  relayUrl?: string;
  now?: () => number;
  fetch?: Fetch;
  log?: (line: string) => void;
  /** Working directory recorded in active markers (default process.cwd()). */
  cwd?: string;
  /** Current parent pid (default process.ppid); markers name the parent Claude Code, and an orphaned server injects nothing. */
  parentPid?: () => number;
};

export type Bridge = {
  /** The session this process claimed (BRIDGE_SESSION, or an auto `tmp-…` send-only session). */
  session: string;
  tools: {
    send(a: { to: string; task: string }): Promise<{ taskId: string; receiverFingerprint: string; newlyPinned: boolean }>;
    message(a: { taskId: string; text: string }): Promise<{ ok: true; note?: string }>;
    reply(a: { taskId: string; text: string }): Promise<{ ok: true; note?: string }>;
    status(a: { taskId: string }): Promise<Record<string, unknown>>;
  };
  start(): Promise<void>;
  stop(): Promise<void>;
  /** Process an envelope exactly as if the relay delivered it (lets tests simulate a misbehaving relay). */
  deliver(outer: Outer): Promise<void>;
};

/** Shared state and helpers used by the inbound and control modules. */
export type Ctx = {
  me: string;
  session: string;
  /** True when the session was named by the owner (BRIDGE_SESSION); false for send-only tmp sessions. */
  receiver: boolean;
  keys: Keypair;
  store: TaskStore;
  client: RelayClient;
  now: () => number;
  classify: ClassifyFn;
  log: (line: string) => void;
  record(event: string, data: object): void;
  notify(ev: ChannelEvent): void;
  peerKey(id: string): ReturnType<typeof resolvePeer>;
  /** Send one envelope in `rec`'s thread to its counterpart (bumps rec.outSeq). */
  sendInThread(rec: TaskRec, kind: Kind, body: string, status?: TaskStatus): Promise<void>;
  /** Threshold for gating in this session: session config, else policy.yaml, else 0.3 (0 = hold everything if policy is broken). */
  threshold(sc: SessionConfig | undefined): number;
  sessionConfig(): SessionConfig | undefined;
  paused(): boolean;
  /** True while paused, or while any active marker exists (receiver task or sender-side answer). */
  busy(): boolean;
  /** True while the hook holds `active` (a held event at or after the marker's ts). */
  heldNow(active: ActiveRec): boolean;
  /** Track used to gate inbound messages in a thread this session opened. */
  senderTrack(rec: TaskRec): string;
  /** Inject a (gated or approved) message; on the sender side this sets the sender marker for the thread. */
  deliverMessage(rec: TaskRec, body: string, approved: boolean): void;
  /** Inject a (gated) result of a thread this session opened, under a time-bounded sender marker. */
  deliverResult(rec: TaskRec, body: string): void;
  /** A thread this session opened ended (result/rejected): clear its marker, even if hook-held, and inject what waits. */
  endSenderThread(taskId: string): Promise<void>;
  /** Clear the sender marker of `taskId` unless the hook holds it (only the owner or the thread's end lifts that). */
  releaseSenderMarker(taskId: string): void;
  /** Make `rec` the active receiver task and inject it; false if it can no longer run (rejected instead). */
  activate(rec: TaskRec): Promise<boolean>;
  injectNext(): Promise<void>;
  /** Apply hook held-events now (also runs on a watcher); set by the control module. */
  pollHeld(): Promise<void>;
  /** Latest hook held-event ts for a task (0 if none); a new marker must be strictly newer. */
  latestHeldTs(taskId: string): number;
};

const PEER = /^([A-Za-z0-9._-]{1,128})\/([A-Za-z0-9._-]{1,128})$/;

export function parsePeer(s: string): { id: string; session: string } {
  const m = PEER.exec(s);
  if (!m) throw new Error(`expected "person/session", got: ${s}`);
  assertSafeName(m[1]!, 'person name');
  assertSafeName(m[2]!, 'session name');
  return { id: m[1]!, session: m[2]! };
}

export function checkText(text: unknown, what = 'text'): string {
  if (typeof text !== 'string' || text.length === 0) throw new Error(`${what} must be a non-empty string`);
  if (Buffer.byteLength(text, 'utf8') > MAX_TEXT_BYTES) throw new Error(`${what} exceeds ${MAX_TEXT_BYTES} bytes`);
  return text;
}

const isOpen = (r: TaskRec) => r.status !== 'done' && r.status !== 'rejected';

export function createBridge(opts: BridgeOpts, deps: BridgeDeps): Bridge {
  const home = opts.home;
  const inHome = <T>(fn: () => T): T => withBridgeHome(home, fn);
  return inHome(() => build(opts, deps, inHome));
}

function build(opts: BridgeOpts, deps: BridgeDeps, inHome: <T>(fn: () => T) => T): Bridge {
  const cfg = loadConfig();
  const receiver = opts.session !== undefined;
  const session = opts.session ?? `tmp-${randomBytes(8).toString('hex')}`;
  assertSafeName(session, 'session name');
  const relayUrl = deps.relayUrl ?? cfg.relayUrl;
  const log = deps.log ?? ((l: string) => process.stderr.write(`bridge: ${l}\n`));
  const client = new RelayClient({ relayUrl, id: cfg.id, keys: cfg.keys, session, log });
  const now = deps.now ?? Date.now;
  const parentPid = deps.parentPid ?? (() => process.ppid);
  const store = new TaskStore(session, now, parentClaudePid(parentPid(), parentPid));
  const cwd = deps.cwd ?? process.cwd();

  // Every state change runs through one queue: the server is the only writer of tasks.json.
  let chain: Promise<unknown> = Promise.resolve();
  const serial = <T>(fn: () => Promise<T>): Promise<T> => {
    const run = chain.then(() => inHome(fn));
    chain = run.catch(() => undefined);
    return run;
  };

  const ctx: Ctx = {
    me: cfg.id,
    session,
    receiver,
    keys: cfg.keys,
    store,
    client,
    now,
    classify: deps.classify ?? classify,
    log,
    record(event, data) {
      try {
        audit(event, { session, ...data });
      } catch (e) {
        log(`audit failed: ${(e as Error).message}`);
      }
    },
    notify(ev) {
      try {
        Promise.resolve(deps.notify(ev)).catch((e: Error) => log(`notify failed: ${e.message}`));
      } catch (e) {
        log(`notify failed: ${(e as Error).message}`);
      }
    },
    // Pinned keys are used as-is; the relay is asked only on first sight (trust on first use).
    peerKey: async (id) => pinnedPeer(id) ?? resolvePeer(id, (i) => getIdentity(relayUrl, i, deps.fetch)),
    async sendInThread(rec, kind, body, status) {
      const peer = parsePeer(rec.peer ?? '');
      const pub = await ctx.peerKey(peer.id);
      const seq = (rec.outSeq ?? 0) + 1;
      store.update(rec.taskId, { outSeq: seq });
      rec.outSeq = seq;
      const inner: Inner = {
        v: 1, kind, taskId: rec.taskId, seq, from: cfg.id, fromSession: session, to: peer.id, session: peer.session,
        body, ...(status ? { status } : {}), ts: ctx.now(),
      };
      await client.send(seal(inner, cfg.keys, pub.boxPub), rec.threadId, kind === 'task');
      ctx.record('outbound', { kind, taskId: rec.taskId, to: rec.peer, seq, status, bytes: Buffer.byteLength(body) });
    },
    threshold(sc) {
      if (sc && typeof sc.threshold === 'number') return sc.threshold;
      try {
        return loadPolicy().threshold ?? DEFAULT_THRESHOLD;
      } catch (e) {
        ctx.record('policy-error', { error: (e as Error).message });
        return 0;
      }
    },
    sessionConfig: () => (receiver ? readSessionConfig(session) : undefined),
    paused: () => false,
    busy() {
      if (ctx.paused()) return true;
      // Orphaned (no Claude Code to gate): everything waits instead of being injected.
      if (!store.hasOwner()) return true;
      try {
        return store.active() !== undefined;
      } catch (e) {
        ctx.record('active-unreadable', { error: (e as Error).message });
        return true;
      }
    },
    heldNow: (a) => ctx.latestHeldTs(a.taskId) >= a.ts,
    senderTrack: (rec) => `reply in thread to ${rec.peer}: ${rec.body}`,
    deliverMessage(rec, body, approved) {
      store.owner(); // throws when orphaned: nothing is injected into a session the hook cannot gate
      let track: string;
      if (rec.role === 'sender') {
        track = ctx.senderTrack(rec);
        store.setActive({
          taskId: rec.taskId, threadId: rec.threadId, role: 'sender', task: body, from: rec.peer ?? '', track,
          threshold: ctx.threshold(ctx.sessionConfig()), approved, cwd,
          ts: Math.max(ctx.now(), ctx.latestHeldTs(rec.taskId) + 1),
        });
      } else {
        const a = store.active();
        track = a?.track ?? '';
        // A new peer turn is not covered by an earlier owner approval: the classifier gates tools again.
        if (a && a.role === 'receiver' && a.taskId === rec.taskId) {
          store.setActive({ ...a, approved: false, ts: ctx.heldNow(a) ? a.ts : Math.max(ctx.now(), ctx.latestHeldTs(rec.taskId) + 1) });
        }
      }
      ctx.record('inject-message', { taskId: rec.taskId, from: rec.peer, approved });
      ctx.notify({ content: body, meta: { kind: 'message', task_id: rec.taskId, from: rec.peer ?? '', track } });
    },
    deliverResult(rec, body) {
      store.owner(); // throws when orphaned (setActive below would too; this keeps the order obvious)
      const ts = Math.max(ctx.now(), ctx.latestHeldTs(rec.taskId) + 1);
      store.setActive({
        taskId: rec.taskId, threadId: rec.threadId, role: 'sender', task: `${rec.body} (result received)`, from: rec.peer ?? '',
        track: `result of a task sent to ${rec.peer}: ${rec.body}`, threshold: ctx.threshold(ctx.sessionConfig()), approved: false, cwd,
        ts, expiresAt: ts + RESULT_MARKER_TTL_MS,
      });
      ctx.record('inject-result', { taskId: rec.taskId, from: rec.peer });
      ctx.notify({ content: body, meta: { kind: 'result', task_id: rec.taskId, from: rec.peer ?? '', status: 'done' } });
    },
    async endSenderThread(taskId) {
      clearSenderMarker(taskId, true);
      await ctx.injectNext();
    },
    releaseSenderMarker: (taskId) => clearSenderMarker(taskId, false),
    async activate(rec) {
      const sc = ctx.sessionConfig();
      if (!sc || !sc.allow.includes(rec.from)) {
        store.update(rec.taskId, { status: 'rejected', reason: 'session is no longer shared' });
        await sendStatusSafe(rec, 'rejected', 'session is no longer shared');
        return false;
      }
      const approved = rec.approved === true;
      store.setActive({
        taskId: rec.taskId, threadId: rec.threadId, role: 'receiver', task: rec.body, from: rec.peer ?? rec.from,
        track: sc.track, threshold: ctx.threshold(sc), approved, ...(sc.scope !== undefined ? { scope: sc.scope } : {}), cwd,
        // Fresh ts strictly after any earlier held event, so an approval lifts the hook's hold.
        ts: Math.max(ctx.now(), ctx.latestHeldTs(rec.taskId) + 1),
      });
      store.update(rec.taskId, { status: 'running', reason: undefined, approved: undefined });
      ctx.record('inject', { taskId: rec.taskId, from: rec.peer, approved });
      ctx.notify({ content: rec.body, meta: { kind: 'task', task_id: rec.taskId, from: rec.peer ?? rec.from, track: sc.track } });
      await sendStatusSafe(rec, 'running', approved ? 'approved by the session owner; running' : 'running');
      return true;
    },
    injectNext: () => injectNext(ctx),
    pollHeld: async () => undefined,
    latestHeldTs: () => 0,
  };

  async function sendStatusSafe(rec: TaskRec, status: TaskStatus, body: string): Promise<void> {
    try {
      await ctx.sendInThread(rec, 'status', body, status);
    } catch (e) {
      ctx.record('send-failed', { taskId: rec.taskId, kind: 'status', status, error: (e as Error).message });
    }
  }

  let control: { stop(): void } | undefined;

  function clearSenderMarker(taskId: string, evenIfHeld: boolean): void {
    try {
      const a = store.active();
      if (a && a.role === 'sender' && a.taskId === taskId && (evenIfHeld || !ctx.heldNow(a))) store.clearActive();
    } catch {
      /* an unreadable marker is left in place: the hook keeps failing closed */
    }
  }

  const tools: Bridge['tools'] = {
    send: (a) =>
      serial(async () => {
        const peer = parsePeer(String(a?.to ?? ''));
        const task = checkText(a?.task, 'task');
        const newlyPinned = pinnedPeer(peer.id) === undefined;
        const pub = await ctx.peerKey(peer.id);
        const taskId = randomBytes(16).toString('hex');
        const rec: TaskRec = {
          taskId, threadId: taskId, from: cfg.id, body: task, status: 'queued', ts: ctx.now(),
          role: 'sender', peer: `${peer.id}/${peer.session}`, outSeq: 0,
        };
        store.add(rec);
        try {
          await ctx.sendInThread(rec, 'task', task);
        } catch (e) {
          store.update(taskId, { status: 'rejected', reason: (e as Error).message });
          ctx.record('send-failed', { taskId, kind: 'task', error: (e as Error).message });
          throw e;
        }
        // A new thread, once sent, ends the gating left by an earlier result (unless the hook holds that marker).
        try {
          const cur = store.active();
          if (cur && cur.role === 'sender' && cur.expiresAt !== undefined && !ctx.heldNow(cur) && !store.held(cur)) {
            store.clearActive();
            ctx.record('result-marker-cleared', { taskId: cur.taskId, by: 'bridge_send' });
          }
        } catch {
          /* an unreadable marker stays: the hook keeps failing closed */
        }
        return { taskId, receiverFingerprint: fingerprint(pub.signPub), newlyPinned };
      }),

    message: (a) =>
      serial(async () => {
        const text = checkText(a?.text);
        const rec = store.get(String(a?.taskId ?? ''));
        if (!rec || !isOpen(rec)) throw new Error('no open thread with that taskId');
        if (rec.role !== 'sender') {
          const active = store.active();
          if (active?.taskId !== rec.taskId) throw new Error('this thread is not the active task of this session');
        }
        await ctx.sendInThread(rec, 'message', text);
        if (rec.role === 'sender') {
          ctx.releaseSenderMarker(rec.taskId);
          await ctx.injectNext();
        }
        return { ok: true as const };
      }),

    reply: (a) =>
      serial(async () => {
        const text = checkText(a?.text);
        const taskId = String(a?.taskId ?? '');
        await ctx.pollHeld();
        const active = store.active();
        if (!active || active.role !== 'receiver' || active.taskId !== taskId) {
          throw new Error('bridge_reply only answers the active task of this session');
        }
        const rec = store.get(taskId);
        if (!rec) throw new Error('unknown task');
        if (rec.status === 'held' || ctx.heldNow(active)) {
          // Held tasks stay open and active until the owner approves or rejects; the note goes out as a thread message.
          await ctx.sendInThread(rec, 'message', text);
          ctx.record('reply-held', { taskId });
          return { ok: true as const, note: 'task is held for the session owner; your text was sent as a message and the thread stays open' };
        }
        await ctx.sendInThread(rec, 'result', text, 'done');
        store.update(taskId, { status: 'done', reason: undefined });
        store.clearActive();
        ctx.record('reply', { taskId, to: rec.peer });
        await ctx.injectNext();
        return { ok: true as const };
      }),

    status: (a) =>
      serial(async () => {
        const rec = store.get(String(a?.taskId ?? ''));
        if (!rec) throw new Error('unknown task');
        let active = false;
        try {
          active = store.active()?.taskId === rec.taskId;
        } catch {
          /* report as inactive */
        }
        return {
          taskId: rec.taskId, role: rec.role ?? 'receiver', peer: rec.peer, status: rec.status,
          ...(rec.reason !== undefined ? { reason: rec.reason } : {}), active,
        };
      }),
  };

  /** A receiver task left active by a previous process. */
  async function resumeLeftover(taskId: string): Promise<void> {
    const rec = store.get(taskId);
    const sc = ctx.sessionConfig();
    if (!rec || !isOpen(rec)) return store.clearActive();
    if (!sc || !sc.allow.includes(rec.from)) {
      store.clearActive();
      store.update(taskId, { status: 'rejected', reason: 'session is no longer shared' });
      return sendStatusSafe(rec, 'rejected', 'session is no longer shared');
    }
    // Held stays held (the hook keeps blocking until the owner decides); a running task is shown to this session again.
    const a = store.activeRaw()!;
    // Re-stamp the marker with this process's pid so the hook keeps honouring it.
    store.setActive({ ...a });
    if (rec.status === 'held') return;
    ctx.notify({ content: a.task, meta: { kind: 'task', task_id: a.taskId, from: a.from, track: a.track } });
  }

  let stopped = false;
  return {
    deliver: (outer) => serial(() => handleDeliver(ctx, outer)),
    session,
    tools,
    start: () =>
      inHome(async () => {
        await ready();
        client.on('deliver', (outer) => {
          void serial(() => handleDeliver(ctx, outer)).catch((e: Error) => log(`inbound failed: ${e.message}`));
        });
        client.on('error', (e: Error) => log(`relay: ${e.message}`));
        control = startControl(ctx, serial);
        await client.connect();
        await serial(async () => {
          // A marker left by a previous server. A sender (or result) marker of a Claude Code that is still alive is kept
          // as is. One whose Claude Code is gone may belong to this Claude Code resumed (`--resume`/`--continue`), whose
          // context still holds the peer text: it is re-stamped with this parent, keeping ts (so a hold stays a hold)
          // and expiresAt. Receiver tasks resume.
          const a = store.activeRaw();
          if (a?.role === 'sender') {
            if (a.pid === undefined || !processAlive(a.pid) || a.pid === store.owner()) {
              store.setActive({ ...a });
              ctx.record('marker-restamped', { taskId: a.taskId, role: a.role, previousPid: a.pid });
            }
          } else if (a?.role === 'receiver') await resumeLeftover(a.taskId);
          await ctx.injectNext();
        }).catch((e: Error) => log(`startup state: ${e.message}`));
      }),
    stop: () =>
      inHome(async () => {
        if (stopped) return;
        stopped = true;
        control?.stop();
        client.close();
        await chain;
        // Send-only sessions are ephemeral: nothing can reach them after this process ends.
        if (!receiver) rmSync(sessionDir(session), { recursive: true, force: true });
      }),
  };
}
