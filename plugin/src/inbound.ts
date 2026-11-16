import { open } from '@claude-bridge/core';
import type { Inner, Outer } from '@claude-bridge/core';
import type { Ctx } from './bridge.js';
import { ENVELOPE_TTL_MS, MAX_TEXT_BYTES } from './bridge.js';
import { PinMismatchError } from './keystore.js';
import { savePending } from './pending.js';
import { gateTask } from './policy/gate.js';
import type { TaskRec, TaskStatus } from './tasks.js';

const TASK_ID = /^[0-9a-f]{32}$/;
const SAFE_NAME = /^[A-Za-z0-9._-]{1,128}$/;
const KINDS = new Set(['task', 'message', 'result', 'status']);
const STATUSES = new Set(['queued', 'running', 'held', 'rejected', 'done']);
const MAX_FUTURE_MS = 5 * 60_000;
const HELD_BY_POLICY = 'held by policy';
/** Status values a sender accepts from the receiver (a thread ends only through a result). */
const PEER_STATUSES = new Set(['queued', 'running', 'held', 'rejected']);

/** Structural checks on a decrypted, signature-verified inner envelope; returns a reason or undefined. */
function invalid(ctx: Ctx, inner: Inner): string | undefined {
  if (inner.v !== 1) return 'unsupported version';
  if (!KINDS.has(inner.kind)) return 'unknown kind';
  if (typeof inner.taskId !== 'string' || !TASK_ID.test(inner.taskId)) return 'bad task id';
  if (!Number.isSafeInteger(inner.seq) || inner.seq < 1) return 'bad seq';
  if (typeof inner.body !== 'string' || Buffer.byteLength(inner.body, 'utf8') > MAX_TEXT_BYTES) return 'bad body';
  if (inner.status !== undefined && !STATUSES.has(inner.status)) return 'bad status';
  if (typeof inner.ts !== 'number' || ctx.now() - inner.ts > ENVELOPE_TTL_MS) return 'expired';
  if (inner.ts - ctx.now() > MAX_FUTURE_MS) return 'timestamp in the future';
  if (inner.to !== ctx.me || inner.session !== ctx.session) return 'not addressed to this session';
  // These end up in channel-event attributes and file names: keep them to the safe name alphabet.
  if (!SAFE_NAME.test(inner.from) || !SAFE_NAME.test(inner.fromSession)) return 'bad sender name';
  return undefined;
}

/** Decrypt, authenticate and route one delivered envelope. Never throws for bad input; drops and audits instead. */
export async function handleDeliver(ctx: Ctx, outer: Outer): Promise<void> {
  const from = typeof outer?.from === 'string' ? outer.from : '?';
  if (outer?.to !== ctx.me || outer.session !== ctx.session) {
    return ctx.record('inbound-drop', { from, reason: 'not addressed to this session' });
  }
  let inner: Inner;
  try {
    const peer = await ctx.peerKey(outer.from);
    inner = open(outer, ctx.keys, peer.signPub);
  } catch (e) {
    if (e instanceof PinMismatchError) {
      ctx.log(e.message);
      return ctx.record('pin-mismatch', { from, error: e.message });
    }
    return ctx.record('inbound-drop', { from, reason: (e as Error).message });
  }
  const bad = invalid(ctx, inner);
  if (bad) return ctx.record('inbound-drop', { from, taskId: inner.taskId, kind: inner.kind, reason: bad });

  const { store } = ctx;
  const peer = `${inner.from}/${inner.fromSession}`;
  const rec = store.get(inner.taskId);
  // Only the thread's counterpart may advance its seq; a task must open a brand-new thread.
  if (inner.kind !== 'task' && (!rec || rec.peer !== peer)) {
    return ctx.record('inbound-drop', { from: peer, taskId: inner.taskId, kind: inner.kind, reason: 'not a thread with this peer' });
  }
  if (inner.seq <= store.lastSeq(inner.taskId) || (inner.kind === 'task' && rec)) {
    return ctx.record('replay', { from: peer, taskId: inner.taskId, kind: inner.kind, seq: inner.seq });
  }
  store.setLastSeq(inner.taskId, inner.seq);
  ctx.record('inbound', { kind: inner.kind, taskId: inner.taskId, from: peer, seq: inner.seq, status: inner.status, bytes: Buffer.byteLength(inner.body) });

  if (inner.kind === 'task') return onTask(ctx, inner, peer);
  if (!rec) return;
  if (inner.kind === 'message') return onMessage(ctx, inner, rec);
  if (inner.kind === 'result') return onResult(ctx, inner, rec);
  return onStatus(ctx, inner, rec);
}

/** Status bodies are fixed strings: no classifier or hook reasons cross to the other person. */
async function reply(ctx: Ctx, rec: TaskRec, status: TaskStatus, body: string): Promise<void> {
  try {
    await ctx.sendInThread(rec, 'status', body, status);
  } catch (e) {
    ctx.record('send-failed', { taskId: rec.taskId, kind: 'status', status, error: (e as Error).message });
  }
}

async function onTask(ctx: Ctx, inner: Inner, peer: string): Promise<void> {
  const { store } = ctx;
  const rec: TaskRec = {
    taskId: inner.taskId, threadId: inner.taskId, from: inner.from, body: inner.body, status: 'queued',
    ts: ctx.now(), role: 'receiver', peer, outSeq: 0,
  };
  const sc = ctx.sessionConfig();
  if (!ctx.receiver || !sc || !sc.allow.includes(inner.from)) {
    store.add({ ...rec, status: 'rejected', reason: 'not shared' });
    ctx.record('task-reject', { taskId: rec.taskId, from: peer, reason: 'not shared' });
    return reply(ctx, rec, 'rejected', 'not shared');
  }
  store.add(rec);
  const v = await gateTask(inner.body, sc.track, ctx.threshold(sc), ctx.classify);
  ctx.record('gate', { taskId: rec.taskId, from: peer, kind: 'task', decision: v.decision, risk: v.risk, reason: v.reason });
  if (v.decision === 'hold') {
    // The classifier's reason (about peer text) stays in the audit; bridge_status shows a fixed phrase.
    store.update(rec.taskId, { status: 'held', reason: HELD_BY_POLICY });
    return reply(ctx, rec, 'held', 'waiting for the session owner');
  }
  if (!ctx.busy()) {
    await ctx.activate(rec);
    return;
  }
  return reply(ctx, rec, 'queued', 'queued behind other work in this session');
}

const heldNotice = (ctx: Ctx, rec: TaskRec, what: string) =>
  ctx.notify({
    content: `${what} from ${rec.peer} in thread ${rec.taskId} was held by claude-bridge policy; it was not delivered. ` +
      'The session owner can review it outside this session.',
    meta: { kind: 'status', task_id: rec.taskId, from: rec.peer ?? '', status: 'held' },
  });

async function onMessage(ctx: Ctx, inner: Inner, rec: TaskRec): Promise<void> {
  const { store } = ctx;
  if (rec.status === 'done' || rec.status === 'rejected') {
    return ctx.record('inbound-drop', { from: rec.peer, taskId: rec.taskId, kind: 'message', reason: `thread is ${rec.status}` });
  }
  if (rec.role !== 'sender') {
    // Unsharing or narrowing a share takes effect at once, even for a thread already open.
    const sc = ctx.sessionConfig();
    if (!sc || !sc.allow.includes(rec.from)) {
      return ctx.record('inbound-drop', { from: rec.peer, taskId: rec.taskId, kind: 'message', reason: 'session is no longer shared with the sender' });
    }
  }
  let active;
  try {
    active = store.active();
  } catch (e) {
    ctx.record('active-unreadable', { error: (e as Error).message });
    return reply(ctx, rec, 'held', 'waiting for the session owner');
  }
  let track: string;
  let threshold: number;
  if (rec.role === 'sender') {
    track = ctx.senderTrack(rec);
    threshold = ctx.threshold(ctx.sessionConfig());
  } else {
    if (active?.role !== 'receiver' || active.taskId !== rec.taskId) {
      ctx.record('inbound-drop', { from: rec.peer, taskId: rec.taskId, kind: 'message', reason: 'task is not active' });
      return reply(ctx, rec, rec.status, 'message not delivered: the task is not active');
    }
    track = active.track;
    threshold = active.threshold;
  }
  const v = await gateTask(inner.body, track, threshold, ctx.classify);
  ctx.record('gate', { taskId: rec.taskId, from: rec.peer, kind: 'message', decision: v.decision, risk: v.risk, reason: v.reason });
  const item = { taskId: rec.taskId, kind: 'message' as const, seq: inner.seq, from: rec.peer ?? '', body: inner.body, ts: ctx.now() };
  if (v.decision === 'hold') {
    savePending(ctx.session, { ...item, state: 'held', reason: v.reason });
    heldNotice(ctx, rec, 'A message');
    return reply(ctx, rec, 'held', 'waiting for the session owner');
  }
  // Symmetric gating: a sender-side answer runs under its own marker, so it waits while another thread holds one.
  // A thread whose marker the hook holds takes no new turns until the owner decides (a peer cannot lift the hold).
  // An orphaned server (no Claude Code to gate) keeps every turn queued.
  const otherThread = !store.hasOwner() ||
    (rec.role === 'sender' && (ctx.paused() || (active !== undefined && active.taskId !== rec.taskId)));
  const hookHeld = active !== undefined && active.taskId === rec.taskId && ctx.heldNow(active);
  if (otherThread || hookHeld) {
    savePending(ctx.session, { ...item, state: 'queued' });
    ctx.notify({
      content: hookHeld
        ? `A message from ${rec.peer} in thread ${rec.taskId} is queued until the session owner reviews the held thread.`
        : `A message from ${rec.peer} in thread ${rec.taskId} is queued until the current bridge thread in this session finishes.`,
      meta: { kind: 'status', task_id: rec.taskId, from: rec.peer ?? '', status: 'queued' },
    });
    return reply(ctx, rec, 'queued', 'queued behind other work in this session');
  }
  ctx.deliverMessage(rec, inner.body, false);
}

async function onResult(ctx: Ctx, inner: Inner, rec: TaskRec): Promise<void> {
  if (rec.role !== 'sender' || rec.status === 'done' || rec.status === 'rejected') {
    return ctx.record('inbound-drop', { from: rec.peer, taskId: rec.taskId, kind: 'result', reason: 'not an open thread opened here' });
  }
  const track = `result of a task sent to ${rec.peer}: ${rec.body}`;
  const v = await gateTask(inner.body, track, ctx.threshold(ctx.sessionConfig()), ctx.classify);
  ctx.record('gate', { taskId: rec.taskId, from: rec.peer, kind: 'result', decision: v.decision, risk: v.risk, reason: v.reason });
  ctx.store.update(rec.taskId, { status: 'done', reason: v.decision === 'hold' ? 'result held by policy' : undefined });
  // The thread is over: its own marker goes (even if hook-held); a result waits only for another thread's marker.
  clearOwnMarker(ctx, rec.taskId);
  const item = { taskId: rec.taskId, kind: 'result' as const, from: rec.peer ?? '', body: inner.body, ts: ctx.now() };
  if (v.decision === 'hold') {
    savePending(ctx.session, { ...item, state: 'held', reason: v.reason });
    heldNotice(ctx, rec, 'The result');
  } else if (ctx.busy()) {
    savePending(ctx.session, { ...item, state: 'queued' });
    ctx.notify({
      content: `The result from ${rec.peer} for thread ${rec.taskId} is queued until the current bridge thread in this session finishes.`,
      meta: { kind: 'status', task_id: rec.taskId, from: rec.peer ?? '', status: 'queued' },
    });
  } else {
    ctx.deliverResult(rec, inner.body);
  }
  await ctx.injectNext();
}

function clearOwnMarker(ctx: Ctx, taskId: string): void {
  try {
    const a = ctx.store.active();
    if (a?.role === 'sender' && a.taskId === taskId) ctx.store.clearActive();
  } catch {
    /* left in place: the hook keeps failing closed */
  }
}

/** Receivers ignore peer status entirely; senders show only a fixed template, never peer-written text. */
async function onStatus(ctx: Ctx, inner: Inner, rec: TaskRec): Promise<void> {
  const status = inner.status;
  if (rec.role !== 'sender' || !status || !PEER_STATUSES.has(status) || rec.status === 'done' || rec.status === 'rejected') {
    return ctx.record('inbound-drop', { from: rec.peer, taskId: rec.taskId, kind: 'status', status, reason: 'status not accepted' });
  }
  ctx.store.update(rec.taskId, { status, reason: undefined });
  ctx.notify({
    content: `Thread ${rec.taskId} with ${rec.peer}: ${status}`,
    meta: { kind: 'status', task_id: rec.taskId, from: rec.peer ?? '', status },
  });
  if (status === 'rejected') await ctx.endSenderThread(rec.taskId);
}
