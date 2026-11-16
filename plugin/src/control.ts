import { existsSync, readdirSync, readFileSync, rmSync, statSync, watch } from 'node:fs';
import type { FSWatcher } from 'node:fs';
import { join } from 'node:path';
import type { Ctx } from './bridge.js';
import { ensureDir, writeSecureFile } from './keystore.js';
import { sessionDir } from './paths.js';
import { listPending, removePending, savePending } from './pending.js';
import type { TaskRec } from './tasks.js';

const isOpen = (r: TaskRec) => r.status !== 'done' && r.status !== 'rejected';

export const POLL_MS = 2000;
const DECISION = /^(approve|reject)-([0-9a-f]{32})\.json$/;

type HeldEvent = { taskId: string; reason: string; ts: number };

/**
 * Owner-side inputs of a session (receiving or send-only): hook held-events (`held-events.jsonl`) and CLI decisions
 * (`control/approve-<id>.json`, `control/reject-<id>.json`, `control/pause`). Watched with fs.watch plus a 2s poll.
 * Installs `ctx.paused`, `ctx.pollHeld` and `ctx.latestHeldTs`.
 */
export function startControl(
  ctx: Ctx,
  serial: <T>(fn: () => Promise<T>) => Promise<T>,
): { stop(): void } {
  const dir = sessionDir(ctx.session);
  const controlDir = join(dir, 'control');
  const heldPath = join(dir, 'held-events.jsonl');
  const offsetPath = join(dir, 'held-offset.json');
  ensureDir(controlDir);
  const { store } = ctx;
  /** Sender-side markers already reported as held, keyed by taskId -> marker ts. */
  const notifiedSender = new Map<string, number>();
  let wasPaused = existsSync(join(controlDir, 'pause'));

  ctx.paused = () => existsSync(join(controlDir, 'pause'));
  ctx.latestHeldTs = (taskId) => latestHeldTs(taskId);

  function readOffset(): number {
    try {
      const n = (JSON.parse(readFileSync(offsetPath, 'utf8')) as { offset?: unknown }).offset;
      return typeof n === 'number' && n >= 0 ? n : 0;
    } catch {
      return 0;
    }
  }

  function parseEvent(line: string): HeldEvent | undefined {
    try {
      const e = JSON.parse(line) as Record<string, unknown>;
      if (typeof e.taskId !== 'string' || typeof e.ts !== 'number' || !/^[0-9a-f]{32}$/.test(e.taskId)) return undefined;
      return { taskId: e.taskId, reason: typeof e.reason === 'string' ? e.reason.slice(0, 500) : 'blocked', ts: e.ts };
    } catch {
      return undefined;
    }
  }

  async function applyHeld(ev: HeldEvent): Promise<void> {
    const active = store.active();
    if (!active || active.taskId !== ev.taskId || ev.ts < active.ts) {
      return ctx.record('held-event-ignored', { taskId: ev.taskId, reason: 'not the active task or superseded' });
    }
    const rec = store.get(ev.taskId);
    if (!rec) return ctx.record('held-event-ignored', { taskId: ev.taskId, reason: 'unknown task' });
    if (active.role === 'receiver') {
      if (rec.status === 'held') return;
      store.update(rec.taskId, { status: 'held', reason: 'held by policy' });
    } else {
      if (notifiedSender.get(rec.taskId) === active.ts) return;
      notifiedSender.set(rec.taskId, active.ts);
    }
    ctx.record('held', { taskId: rec.taskId, role: active.role, reason: ev.reason });
    try {
      // The deny reason stays local (TaskRec + audit); the other person only learns that the owner must look.
      await ctx.sendInThread(rec, 'status', 'waiting for the session owner', 'held');
    } catch (e) {
      ctx.record('send-failed', { taskId: rec.taskId, kind: 'status', status: 'held', error: (e as Error).message });
    }
  }

  /** Applies every complete held-event line after the persisted byte offset. */
  ctx.pollHeld = async () => {
    if (!existsSync(heldPath)) return;
    let offset = readOffset();
    const size = statSync(heldPath).size;
    if (size < offset) offset = 0; // truncated or replaced
    if (size === offset) return;
    const buf = readFileSync(heldPath).subarray(offset);
    const end = buf.lastIndexOf(0x0a);
    if (end < 0) return;
    for (const line of buf.subarray(0, end).toString('utf8').split('\n')) {
      if (!line.trim()) continue;
      const ev = parseEvent(line);
      if (!ev) ctx.record('held-event-ignored', { reason: 'malformed event' });
      else {
        try {
          await applyHeld(ev);
        } catch (e) {
          ctx.record('held-event-ignored', { taskId: ev.taskId, reason: (e as Error).message });
        }
      }
    }
    writeSecureFile(offsetPath, JSON.stringify({ offset: offset + end + 1 }));
  };

  /** Release the oldest policy-held message of a thread (owner approval). */
  function releaseHeldMessage(rec: TaskRec): boolean {
    const item = listPending(ctx.session, rec.taskId).find((p) => p.kind === 'message' && p.state === 'held');
    if (!item) return false;
    ctx.record('approve', { taskId: rec.taskId, kind: 'message', seq: item.seq });
    if (!isOpen(rec)) {
      removePending(ctx.session, item);
      ctx.record('approve-ignored', { taskId: rec.taskId, reason: `thread is ${rec.status}` });
      return true;
    }
    if (rec.role === 'receiver') {
      const active = store.active();
      if (active?.taskId !== rec.taskId) {
        ctx.record('approve-ignored', { taskId: rec.taskId, reason: 'task is not active; message kept' });
        return true;
      }
      removePending(ctx.session, item);
      ctx.deliverMessage(rec, item.body, false);
      return true;
    }
    if (ctx.busy() && store.active()?.taskId !== rec.taskId) {
      savePending(ctx.session, { ...item, state: 'queued', approved: true, reason: undefined });
      return true;
    }
    removePending(ctx.session, item);
    ctx.deliverMessage(rec, item.body, true);
    return true;
  }

  async function approve(taskId: string): Promise<void> {
    // Approving injects peer text; an orphaned server has no Claude Code the hook could gate.
    if (!store.hasOwner()) return ctx.record('approve-ignored', { taskId, reason: 'no parent Claude Code process (orphaned server)' });
    const rec = store.get(taskId);
    const active = store.active();
    if (rec?.role === 'sender') {
      if (active?.role === 'sender' && active.taskId === taskId && active.expiresAt !== undefined) {
        // The owner has seen the result: its time-bounded gating ends.
        store.clearActive();
        ctx.record('approve', { taskId, role: 'sender', marker: 'result' });
        return;
      }
      // The marker branch only applies when the hook holds the marker itself; otherwise release a held message.
      if (active?.role === 'sender' && active.taskId === taskId && ctx.heldNow(active)) {
        store.setActive({ ...active, approved: true, ts: Math.max(ctx.now(), latestHeldTs(taskId) + 1) });
        ctx.record('approve', { taskId, role: 'sender' });
        ctx.notify({ content: active.task, meta: { kind: 'message', task_id: taskId, from: active.from, track: active.track } });
        return;
      }
      if (!releaseHeldMessage(rec)) ctx.record('approve-ignored', { taskId, reason: 'nothing held' });
      return;
    }
    if (!rec) return ctx.record('approve-ignored', { taskId, reason: 'unknown task' });
    if (rec.status !== 'held') {
      if (!releaseHeldMessage(rec)) ctx.record('approve-ignored', { taskId, reason: `task is ${rec.status}` });
      return;
    }
    ctx.record('approve', { taskId, role: 'receiver' });
    store.update(taskId, { approved: true });
    if (active && active.taskId !== taskId) {
      store.update(taskId, { status: 'queued', reason: undefined });
      return;
    }
    if (ctx.paused()) {
      if (active?.taskId === taskId) store.clearActive();
      store.update(taskId, { status: 'queued', reason: undefined });
      return;
    }
    await ctx.activate({ ...rec, approved: true });
  }

  async function reject(taskId: string): Promise<void> {
    const rec = store.get(taskId);
    const active = store.active();
    if (rec?.role === 'sender') {
      if (active?.role !== 'sender' || active.taskId !== taskId) return ctx.record('reject-ignored', { taskId, reason: 'no marker' });
      store.clearActive();
      ctx.record('reject', { taskId, role: 'sender' });
      if (!isOpen(rec)) {
        // A result marker: the thread is already over, nothing to tell the other side.
        await ctx.injectNext();
        return;
      }
      try {
        await ctx.sendInThread(rec, 'status', 'the session owner declined to answer this message', 'rejected');
      } catch (e) {
        ctx.record('send-failed', { taskId, kind: 'status', status: 'rejected', error: (e as Error).message });
      }
      await ctx.injectNext();
      return;
    }
    if (!rec || rec.status === 'done' || rec.status === 'rejected') {
      return ctx.record('reject-ignored', { taskId, reason: rec ? `task is ${rec.status}` : 'unknown task' });
    }
    store.update(taskId, { status: 'rejected', reason: 'rejected by the session owner', approved: undefined });
    ctx.record('reject', { taskId, role: 'receiver' });
    try {
      await ctx.sendInThread(rec, 'status', 'rejected by the session owner', 'rejected');
    } catch (e) {
      ctx.record('send-failed', { taskId, kind: 'status', status: 'rejected', error: (e as Error).message });
    }
    if (active?.taskId === taskId) store.clearActive();
    await ctx.injectNext();
  }

  /** Clear a marker that expired (a result marker nobody cleared or held) and inject what waited behind it. */
  async function sweepExpired(): Promise<void> {
    let raw;
    try {
      raw = store.activeRaw();
    } catch {
      return; // unreadable: left for the hook to fail closed on
    }
    if (!raw || raw.expiresAt === undefined || raw.expiresAt >= ctx.now()) return;
    // A held marker never expires: only the owner (approve/reject/clear) or the thread's end lifts it.
    try {
      if (ctx.heldNow(raw) || store.held(raw)) return;
    } catch {
      return; // held state unreadable: keep the marker
    }
    store.clearActive();
    ctx.record('marker-expired', { taskId: raw.taskId, role: raw.role });
    await ctx.injectNext();
  }

  /** Unsharing or narrowing a share ends the active remote task of a person who is no longer allowed. */
  async function enforceShare(): Promise<void> {
    if (!ctx.receiver) return;
    let active;
    try {
      active = store.active();
    } catch {
      return;
    }
    if (!active || active.role !== 'receiver') return;
    const rec = store.get(active.taskId);
    if (!rec) return;
    let sc;
    try {
      sc = ctx.sessionConfig();
    } catch {
      sc = undefined; // unreadable config counts as not shared
    }
    if (sc && sc.allow.includes(rec.from)) return;
    store.clearActive();
    if (isOpen(rec)) store.update(rec.taskId, { status: 'rejected', reason: 'session is no longer shared', approved: undefined });
    ctx.record('task-reject', { taskId: rec.taskId, from: rec.peer, reason: 'session is no longer shared' });
    ctx.notify({
      content: `Thread ${rec.taskId} with ${rec.peer} was ended: this session is no longer shared with that person. Stop working on it.`,
      meta: { kind: 'status', task_id: rec.taskId, from: rec.peer ?? '', status: 'rejected' },
    });
    try {
      await ctx.sendInThread(rec, 'status', 'session is no longer shared', 'rejected');
    } catch (e) {
      ctx.record('send-failed', { taskId: rec.taskId, kind: 'status', status: 'rejected', error: (e as Error).message });
    }
    await ctx.injectNext();
  }

  async function processControl(): Promise<void> {
    for (const name of readdirSync(controlDir).sort()) {
      if (name === 'pause') continue;
      const m = DECISION.exec(name);
      rmSync(join(controlDir, name), { force: true });
      if (!m) {
        ctx.record('control-ignored', { file: name });
        continue;
      }
      try {
        await (m[1] === 'approve' ? approve(m[2]!) : reject(m[2]!));
        await ctx.injectNext();
      } catch (e) {
        ctx.record('control-failed', { file: name, error: (e as Error).message });
      }
    }
    const paused = ctx.paused();
    if (paused !== wasPaused) ctx.record(paused ? 'pause' : 'resume', {});
    if (wasPaused && !paused) await ctx.injectNext();
    wasPaused = paused;
  }

  function latestHeldTs(taskId: string): number {
    if (!existsSync(heldPath)) return 0;
    let max = 0;
    for (const line of readFileSync(heldPath, 'utf8').split('\n')) {
      if (!line.includes(taskId)) continue;
      const ev = parseEvent(line);
      if (ev?.taskId === taskId && ev.ts > max) max = ev.ts;
    }
    return max;
  }

  /** Marker file for `bridge status`: this session's server is orphaned and injects nothing. */
  const orphanPath = join(dir, 'orphaned.json');
  let orphanNoted = false;
  if (store.hasOwner()) rmSync(orphanPath, { force: true }); // left by an earlier, orphaned server
  function noteOrphaned(): void {
    if (orphanNoted || store.hasOwner()) return;
    orphanNoted = true;
    const msg = 'orphaned: no parent Claude Code process (parent pid is 1 or changed); nothing will be injected and ' +
      'remote work stays queued until the session is restarted';
    ctx.log(msg);
    ctx.record('orphaned', { pid: process.pid, ppid: process.ppid });
    try {
      writeSecureFile(orphanPath, JSON.stringify({ pid: process.pid, ts: ctx.now() }));
    } catch (e) {
      ctx.log(`cannot write ${orphanPath}: ${(e as Error).message}`);
    }
  }

  let scheduled = false;
  const scan = () => {
    if (scheduled) return;
    scheduled = true;
    void serial(async () => {
      scheduled = false;
      noteOrphaned();
      await ctx.pollHeld();
      await processControl();
      await enforceShare();
      await sweepExpired();
    }).catch((e: Error) => ctx.log(`control scan failed: ${e.message}`));
  };

  const watchers: FSWatcher[] = [];
  const targets: [string, (f: string | null) => boolean][] = [
    [dir, (f) => f === null || f === 'held-events.jsonl' || f === 'config.json'],
    [controlDir, () => true],
  ];
  for (const [d, relevant] of targets) {
    try {
      const w = watch(d, (_ev, f) => relevant(f) && scan());
      w.on('error', () => undefined);
      watchers.push(w);
    } catch {
      /* the poll below still covers it */
    }
  }
  const timer = setInterval(scan, POLL_MS);
  timer.unref();
  scan();

  return {
    stop() {
      clearInterval(timer);
      for (const w of watchers) w.close();
    },
  };
}
