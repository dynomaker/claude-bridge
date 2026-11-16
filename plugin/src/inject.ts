import type { Ctx } from './bridge.js';
import { listPending, removePending } from './pending.js';
import type { PendingItem } from './pending.js';
import type { TaskRec } from './tasks.js';

const isOpen = (r: TaskRec) => r.status !== 'done' && r.status !== 'rejected';

function dropClosed(ctx: Ctx, item: PendingItem, rec: TaskRec | undefined): void {
  removePending(ctx.session, item);
  ctx.record('queued-message-dropped', { taskId: item.taskId, seq: item.seq, reason: 'thread ended' });
  ctx.notify({
    content: `A queued message from ${item.from} in thread ${item.taskId} was dropped because the thread ended.`,
    meta: { kind: 'status', task_id: item.taskId, from: item.from, status: rec?.status ?? 'done' },
  });
}

/**
 * Inject whatever waits, in order: turns queued for the active (not hook-held) thread; with no active marker,
 * the oldest queued result or answer of another thread (each sets a sender marker); then the next queued receiver task.
 */
export async function injectNext(ctx: Ctx): Promise<void> {
  // Orphaned server: no Claude Code the hook could gate, so everything stays queued.
  if (ctx.paused() || !ctx.store.hasOwner()) return;
  const { store } = ctx;
  let active;
  try {
    active = store.active();
  } catch (e) {
    ctx.record('active-unreadable', { error: (e as Error).message });
    return;
  }
  // Queued turns of threads that ended are dropped (with a notice) whatever marker is active.
  for (const item of listPending(ctx.session)) {
    if (item.state !== 'queued' || item.kind !== 'message') continue;
    const rec = store.get(item.taskId);
    if (!rec || !isOpen(rec)) dropClosed(ctx, item, rec);
  }
  if (active) {
    if (ctx.heldNow(active)) return;
    for (const item of listPending(ctx.session, active.taskId)) {
      if (item.state !== 'queued' || item.kind !== 'message') continue;
      const rec = store.get(item.taskId);
      if (!rec || !isOpen(rec)) {
        dropClosed(ctx, item, rec);
        continue;
      }
      removePending(ctx.session, item);
      ctx.deliverMessage(rec, item.body, item.approved === true);
    }
    return;
  }
  for (const item of listPending(ctx.session)) {
    if (item.state !== 'queued') continue;
    const rec = store.get(item.taskId);
    if (item.kind === 'result') {
      removePending(ctx.session, item);
      if (!rec) {
        ctx.record('queued-result-dropped', { taskId: item.taskId, reason: 'unknown thread' });
        continue;
      }
      ctx.deliverResult(rec, item.body); // sets a sender marker: the rest waits for it
      return;
    }
    if (!rec || !isOpen(rec)) {
      dropClosed(ctx, item, rec);
      continue;
    }
    // A receiver task's turns wait until that task is active again.
    if (rec.role !== 'sender') continue;
    removePending(ctx.session, item);
    ctx.deliverMessage(rec, item.body, item.approved === true);
    return;
  }
  if (!ctx.receiver) return;
  for (;;) {
    const next = store.nextQueued();
    if (!next || (await ctx.activate(next))) return;
  }
}
