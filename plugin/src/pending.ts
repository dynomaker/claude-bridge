import { existsSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { writeSecureFile } from './keystore.js';
import { assertSafeName, sessionDir } from './paths.js';

/**
 * An inbound message or result that was not injected: `held` by policy (released by the owner) or
 * `queued` behind another active thread (injected when it clears). Stored as
 * `sessionDir/held/<taskId>-<seq>.json` or `<taskId>-result.json`, mode 0600.
 */
export type PendingItem = {
  taskId: string;
  kind: 'message' | 'result';
  /** Envelope seq for messages; absent for results. */
  seq?: number;
  /** Counterpart endpoint "person/session". */
  from: string;
  body: string;
  state: 'held' | 'queued';
  reason?: string;
  approved?: boolean;
  /** Local receipt time. */
  ts: number;
};

const FILE = /^([0-9a-f]{32})-(\d+|result)\.json$/;

const heldDir = (session: string) => join(sessionDir(session), 'held');
const fileName = (p: Pick<PendingItem, 'taskId' | 'kind' | 'seq'>) => `${p.taskId}-${p.kind === 'result' ? 'result' : String(p.seq)}.json`;

export function savePending(session: string, item: PendingItem): void {
  assertSafeName(item.taskId, 'task id');
  if (item.kind === 'message' && !Number.isSafeInteger(item.seq)) throw new Error('pending message needs a seq');
  writeSecureFile(join(heldDir(session), fileName(item)), JSON.stringify(item));
}

export function removePending(session: string, item: Pick<PendingItem, 'taskId' | 'kind' | 'seq'>): void {
  rmSync(join(heldDir(session), fileName(item)), { force: true });
}

/** All readable pending items, oldest first; optionally only those of one thread. Unreadable files are skipped. */
export function listPending(session: string, taskId?: string): PendingItem[] {
  const dir = heldDir(session);
  if (!existsSync(dir)) return [];
  const out: PendingItem[] = [];
  for (const name of readdirSync(dir)) {
    const m = FILE.exec(name);
    if (!m || (taskId !== undefined && m[1] !== taskId)) continue;
    try {
      const v = JSON.parse(readFileSync(join(dir, name), 'utf8')) as PendingItem;
      if (v && typeof v.body === 'string' && v.taskId === m[1]) out.push(v);
    } catch {
      /* skip */
    }
  }
  return out.sort((a, b) => a.ts - b.ts || (a.seq ?? 0) - (b.seq ?? 0));
}
