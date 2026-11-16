import { existsSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { writeSecureFile } from './keystore.js';
import { assertSafeName, sessionDir } from './paths.js';

export type TaskStatus = 'queued' | 'running' | 'held' | 'rejected' | 'done';
export type TaskRec = {
  taskId: string;
  threadId: string;
  from: string;
  body: string;
  status: TaskStatus;
  reason?: string;
  /** Set locally by the server on receipt; never taken from the sender. */
  ts: number;
  /** 'receiver' for threads opened by a remote sender (default), 'sender' for threads this session opened. */
  role?: 'receiver' | 'sender';
  /** Counterpart endpoint as "person/session"; outbound envelopes of this thread go there. */
  peer?: string;
  /** Last seq this side sent in the thread. */
  outSeq?: number;
  /** Owner approved a held task that is waiting in the queue. */
  approved?: boolean;
};

/** Marker for the task a session is currently handling (receiver) or reacting to (sender). */
export type ActiveRec = {
  taskId: string;
  threadId: string;
  role: 'receiver' | 'sender';
  task: string;
  from: string;
  track: string;
  threshold: number;
  approved: boolean;
  scope?: string;
  /** Working directory of the session; lets the hook find markers of send-only (tmp-*) sessions. */
  cwd?: string;
  /**
   * Pid of the Claude Code process whose context holds the peer text (the server's parent); a marker whose process is
   * gone counts as absent. The server dying alone does not lift it.
   */
  pid?: number;
  /** Absolute expiry (ms epoch); an expired marker counts as absent unless the hook holds it. Set on result markers. */
  expiresAt?: number;
  ts: number;
};

/** False only when no process with this pid exists (EPERM means it exists under another user). */
export function processAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code !== 'ESRCH';
  }
}

/**
 * Held-state contract (shared by hook and server): a held event in `held-events.jsonl` is `{taskId, reason, ts}`.
 * `rec` is held iff some event for its task has `ts >= rec.ts` (or no numeric ts). An unparseable FINAL line counts as
 * held (a write may be in progress, fail closed); unparseable earlier lines are ignored. Read errors throw.
 */
export function heldIn(dir: string, rec: Pick<ActiveRec, 'taskId' | 'ts'>): boolean {
  const p = join(dir, 'held-events.jsonl');
  if (!existsSync(p)) return false;
  const lines = readFileSync(p, 'utf8').split('\n').filter((l) => l.trim());
  for (let i = 0; i < lines.length; i++) {
    try {
      const ev = JSON.parse(lines[i]!) as { taskId?: unknown; ts?: unknown };
      if (ev.taskId === rec.taskId && (typeof ev.ts !== 'number' || ev.ts >= rec.ts)) return true;
    } catch {
      if (i === lines.length - 1) return true;
    }
  }
  return false;
}

/**
 * Whether a marker still applies: its Claude Code process is alive and it has not expired. A held marker never
 * expires (`held` is asked only for an expired one; only the owner or the thread's end lifts a hold).
 */
export function markerLive(rec: ActiveRec, now: number = Date.now(), held: () => boolean = () => false): boolean {
  if (rec.expiresAt !== undefined && rec.expiresAt < now && !held()) return false;
  return rec.pid === undefined || processAlive(rec.pid);
}

/**
 * The Claude Code process this server serves: its parent, as long as the parent is the one it started under and is
 * not init (pid 1). Undefined once the server is orphaned.
 */
export function parentClaudePid(startPpid: number, parentPid: () => number = () => process.ppid): () => number | undefined {
  return () => {
    const p = parentPid();
    return Number.isSafeInteger(p) && p > 1 && p === startPpid ? p : undefined;
  };
}

const STATUSES: readonly string[] = ['queued', 'running', 'held', 'rejected', 'done'];

function readJson(path: string): unknown {
  return JSON.parse(readFileSync(path, 'utf8'));
}

/** Throws unless `v` is a well-formed active record. */
export function parseActive(v: unknown): ActiveRec {
  if (!v || typeof v !== 'object' || Array.isArray(v)) throw new Error('active.json: not an object');
  const r = v as Record<string, unknown>;
  const str = (k: string) => {
    if (typeof r[k] !== 'string') throw new Error(`active.json: ${k} must be a string`);
    return r[k] as string;
  };
  const taskId = str('taskId');
  assertSafeName(taskId, 'task id');
  if (r.role !== 'receiver' && r.role !== 'sender') throw new Error('active.json: invalid role');
  if (typeof r.threshold !== 'number' || !Number.isFinite(r.threshold)) throw new Error('active.json: threshold must be a number');
  if (typeof r.approved !== 'boolean') throw new Error('active.json: approved must be a boolean');
  if (r.scope !== undefined && typeof r.scope !== 'string') throw new Error('active.json: scope must be a string');
  if (r.cwd !== undefined && typeof r.cwd !== 'string') throw new Error('active.json: cwd must be a string');
  if (r.pid !== undefined && (!Number.isSafeInteger(r.pid) || (r.pid as number) <= 0)) throw new Error('active.json: pid must be a positive integer');
  if (r.expiresAt !== undefined && typeof r.expiresAt !== 'number') throw new Error('active.json: expiresAt must be a number');
  if (typeof r.ts !== 'number') throw new Error('active.json: ts must be a number');
  return {
    taskId, threadId: str('threadId'), role: r.role, task: str('task'), from: str('from'), track: str('track'),
    threshold: r.threshold, approved: r.approved, ...(r.scope !== undefined ? { scope: r.scope } : {}),
    ...(r.cwd !== undefined ? { cwd: r.cwd } : {}), ...(r.pid !== undefined ? { pid: r.pid as number } : {}),
    ...(r.expiresAt !== undefined ? { expiresAt: r.expiresAt } : {}), ts: r.ts,
  };
}

/** Per-session task state. Files live under `sessionDir(session)`, mode 0600, written atomically. */
export class TaskStore {
  private readonly dir: string;

  /**
   * `clock` decides marker expiry (default Date.now). `ownerPid` names the Claude Code process markers are stamped
   * with (default: this process's parent while it is not orphaned); only the server writes markers.
   */
  constructor(
    readonly session: string,
    private readonly clock: () => number = Date.now,
    private readonly ownerPid: () => number | undefined = parentClaudePid(process.ppid),
  ) {
    this.dir = sessionDir(session);
  }

  /** The Claude Code pid markers are stamped with; throws when there is none (orphaned server: inject nothing). */
  owner(): number {
    const pid = this.ownerPid();
    if (pid === undefined || !Number.isSafeInteger(pid) || pid <= 1) {
      throw new Error('no parent Claude Code process (orphaned server); refusing to inject peer content');
    }
    return pid;
  }

  /** False when peer content must not be injected (see `owner`). */
  hasOwner(): boolean {
    try {
      this.owner();
      return true;
    } catch {
      return false;
    }
  }

  /** Whether the hook holds `rec` (a held event of its task at or after its ts). Throws on read errors. */
  held(rec: Pick<ActiveRec, 'taskId' | 'ts'>): boolean {
    return heldIn(this.dir, rec);
  }

  private path(name: string): string {
    return join(this.dir, name);
  }

  private load(): TaskRec[] {
    const p = this.path('tasks.json');
    if (!existsSync(p)) return [];
    const v = readJson(p);
    if (!Array.isArray(v)) throw new Error('tasks.json: not an array');
    return v as TaskRec[];
  }

  private save(recs: TaskRec[]): void {
    writeSecureFile(this.path('tasks.json'), JSON.stringify(recs));
  }

  add(rec: TaskRec): void {
    assertSafeName(rec.taskId, 'task id');
    assertSafeName(rec.threadId, 'thread id');
    const recs = this.load();
    if (recs.some((r) => r.taskId === rec.taskId)) throw new Error(`duplicate task: ${rec.taskId}`);
    recs.push(rec);
    this.save(recs);
  }

  /** All task records of the session. */
  list(): TaskRec[] {
    return this.load();
  }

  get(id: string): TaskRec | undefined {
    assertSafeName(id, 'task id');
    return this.load().find((r) => r.taskId === id);
  }

  /** Replay guard: true once a task with this id has ever been added. */
  seen(taskId: string): boolean {
    return this.get(taskId) !== undefined;
  }

  setStatus(id: string, status: TaskStatus, reason?: string): void {
    assertSafeName(id, 'task id');
    if (!STATUSES.includes(status)) throw new Error(`invalid status: ${status}`);
    const recs = this.load();
    const rec = recs.find((r) => r.taskId === id);
    if (!rec) throw new Error(`unknown task: ${id}`);
    rec.status = status;
    if (reason !== undefined) rec.reason = reason;
    else delete rec.reason;
    this.save(recs);
  }

  /** Merge fields into a task record (taskId/threadId are immutable). */
  update(id: string, patch: Partial<Omit<TaskRec, 'taskId' | 'threadId'>>): TaskRec {
    assertSafeName(id, 'task id');
    if (patch.status !== undefined && !STATUSES.includes(patch.status)) throw new Error(`invalid status: ${patch.status}`);
    const recs = this.load();
    const rec = recs.find((r) => r.taskId === id);
    if (!rec) throw new Error(`unknown task: ${id}`);
    Object.assign(rec, patch);
    this.save(recs);
    return rec;
  }

  /** Queued inbound (receiver) task with the smallest `ts`; ties go to the earliest inserted. */
  nextQueued(): TaskRec | undefined {
    return this.load()
      .filter((r) => r.status === 'queued' && r.role !== 'sender')
      .reduce<TaskRec | undefined>((best, r) => (best === undefined || r.ts < best.ts ? r : best), undefined);
  }

  // ---- per-thread replay guard (inbound seq must be > lastSeq)

  private loadSeqs(): Record<string, number> {
    const p = this.path('seqs.json');
    const out: Record<string, number> = Object.create(null);
    if (existsSync(p)) Object.assign(out, readJson(p) as Record<string, number>);
    return out;
  }

  lastSeq(threadId: string): number {
    assertSafeName(threadId, 'thread id');
    const n = this.loadSeqs()[threadId];
    return typeof n === 'number' ? n : 0;
  }

  setLastSeq(threadId: string, seq: number): void {
    assertSafeName(threadId, 'thread id');
    if (!Number.isSafeInteger(seq) || seq < 0) throw new Error(`invalid seq: ${seq}`);
    const seqs = this.loadSeqs();
    seqs[threadId] = seq;
    writeSecureFile(this.path('seqs.json'), JSON.stringify(seqs));
  }

  // ---- active marker

  /**
   * The active record; undefined when absent, expired (and not held), or its Claude Code process is gone.
   * Throws when the file exists but is unreadable or malformed.
   */
  active(): ActiveRec | undefined {
    const rec = this.activeRaw();
    return rec && markerLive(rec, this.clock(), () => this.held(rec)) ? rec : undefined;
  }

  /** The marker file as written, live or stale; undefined when absent. Throws when malformed. */
  activeRaw(): ActiveRec | undefined {
    const p = this.path('active.json');
    if (!existsSync(p)) return undefined;
    return parseActive(readJson(p));
  }

  /**
   * Writes the marker stamped with the Claude Code pid (the server is the only writer). Throws, writing nothing, when the
   * server is orphaned: callers set the marker before injecting, so nothing reaches a session the hook cannot gate.
   */
  setActive(rec: ActiveRec): void {
    const stamped = { ...rec, pid: this.owner() };
    parseActive(stamped);
    writeSecureFile(this.path('active.json'), JSON.stringify(stamped));
  }

  clearActive(): void {
    rmSync(this.path('active.json'), { force: true });
  }
}
