import Database from 'better-sqlite3';
import { randomBytes } from 'node:crypto';
import type { Outer, PublicIdentity } from '@claude-bridge/core';

export const QUEUE_TTL_MS = 86_400_000;
export const THREAD_IDLE_MS = 86_400_000;
export const THREAD_MAX_AGE_MS = 7 * 86_400_000;

/** `threadId` is the thread the envelope was sent in (absent for rows queued before the column existed). */
export type Queued = { outer: Outer; enqueuedAt: number; threadId?: string };

type ThreadRow = { a: string; a_session: string; b: string; b_session: string };
function samePair(r: ThreadRow, x: string, xs: string, y: string, ys: string): boolean {
  return (
    (r.a === x && r.a_session === xs && r.b === y && r.b_session === ys) ||
    (r.a === y && r.a_session === ys && r.b === x && r.b_session === xs)
  );
}

export class Store {
  private db: Database.Database;

  constructor(dbPath: string) {
    this.db = new Database(dbPath);
    this.db.pragma('journal_mode = WAL');
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS identities (
        id TEXT PRIMARY KEY, sign_pub TEXT NOT NULL, box_pub TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0
      );
      CREATE TABLE IF NOT EXISTS invites (code TEXT PRIMARY KEY, name TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS shares (
        owner TEXT NOT NULL, session TEXT NOT NULL, allow_json TEXT NOT NULL, track TEXT NOT NULL,
        PRIMARY KEY (owner, session)
      );
      CREATE TABLE IF NOT EXISTS queue (
        id INTEGER PRIMARY KEY AUTOINCREMENT, recipient TEXT NOT NULL, sender TEXT NOT NULL,
        from_session TEXT NOT NULL, session TEXT NOT NULL, ct TEXT NOT NULL, enqueued_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS threads (
        thread_id TEXT PRIMARY KEY, a TEXT NOT NULL, a_session TEXT NOT NULL,
        b TEXT NOT NULL, b_session TEXT NOT NULL, created_ts INTEGER NOT NULL, last_ts INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS queue_recipient ON queue (recipient, session, id);
    `);
    const cols = this.db.prepare('PRAGMA table_info(queue)').all() as { name: string }[];
    if (!cols.some((c) => c.name === 'thread_id')) this.db.exec('ALTER TABLE queue ADD COLUMN thread_id TEXT');
  }

  close(): void {
    this.db.close();
  }

  createInvite(name: string): string {
    const code = randomBytes(16).toString('hex');
    this.db.prepare('INSERT INTO invites (code, name) VALUES (?, ?)').run(code, name);
    return code;
  }

  redeemInvite(code: string, signPub: string, boxPub: string): PublicIdentity {
    return this.db.transaction((): PublicIdentity => {
      const inv = this.db.prepare('SELECT name FROM invites WHERE code = ?').get(code) as { name: string } | undefined;
      if (!inv) throw new Error('invalid or used invite');
      if (this.db.prepare('SELECT 1 FROM identities WHERE id = ?').get(inv.name)) {
        throw new Error('name already registered');
      }
      this.db.prepare('DELETE FROM invites WHERE code = ?').run(code);
      this.db.prepare('INSERT INTO identities (id, sign_pub, box_pub) VALUES (?, ?, ?)').run(inv.name, signPub, boxPub);
      return { id: inv.name, signPub, boxPub };
    })();
  }

  /** Revoked identities are reported as absent. */
  getIdentity(id: string): PublicIdentity | undefined {
    const r = this.db.prepare('SELECT id, sign_pub, box_pub FROM identities WHERE id = ? AND revoked = 0').get(id) as
      | { id: string; sign_pub: string; box_pub: string }
      | undefined;
    return r && { id: r.id, signPub: r.sign_pub, boxPub: r.box_pub };
  }

  revokeIdentity(id: string): void {
    this.db.transaction(() => {
      this.db.prepare('UPDATE identities SET revoked = 1 WHERE id = ?').run(id);
      this.db.prepare('DELETE FROM queue WHERE sender = ?').run(id);
      this.db.prepare('DELETE FROM shares WHERE owner = ?').run(id);
      this.db.prepare('DELETE FROM threads WHERE a = ? OR b = ?').run(id, id);
    })();
  }

  /**
   * Creates or replaces a share. Narrowing it ends the threads opened INTO (owner, session) by people no longer allowed,
   * and drops their queued envelopes; threads that (owner, session) itself opened to others are kept.
   */
  setShare(owner: string, session: string, allow: string[], track: string): void {
    this.db.transaction(() => {
      this.db
        .prepare(
          `INSERT INTO shares (owner, session, allow_json, track) VALUES (?, ?, ?, ?)
           ON CONFLICT (owner, session) DO UPDATE SET allow_json = excluded.allow_json, track = excluded.track`,
        )
        .run(owner, session, JSON.stringify(allow), track);
      this.dropInbound(owner, session, new Set(allow));
    })();
  }

  /** Removes a share: every thread opened into (owner, session) ends; threads it opened to others are kept. */
  deleteShare(owner: string, session: string): void {
    this.db.transaction(() => {
      this.db.prepare('DELETE FROM shares WHERE owner = ? AND session = ?').run(owner, session);
      this.dropInbound(owner, session, new Set());
    })();
  }

  /**
   * Ends threads where (owner, session) is the receiving (b) side and the opener is not in `allowed`, and drops the
   * envelopes queued for (owner, session) in those threads. Envelopes without a known thread (older rows without a
   * thread id, or a thread already purged) are dropped when their sender is not allowed, unless (owner, session)
   * opened a thread to that exact endpoint.
   */
  private dropInbound(owner: string, session: string, allowed: Set<string>): void {
    const threads = this.db
      .prepare('SELECT thread_id, a, a_session, b, b_session FROM threads WHERE (a = ? AND a_session = ?) OR (b = ? AND b_session = ?)')
      .all(owner, session, owner, session) as ({ thread_id: string } & ThreadRow)[];
    const opened = threads.filter((t) => t.a === owner && t.a_session === session);
    const revoked = new Set(
      threads.filter((t) => !(t.a === owner && t.a_session === session) && !allowed.has(t.a)).map((t) => t.thread_id),
    );
    const dropThread = this.db.prepare('DELETE FROM threads WHERE thread_id = ?');
    for (const id of revoked) dropThread.run(id);
    const known = new Set(threads.map((t) => t.thread_id));
    const queued = this.db
      .prepare('SELECT id, sender, from_session, thread_id FROM queue WHERE recipient = ? AND session = ?')
      .all(owner, session) as { id: number; sender: string; from_session: string; thread_id: string | null }[];
    const dropQueued = this.db.prepare('DELETE FROM queue WHERE id = ?');
    for (const q of queued) {
      // A row whose thread is unknown (older row, or its thread was purged) is judged by its sender.
      const drop = q.thread_id !== null && known.has(q.thread_id)
        ? revoked.has(q.thread_id)
        : !allowed.has(q.sender) && !opened.some((t) => t.b === q.sender && t.b_session === q.from_session);
      if (drop) dropQueued.run(q.id);
    }
  }

  listShares(owner: string): { session: string; allow: string[]; track: string }[] {
    const rows = this.db
      .prepare('SELECT session, allow_json, track FROM shares WHERE owner = ? ORDER BY session')
      .all(owner) as { session: string; allow_json: string; track: string }[];
    return rows.map((r) => ({ session: r.session, allow: JSON.parse(r.allow_json) as string[], track: r.track }));
  }

  canSend(from: string, owner: string, session: string): boolean {
    if (!this.getIdentity(from)) return false;
    const r = this.db.prepare('SELECT allow_json FROM shares WHERE owner = ? AND session = ?').get(owner, session) as
      | { allow_json: string }
      | undefined;
    return !!r && (JSON.parse(r.allow_json) as string[]).includes(from);
  }

  enqueue(outer: Outer, now: number, threadId?: string): void {
    this.db
      .prepare('INSERT INTO queue (recipient, sender, from_session, session, ct, enqueued_at, thread_id) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .run(outer.to, outer.from, outer.fromSession, outer.session, outer.ct, now, threadId ?? null);
  }

  /** Removes and returns the queued envelopes for one (recipient, session) endpoint, oldest first. */
  drain(to: string, session: string, now: number): Queued[] {
    return this.db.transaction((): Queued[] => {
      const rows = this.db
        .prepare(
          'SELECT sender, from_session, ct, enqueued_at, thread_id FROM queue WHERE recipient = ? AND session = ? AND enqueued_at >= ? ORDER BY id',
        )
        .all(to, session, now - QUEUE_TTL_MS) as
        { sender: string; from_session: string; ct: string; enqueued_at: number; thread_id: string | null }[];
      this.db.prepare('DELETE FROM queue WHERE recipient = ? AND session = ?').run(to, session);
      return rows.map((r) => ({
        outer: { from: r.sender, fromSession: r.from_session, to, session, ct: r.ct },
        enqueuedAt: r.enqueued_at,
        ...(r.thread_id !== null ? { threadId: r.thread_id } : {}),
      }));
    })();
  }

  /** Records a thread between two endpoints; re-opening with the same endpoints refreshes it. */
  openThread(threadId: string, a: string, aSession: string, b: string, bSession: string, now: number): void {
    this.db.transaction(() => {
      const r = this.db.prepare('SELECT a, a_session, b, b_session FROM threads WHERE thread_id = ?').get(threadId) as
        | { a: string; a_session: string; b: string; b_session: string }
        | undefined;
      if (!r) {
        this.db
          .prepare('INSERT INTO threads (thread_id, a, a_session, b, b_session, created_ts, last_ts) VALUES (?, ?, ?, ?, ?, ?, ?)')
          .run(threadId, a, aSession, b, bSession, now, now);
        return;
      }
      if (!samePair(r, a, aSession, b, bSession)) throw new Error('thread id taken');
      this.db.prepare('UPDATE threads SET last_ts = ? WHERE thread_id = ?').run(now, threadId);
    })();
  }

  /** True iff the thread exists, the two endpoints are its pair (either order), and it was active within 24h and created within 7 days; bumps activity. */
  touchThread(threadId: string, from: string, fromSession: string, to: string, toSession: string, now: number): boolean {
    return this.db.transaction((): boolean => {
      const r = this.db.prepare('SELECT a, a_session, b, b_session, created_ts, last_ts FROM threads WHERE thread_id = ?').get(threadId) as
        | { a: string; a_session: string; b: string; b_session: string; created_ts: number; last_ts: number }
        | undefined;
      if (!r || !samePair(r, from, fromSession, to, toSession)) return false;
      if (r.last_ts < now - THREAD_IDLE_MS || r.created_ts < now - THREAD_MAX_AGE_MS) return false;
      this.db.prepare('UPDATE threads SET last_ts = ? WHERE thread_id = ?').run(now, threadId);
      return true;
    })();
  }

  purgeExpired(now: number): number {
    const q = this.db.prepare('DELETE FROM queue WHERE enqueued_at < ?').run(now - QUEUE_TTL_MS).changes;
    this.db.prepare('DELETE FROM threads WHERE last_ts < ? OR created_ts < ?').run(now - THREAD_IDLE_MS, now - THREAD_MAX_AGE_MS);
    return q;
  }
}
