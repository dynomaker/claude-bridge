import { describe, expect, it } from 'vitest';
import Database from 'better-sqlite3';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store } from '../src/store.js';

const DAY = 86_400_000;
const outer = (ct = 'x') => ({ from: 'alice', fromSession: 'a1', to: 'bob', session: 's1', ct });

function setup() {
  const s = new Store(':memory:');
  s.redeemInvite(s.createInvite('alice'), 'sa', 'ba');
  s.redeemInvite(s.createInvite('bob'), 'sb', 'bb');
  return s;
}

describe('invites', () => {
  it('redeems once and returns the identity', () => {
    const s = new Store(':memory:');
    const code = s.createInvite('alice');
    expect(code).toMatch(/^[0-9a-f]{32}$/);
    expect(s.redeemInvite(code, 'sp', 'bp')).toEqual({ id: 'alice', signPub: 'sp', boxPub: 'bp' });
    expect(s.getIdentity('alice')).toEqual({ id: 'alice', signPub: 'sp', boxPub: 'bp' });
    expect(() => s.redeemInvite(code, 'sp', 'bp')).toThrow();
  });
  it('rejects unknown codes and already registered names', () => {
    const s = new Store(':memory:');
    expect(() => s.redeemInvite('nope', 'a', 'b')).toThrow();
    s.redeemInvite(s.createInvite('alice'), 'a', 'b');
    const dup = s.createInvite('alice');
    expect(() => s.redeemInvite(dup, 'a', 'b')).toThrow();
  });
});

describe('shares', () => {
  it('gates canSend', () => {
    const s = setup();
    expect(s.canSend('bob', 'alice', 's1')).toBe(false);
    s.setShare('alice', 's1', ['bob'], 'review');
    expect(s.listShares('alice')).toEqual([{ session: 's1', allow: ['bob'], track: 'review' }]);
    expect(s.canSend('bob', 'alice', 's1')).toBe(true);
    expect(s.canSend('carol', 'alice', 's1')).toBe(false);
    s.deleteShare('alice', 's1');
    expect(s.canSend('bob', 'alice', 's1')).toBe(false);
  });
  it('denies a revoked sender', () => {
    const s = setup();
    s.setShare('alice', 's1', ['bob'], 'review');
    s.revokeIdentity('bob');
    expect(s.canSend('bob', 'alice', 's1')).toBe(false);
  });
});

describe('queue', () => {
  it('drains once', () => {
    const s = setup();
    s.enqueue(outer(), 1000);
    expect(s.drain('bob', 's1', 2000)).toEqual([{ outer: outer(), enqueuedAt: 1000 }]);
    expect(s.drain('bob', 's1', 2000)).toEqual([]);
  });
  it('keeps FIFO order and per-recipient queues', () => {
    const s = setup();
    s.enqueue(outer('1'), 1000);
    s.enqueue({ ...outer('2'), to: 'carol' }, 1001);
    s.enqueue(outer('3'), 1002);
    expect(s.drain('bob', 's1', 2000).map((q) => q.outer.ct)).toEqual(['1', '3']);
  });
  it('skips expired entries and purges them', () => {
    const s = setup();
    const now = 10 * DAY;
    s.enqueue(outer('old'), now - DAY - 1);
    s.enqueue(outer('edge'), now - DAY);
    expect(s.drain('bob', 's1', now).map((q) => q.outer.ct)).toEqual(['edge']);
    s.enqueue(outer('old2'), now - DAY - 1);
    expect(s.purgeExpired(now)).toBe(1);
    expect(s.purgeExpired(now)).toBe(0);
  });
});

describe('cleanup', () => {
  it('revoking an identity drops its queued sends and its own shares', () => {
    const s = setup();
    s.setShare('bob', 's2', ['alice'], 't');
    s.setShare('alice', 's1', ['bob'], 't');
    s.enqueue({ from: 'bob', fromSession: 'b1', to: 'alice', session: 's1', ct: 'x' }, 1000);
    s.enqueue({ from: 'alice', fromSession: 'a1', to: 'bob', session: 's2', ct: 'y' }, 1000);
    s.revokeIdentity('bob');
    expect(s.listShares('bob')).toEqual([]);
    expect(s.listShares('alice')).toHaveLength(1);
    expect(s.drain('alice', 's1', 2000)).toEqual([]);
    expect(s.drain('bob', 's2', 2000)).toHaveLength(1);
  });
  it('deleting a share drops envelopes queued for that owner and session only', () => {
    const s = setup();
    s.setShare('alice', 's1', ['bob'], 't');
    s.enqueue({ from: 'bob', fromSession: 'b1', to: 'alice', session: 's1', ct: 'x' }, 1000);
    s.enqueue({ from: 'bob', fromSession: 'b1', to: 'alice', session: 's2', ct: 'y' }, 1000);
    s.deleteShare('alice', 's1');
    expect(s.drain('alice', 's2', 2000).map((q) => q.outer)).toEqual([
      { from: 'bob', fromSession: 'b1', to: 'alice', session: 's2', ct: 'y' },
    ]);
  });
});

describe('queue sessions', () => {
  it('drains only the claimed session and keeps the others', () => {
    const s = setup();
    s.enqueue(outer('1'), 1000);
    s.enqueue({ ...outer('2'), session: 's2' }, 1001);
    expect(s.drain('bob', 's2', 2000).map((q) => q.outer.ct)).toEqual(['2']);
    expect(s.drain('bob', 's1', 2000).map((q) => q.outer)).toEqual([outer('1')]);
  });
});

describe('threads', () => {
  it('touches only between the two endpoints, either direction, within 24h', () => {
    const s = setup();
    s.openThread('t1', 'alice', 'a1', 'bob', 'b1', 1000);
    expect(s.touchThread('t1', 'bob', 'b1', 'alice', 'a1', 2000)).toBe(true);
    expect(s.touchThread('t1', 'alice', 'a1', 'bob', 'b1', 3000)).toBe(true);
    expect(s.touchThread('t1', 'alice', 'a1', 'carol', 'b1', 3000)).toBe(false);
    expect(s.touchThread('t1', 'carol', 'a1', 'bob', 'b1', 3000)).toBe(false);
    expect(s.touchThread('t1', 'alice', 'a2', 'bob', 'b1', 3000)).toBe(false);
    expect(s.touchThread('t1', 'alice', 'a1', 'bob', 'b2', 3000)).toBe(false);
    expect(s.touchThread('nope', 'alice', 'a1', 'bob', 'b1', 3000)).toBe(false);
  });
  it('expires after 24h idle and each touch extends the window', () => {
    const s = setup();
    s.openThread('t1', 'alice', 'a1', 'bob', 'b1', 0);
    expect(s.touchThread('t1', 'bob', 'b1', 'alice', 'a1', DAY)).toBe(true);
    expect(s.touchThread('t1', 'bob', 'b1', 'alice', 'a1', 2 * DAY)).toBe(true);
    expect(s.touchThread('t1', 'bob', 'b1', 'alice', 'a1', 3 * DAY + 1)).toBe(false);
  });
  it('rejects reuse of a thread id by other endpoints, allows re-open by the same pair', () => {
    const s = setup();
    s.openThread('t1', 'alice', 'a1', 'bob', 'b1', 0);
    expect(() => s.openThread('t1', 'carol', 'a1', 'bob', 'b1', 1)).toThrow();
    expect(() => s.openThread('t1', 'alice', 'a2', 'bob', 'b1', 1)).toThrow();
    expect(() => s.openThread('t1', 'bob', 'b1', 'alice', 'a1', 1)).not.toThrow();
  });
  it('purgeExpired removes threads idle more than 24h', () => {
    const s = setup();
    s.openThread('t1', 'alice', 'a1', 'bob', 'b1', 0);
    s.purgeExpired(DAY + 1);
    expect(s.touchThread('t1', 'alice', 'a1', 'bob', 'b1', DAY + 1)).toBe(false);
    s.openThread('t2', 'alice', 'a1', 'bob', 'b1', 0);
    s.purgeExpired(DAY);
    expect(s.touchThread('t2', 'alice', 'a1', 'bob', 'b1', DAY)).toBe(true);
  });
});

describe('thread lifecycle', () => {
  it('deleting a share ends threads that involve that endpoint only', () => {
    const s = setup();
    s.openThread('t1', 'alice', 'a1', 'bob', 'b1', 0);
    s.openThread('t2', 'alice', 'a1', 'bob', 'b2', 0);
    s.deleteShare('bob', 'b1');
    expect(s.touchThread('t1', 'alice', 'a1', 'bob', 'b1', 1)).toBe(false);
    expect(s.touchThread('t2', 'alice', 'a1', 'bob', 'b2', 1)).toBe(true);
  });
  it('narrowing a share ends threads and drops queued envelopes of people no longer allowed', () => {
    const s = setup();
    s.redeemInvite(s.createInvite('carol'), 'sc', 'bc');
    s.setShare('bob', 'b1', ['alice', 'carol'], 't');
    s.openThread('t1', 'alice', 'a1', 'bob', 'b1', 0);
    s.openThread('t2', 'carol', 'c1', 'bob', 'b1', 0);
    s.openThread('t3', 'alice', 'a1', 'bob', 'b2', 0);
    s.enqueue({ from: 'alice', fromSession: 'a1', to: 'bob', session: 'b1', ct: 'from-alice' }, 1);
    s.enqueue({ from: 'carol', fromSession: 'c1', to: 'bob', session: 'b1', ct: 'from-carol' }, 1);
    s.enqueue({ from: 'alice', fromSession: 'a1', to: 'bob', session: 'b2', ct: 'other-session' }, 1);
    s.setShare('bob', 'b1', ['carol'], 't');
    expect(s.touchThread('t1', 'alice', 'a1', 'bob', 'b1', 2)).toBe(false);
    expect(s.touchThread('t2', 'carol', 'c1', 'bob', 'b1', 2)).toBe(true);
    expect(s.touchThread('t3', 'alice', 'a1', 'bob', 'b2', 2)).toBe(true);
    expect(s.drain('bob', 'b1', 2).map((q) => q.outer.ct)).toEqual(['from-carol']);
    expect(s.drain('bob', 'b2', 2).map((q) => q.outer.ct)).toEqual(['other-session']);
  });
  it('share changes keep the threads the owner session opened to others and their queued replies (D)', () => {
    const s = setup();
    s.redeemInvite(s.createInvite('carol'), 'sc', 'bc');
    s.setShare('bob', 'b1', ['alice', 'carol'], 't');
    // bob/b1 opened t-out to alice/a1 (bob is the a side); alice opened t-in into bob/b1 (bob is the b side).
    s.openThread('t-out', 'bob', 'b1', 'alice', 'a1', 0);
    s.openThread('t-in', 'alice', 'a1', 'bob', 'b1', 0);
    s.enqueue({ from: 'alice', fromSession: 'a1', to: 'bob', session: 'b1', ct: 'result-of-out' }, 1, 't-out');
    s.enqueue({ from: 'alice', fromSession: 'a1', to: 'bob', session: 'b1', ct: 'turn-of-in' }, 1, 't-in');
    s.setShare('bob', 'b1', ['carol'], 't');
    expect(s.touchThread('t-out', 'alice', 'a1', 'bob', 'b1', 2)).toBe(true);
    expect(s.touchThread('t-in', 'alice', 'a1', 'bob', 'b1', 2)).toBe(false);
    expect(s.drain('bob', 'b1', 2).map((q) => q.outer.ct)).toEqual(['result-of-out']);

    s.openThread('t-in2', 'carol', 'c1', 'bob', 'b1', 3);
    s.enqueue({ from: 'alice', fromSession: 'a1', to: 'bob', session: 'b1', ct: 'result-of-out-2' }, 3, 't-out');
    s.enqueue({ from: 'carol', fromSession: 'c1', to: 'bob', session: 'b1', ct: 'turn-of-in2' }, 3, 't-in2');
    s.deleteShare('bob', 'b1');
    expect(s.touchThread('t-out', 'bob', 'b1', 'alice', 'a1', 4)).toBe(true);
    expect(s.touchThread('t-in2', 'carol', 'c1', 'bob', 'b1', 4)).toBe(false);
    expect(s.drain('bob', 'b1', 4).map((q) => q.outer.ct)).toEqual(['result-of-out-2']);
  });
  it('a queued row whose thread is gone (purged) is handled like a row without a thread id (M3)', () => {
    const s = setup();
    s.setShare('bob', 'b1', ['alice'], 't');
    s.enqueue({ from: 'alice', fromSession: 'a1', to: 'bob', session: 'b1', ct: 'orphan-row' }, 1, 'purged-thread');
    s.openThread('t-out', 'bob', 'b1', 'alice', 'a2', 0);
    s.enqueue({ from: 'alice', fromSession: 'a2', to: 'bob', session: 'b1', ct: 'reply-to-out' }, 1, 'gone-too');
    s.deleteShare('bob', 'b1');
    expect(s.drain('bob', 'b1', 2).map((q) => q.outer.ct)).toEqual(['reply-to-out']);
  });
  it('re-queued envelopes keep their thread (D)', () => {
    const s = setup();
    s.setShare('bob', 'b1', ['alice'], 't');
    s.openThread('t-out', 'bob', 'b1', 'alice', 'a1', 0);
    s.enqueue({ from: 'alice', fromSession: 'a1', to: 'bob', session: 'b1', ct: 'r' }, 1, 't-out');
    const [q] = s.drain('bob', 'b1', 2);
    expect(q!.threadId).toBe('t-out');
    s.enqueue(q!.outer, q!.enqueuedAt, q!.threadId);
    s.deleteShare('bob', 'b1');
    expect(s.drain('bob', 'b1', 2).map((x) => x.outer.ct)).toEqual(['r']);
  });
  it('adds the thread column to a queue created by an older relay and keeps its rows (D)', () => {
    const dir = mkdtempSync(join(tmpdir(), 'relay-migrate-'));
    try {
      const path = join(dir, 'relay.db');
      const old = new Database(path);
      old.exec(`CREATE TABLE queue (id INTEGER PRIMARY KEY AUTOINCREMENT, recipient TEXT NOT NULL, sender TEXT NOT NULL,
        from_session TEXT NOT NULL, session TEXT NOT NULL, ct TEXT NOT NULL, enqueued_at INTEGER NOT NULL)`);
      old.prepare('INSERT INTO queue (recipient, sender, from_session, session, ct, enqueued_at) VALUES (?, ?, ?, ?, ?, ?)')
        .run('bob', 'alice', 'a1', 'b1', 'legacy', 1);
      old.close();
      const s = new Store(path);
      s.enqueue({ from: 'alice', fromSession: 'a1', to: 'bob', session: 'b1', ct: 'new' }, 2, 't1');
      expect(s.drain('bob', 'b1', 3)).toEqual([
        { outer: { from: 'alice', fromSession: 'a1', to: 'bob', session: 'b1', ct: 'legacy' }, enqueuedAt: 1 },
        { outer: { from: 'alice', fromSession: 'a1', to: 'bob', session: 'b1', ct: 'new' }, enqueuedAt: 2, threadId: 't1' },
      ]);
      s.close();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
  it('revoking an identity ends its threads', () => {
    const s = setup();
    s.openThread('t1', 'alice', 'a1', 'bob', 'b1', 0);
    s.revokeIdentity('alice');
    expect(s.touchThread('t1', 'alice', 'a1', 'bob', 'b1', 1)).toBe(false);
  });
  it('caps total lifetime at 7 days even when kept active', () => {
    const s = setup();
    s.openThread('t1', 'alice', 'a1', 'bob', 'b1', 0);
    for (let d = 1; d <= 7; d++) expect(s.touchThread('t1', 'alice', 'a1', 'bob', 'b1', d * DAY)).toBe(true);
    expect(s.touchThread('t1', 'alice', 'a1', 'bob', 'b1', 7 * DAY + 1)).toBe(false);
    s.openThread('t2', 'alice', 'a1', 'bob', 'b1', 0);
    for (let d = 1; d <= 7; d++) s.touchThread('t2', 'alice', 'a1', 'bob', 'b1', d * DAY);
    s.purgeExpired(7 * DAY + 1);
    expect(() => s.openThread('t2', 'carol', 'x', 'bob', 'b1', 7 * DAY + 2)).not.toThrow();
  });
});
