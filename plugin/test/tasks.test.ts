import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { audit } from '../src/audit.js';
import { TaskStore } from '../src/tasks.js';
import type { ActiveRec, TaskRec } from '../src/tasks.js';

let home: string;
beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'bridge-tasks-'));
  process.env.BRIDGE_HOME = home;
});
afterEach(() => {
  delete process.env.BRIDGE_HOME;
  rmSync(home, { recursive: true, force: true });
});

const rec = (taskId: string, ts: number, status: TaskRec['status'] = 'queued'): TaskRec => ({ taskId, threadId: 'th1', from: 'alice', body: 'b', status, ts });
const act: ActiveRec = { taskId: 't1', threadId: 'th1', role: 'receiver', task: 'x', from: 'alice', track: 'tr', threshold: 0.3, approved: false, ts: 1 };

describe('TaskStore', () => {
  it('seen is true after add, false before', () => {
    const s = new TaskStore('s1');
    expect(s.seen('t1')).toBe(false);
    s.add(rec('t1', 1));
    expect(s.seen('t1')).toBe(true);
    expect(new TaskStore('s2').seen('t1')).toBe(false);
  });
  it('rejects duplicate and unsafe ids', () => {
    const s = new TaskStore('s1');
    s.add(rec('t1', 1));
    expect(() => s.add(rec('t1', 2))).toThrow();
    expect(() => s.add(rec('../x', 2))).toThrow();
    expect(() => s.get('__proto__')).toThrow();
  });
  it('nextQueued is FIFO and skips non-queued', () => {
    const s = new TaskStore('s1');
    s.add(rec('a', 5, 'held'));
    s.add(rec('b', 2));
    s.add(rec('c', 1));
    s.add(rec('d', 1));
    expect(s.nextQueued()?.taskId).toBe('c');
    s.setStatus('c', 'running');
    expect(s.nextQueued()?.taskId).toBe('d');
  });
  it('setStatus stores reason and throws for unknown task', () => {
    const s = new TaskStore('s1');
    s.add(rec('t1', 1));
    s.setStatus('t1', 'held', 'why');
    expect(s.get('t1')).toMatchObject({ status: 'held', reason: 'why' });
    expect(() => s.setStatus('nope', 'done')).toThrow();
  });
  it('tracks lastSeq per thread', () => {
    const s = new TaskStore('s1');
    expect(s.lastSeq('th1')).toBe(0);
    s.setLastSeq('th1', 4);
    expect(s.lastSeq('th1')).toBe(4);
    expect(s.lastSeq('th2')).toBe(0);
    expect(() => s.setLastSeq('th1', -1)).toThrow();
  });
  it('active round-trips, clears, and throws on corruption; files are 0600', () => {
    const s = new TaskStore('s1');
    expect(s.active()).toBeUndefined();
    s.setActive({ ...act, scope: '/p' });
    expect(s.active()).toMatchObject({ taskId: 't1', scope: '/p', role: 'receiver' });
    expect(statSync(join(home, 'sessions', 's1', 'active.json')).mode & 0o777).toBe(0o600);
    s.clearActive();
    expect(s.active()).toBeUndefined();
    s.setActive(act);
    s.add(rec('t1', 1));
    expect(statSync(join(home, 'sessions', 's1', 'tasks.json')).mode & 0o777).toBe(0o600);
  });
  it('stamps markers with the parent (Claude Code) pid, not the server pid (A)', () => {
    const s = new TaskStore('s1');
    s.setActive(act);
    expect(s.activeRaw()?.pid).toBe(process.ppid);
    expect(new TaskStore('s2', Date.now, () => 4242).owner()).toBe(4242);
  });
  it('refuses to write a marker without a usable parent process (A)', () => {
    for (const pid of [1, undefined]) {
      const s = new TaskStore('s1', Date.now, () => pid);
      expect(s.hasOwner()).toBe(false);
      expect(() => s.setActive(act)).toThrow(/parent Claude Code process/);
      expect(s.activeRaw()).toBeUndefined();
    }
  });
  it('an expired marker stays live while the hook holds it (C)', () => {
    let now = 1000;
    const s = new TaskStore('s1', () => now);
    s.setActive({ ...act, role: 'sender', ts: 1000, expiresAt: 2000 });
    now = 3000;
    expect(s.active()).toBeUndefined();
    writeFileSync(join(home, 'sessions', 's1', 'held-events.jsonl'), JSON.stringify({ taskId: 't1', reason: 'r', ts: 1500 }) + '\n');
    expect(s.active()).toMatchObject({ taskId: 't1' });
    expect(s.held(s.activeRaw()!)).toBe(true);
    // A hold from before the marker was written does not count.
    writeFileSync(join(home, 'sessions', 's1', 'held-events.jsonl'), JSON.stringify({ taskId: 't1', reason: 'r', ts: 999 }) + '\n');
    expect(s.active()).toBeUndefined();
  });
});

describe('audit', () => {
  it('appends JSONL to audit.log with mode 0600', () => {
    audit('e1', { a: 1 });
    audit('e2', { b: 2 });
    const lines = readFileSync(join(home, 'audit.log'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    expect(lines.map((l) => l.event)).toEqual(['e1', 'e2']);
    expect(lines[0].a).toBe(1);
    expect(statSync(join(home, 'audit.log')).mode & 0o777).toBe(0o600);
  });
});
