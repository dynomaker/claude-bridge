import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, statSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { generateKeypair } from '@claude-bridge/core';
import { createHttpHandler } from '../../relay/src/http.js';
import { Store } from '../../relay/src/store.js';
import { PinMismatchError, pinKey } from '../src/keystore.js';
import { cmdApprove, cmdClear, cmdInit, cmdList, cmdPause, cmdPin, cmdResume, cmdShare, cmdStatus, cmdUnshare, parseArgs } from '../src/cli.js';
import { sessionDir } from '../src/paths.js';
import { savePending } from '../src/pending.js';
import { TaskStore } from '../src/tasks.js';

let homes: string[] = [];
let closers: (() => void)[] = [];
const out: string[] = [];
const deps = { log: (l: string) => void out.push(l) };

beforeEach(() => {
  out.length = 0;
});
afterEach(() => {
  closers.splice(0).forEach((c) => c());
  homes.splice(0).forEach((h) => rmSync(h, { recursive: true, force: true }));
  delete process.env.BRIDGE_HOME;
});

const useHome = () => {
  const h = mkdtempSync(join(tmpdir(), 'bridge-cli-'));
  homes.push(h);
  process.env.BRIDGE_HOME = h;
  return h;
};
const A = (s: string) => parseArgs(s.split(' ').filter(Boolean));

describe('bridge cli', () => {
  it('init, share, list, unshare against a real relay', async () => {
    const store = new Store(':memory:');
    const server = createServer(createHttpHandler(store));
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    closers.push(() => server.close(), () => store.close());
    const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

    // bob registers with his own home, alice with hers
    useHome();
    await cmdInit(A(`${url} ${store.createInvite('bob')}`), deps);
    const aliceHome = useHome();
    await cmdInit(A(`${url} ${store.createInvite('alice')}`), deps);
    expect(out.some((l) => /^fingerprint [0-9a-f]{4}(-[0-9a-f]{4}){3}$/.test(l))).toBe(true);
    await expect(cmdInit(A(`${url} x`), deps)).rejects.toThrow(/already initialised/);

    out.length = 0;
    await cmdShare(parseArgs(['proj', 'bob', '--track', 'ship v1', '--scope', '/src']), deps);
    expect(out.some((l) => /^bob {2}[0-9a-f]{4}-/.test(l))).toBe(true);
    const sc = JSON.parse(readFileSync(join(sessionDir('proj'), 'config.json'), 'utf8'));
    expect(sc).toEqual({ session: 'proj', allow: ['bob'], track: 'ship v1', scope: '/src' });
    expect(sc).not.toHaveProperty('threshold');
    expect(store.listShares('alice')).toEqual([{ session: 'proj', allow: ['bob'], track: 'ship v1' }]);

    await cmdShare(parseArgs(['proj', 'bob', '--track', 'ship v1', '--threshold', '0.45']), deps);
    expect(JSON.parse(readFileSync(join(sessionDir('proj'), 'config.json'), 'utf8'))).toMatchObject({ threshold: 0.45 });

    out.length = 0;
    await cmdList(A(''), deps);
    expect(out.join('\n')).toContain('proj');
    expect(out.filter((l) => l.includes('proj')).length).toBe(2);

    await cmdUnshare(A('proj'), deps);
    expect(store.listShares('alice')).toEqual([]);
    expect(existsSync(join(aliceHome, 'sessions', 'proj', 'config.json'))).toBe(false);
  });

  it('control files', async () => {
    useHome();
    await cmdApprove(A('t1 --session proj'), { ...deps, now: () => 42 });
    expect(JSON.parse(readFileSync(join(sessionDir('proj'), 'control', 'approve-t1.json'), 'utf8'))).toEqual({
      op: 'approve',
      taskId: 't1',
      ts: 42,
    });
    await cmdPause(A('proj'), deps);
    expect(existsSync(join(sessionDir('proj'), 'control', 'pause'))).toBe(true);
    expect(statSync(join(sessionDir('proj'), 'control')).mode & 0o777).toBe(0o700);
    await cmdResume(A('proj'), deps);
    expect(existsSync(join(sessionDir('proj'), 'control', 'pause'))).toBe(false);
    await expect(cmdApprove(A('../x --session proj'), deps)).rejects.toThrow(/invalid task id/);
    await expect(cmdPause(A('../x'), deps)).rejects.toThrow(/invalid session name/);
    await expect(cmdPin(A('bob'), deps)).rejects.toThrow(/usage/);
    // --threshold is optional with no built-in value of its own (session config, else policy.yaml, else 0.3).
    const usage = await cmdShare(A('proj'), deps).catch((e: Error) => e.message);
    expect(usage).toContain('[--threshold <0-1>]');
    expect(usage).not.toContain('0.3');
  });

  it('rejects an unsafe session name before any relay call', async () => {
    useHome();
    const f = vi.fn();
    await expect(cmdShare(parseArgs(['../x', 'bob', '--track', 't']), { ...deps, fetch: f })).rejects.toThrow(/invalid session name/);
    await expect(cmdUnshare(A('../x'), { ...deps, fetch: f })).rejects.toThrow(/invalid session name/);
    expect(f).not.toHaveBeenCalled();
  });

  it('aborts share on pin mismatch: no putShare, no session config', async () => {
    const store = new Store(':memory:');
    const server = createServer(createHttpHandler(store));
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    closers.push(() => server.close(), () => store.close());
    const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    useHome();
    await cmdInit(A(`${url} ${store.createInvite('bob')}`), deps);
    const aliceHome = useHome();
    await cmdInit(A(`${url} ${store.createInvite('alice')}`), deps);
    const other = generateKeypair();
    pinKey('bob', other.signPub, other.boxPub);

    await expect(cmdShare(parseArgs(['proj', 'bob', '--track', 't']), deps)).rejects.toBeInstanceOf(PinMismatchError);
    expect(store.listShares('alice')).toEqual([]);
    expect(existsSync(join(aliceHome, 'sessions', 'proj', 'config.json'))).toBe(false);
  });
  it('init warns about plain http to a remote relay and keeps the keys on disk before redeeming the invite', async () => {
    const h = useHome();
    const f = vi.fn(async () => new Response(JSON.stringify({ error: 'invalid or used invite' }), { status: 400 }));
    await expect(cmdInit(A('http://relay.example.com x'), { ...deps, fetch: f as unknown as typeof fetch })).rejects.toThrow();
    expect(out.some((l) => /warning: .*plain http/.test(l))).toBe(true);
    expect(JSON.parse(readFileSync(join(h, 'config.pending.json'), 'utf8')).keys).toBeDefined();
    out.length = 0;
    await expect(cmdInit(A('http://127.0.0.1:9 x'), { ...deps, fetch: f as unknown as typeof fetch })).rejects.toThrow();
    expect(out.some((l) => /warning/.test(l))).toBe(false);

    // An unwritable home fails before the invite is sent.
    const file = join(h, 'not-a-dir');
    writeFileSync(file, '');
    process.env.BRIDGE_HOME = join(file, 'home');
    f.mockClear();
    await expect(cmdInit(A('https://relay.example.com x'), { ...deps, fetch: f as unknown as typeof fetch })).rejects.toThrow();
    expect(f).not.toHaveBeenCalled();
  });

  it('status lists every session with its marker, held and queued counts, without peer text', async () => {
    const h = useHome();
    mkdirSync(join(h, 'sessions', 'front'), { recursive: true });
    writeFileSync(join(h, 'sessions', 'front', 'config.json'), JSON.stringify({ session: 'front', allow: ['alice'], track: 't' }));
    const s = new TaskStore('front');
    s.add({ taskId: 'a'.repeat(32), threadId: 'a'.repeat(32), from: 'alice', body: 'SECRET TASK TEXT', status: 'running', ts: 1, role: 'receiver' });
    s.add({ taskId: 'b'.repeat(32), threadId: 'b'.repeat(32), from: 'alice', body: 'x', status: 'queued', ts: 2, role: 'receiver' });
    s.setActive({ taskId: 'a'.repeat(32), threadId: 'a'.repeat(32), role: 'receiver', task: 'SECRET TASK TEXT', from: 'alice/a1', track: 't', threshold: 0.3, approved: false, ts: 1 });
    savePending('front', { taskId: 'a'.repeat(32), kind: 'message', seq: 2, from: 'alice/a1', body: 'SECRET HELD', state: 'held', ts: 3 });
    const tmp = 'tmp-0123456789abcdef';
    mkdirSync(join(h, 'sessions', tmp), { recursive: true });
    const dead = spawnSync(process.execPath, ['-e', '']).pid;
    writeFileSync(join(h, 'sessions', tmp, 'active.json'), JSON.stringify({ taskId: 'c'.repeat(32), threadId: 'c'.repeat(32), role: 'sender', task: 'x', from: 'bob/front', track: 't', threshold: 0.3, approved: false, ts: 1, pid: dead }));

    await cmdStatus(A(''), deps);
    const text = out.join('\n');
    expect(text).toContain('front  (shared with [alice])');
    expect(text).toContain(`receiver task ${'a'.repeat(32)} from alice/a1`);
    expect(text).toContain('held: 1  queued: 0 turn(s), 1 task(s)');
    expect(text).toContain(`${tmp}  (send-only)`);
    expect(text).toContain(`[stale: Claude Code process ${dead} is gone]`);
    expect(text).not.toContain('SECRET');
  });

  it('status shows a held result marker as held, not expired (C)', async () => {
    const h = useHome();
    mkdirSync(join(h, 'sessions', 'desk'), { recursive: true });
    const m = { taskId: 'd'.repeat(32), threadId: 'd'.repeat(32), role: 'sender', task: 'x', from: 'bob/front', track: 't', threshold: 0.3, approved: false, ts: 10, expiresAt: 20, pid: process.pid };
    writeFileSync(join(h, 'sessions', 'desk', 'active.json'), JSON.stringify(m));
    await cmdStatus(A(''), deps);
    expect(out.join('\n')).toContain('[expired]');
    out.length = 0;
    writeFileSync(join(h, 'sessions', 'desk', 'held-events.jsonl'), JSON.stringify({ taskId: m.taskId, reason: 'r', ts: 11 }) + '\n');
    await cmdStatus(A(''), deps);
    expect(out.join('\n')).not.toContain('[expired]');
    expect(out.join('\n')).toContain('[held: waits for the owner]');
  });

  it('clear removes a marker after printing it, only from a terminal outside Claude Code', async () => {
    const h = useHome();
    const path = join(h, 'sessions', 'front', 'active.json');
    mkdirSync(join(h, 'sessions', 'front'), { recursive: true });
    writeFileSync(path, JSON.stringify({ taskId: 'a'.repeat(32), role: 'receiver' }));
    const tty = { ...deps, isTTY: true, env: {} };
    await expect(cmdClear(A('--session front'), { ...deps, isTTY: true, env: { CLAUDECODE: '1' } })).rejects.toThrow(/separate terminal/);
    await expect(cmdClear(A('--session front'), { ...deps, isTTY: false, env: {} })).rejects.toThrow(/separate terminal/);
    expect(existsSync(path)).toBe(true);
    await expect(cmdClear(A(''), tty)).rejects.toThrow(/usage/);
    await expect(cmdClear(A('--session ../x'), tty)).rejects.toThrow(/invalid session name/);
    await cmdClear(A('--session front'), tty);
    expect(existsSync(path)).toBe(false);
    expect(out.join('\n')).toContain('a'.repeat(32));
    out.length = 0;
    await cmdClear(A('--session front'), tty);
    expect(out).toEqual(['no active marker in session front']);
  });
});
