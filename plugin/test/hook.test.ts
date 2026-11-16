import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { launchHook } from '../src/hook-launch.js';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { runHook } from '../src/hook.js';
import { TaskStore } from '../src/tasks.js';
import type { ActiveRec } from '../src/tasks.js';

let home: string;
let proj: string;
const env = { BRIDGE_SESSION: 's1' } as NodeJS.ProcessEnv;
beforeEach(() => {
  vi.clearAllMocks();
  home = mkdtempSync(join(tmpdir(), 'bridge-hook-'));
  proj = mkdtempSync(join(tmpdir(), 'bridge-proj-'));
  process.env.BRIDGE_HOME = home;
});
afterEach(() => {
  delete process.env.BRIDGE_HOME;
  rmSync(home, { recursive: true, force: true });
  rmSync(proj, { recursive: true, force: true });
});

const active = (o: Partial<ActiveRec> = {}): ActiveRec => ({ taskId: 't1', threadId: 'th1', role: 'receiver', task: 'fix parser', from: 'alice', track: 'parser', threshold: 0.3, approved: false, ts: 1, ...o });
const setup = (o: Partial<ActiveRec> = {}) => {
  const s = new TaskStore('s1');
  s.add({ taskId: 't1', threadId: 'th1', from: 'alice', body: 'b', status: 'running', ts: 1 });
  s.setActive(active(o));
  return s;
};
const call = (tool_name: string, tool_input: unknown) => JSON.stringify({ tool_name, tool_input, cwd: proj });
const bash = (command: string) => call('Bash', { command });
const ok = vi.fn(async () => ({ risk: 0, reason: 'fine' }));
const boom = vi.fn(async () => { throw new Error('down'); });
const auditLines = () => readFileSync(join(home, 'audit.log'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
const heldEvents = () => readFileSync(join(home, 'sessions', 's1', 'held-events.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
const decision = (out: string) => JSON.parse(out).hookSpecificOutput;
/** A pid that belonged to a process which has exited and been reaped. */
const deadPid = () => spawnSync(process.execPath, ['-e', '']).pid!;
/** Write a marker file directly (setActive would stamp this process's live pid). */
const rawMarker = (session: string, o: Partial<ActiveRec>) => {
  mkdirSync(join(home, 'sessions', session), { recursive: true });
  writeFileSync(join(home, 'sessions', session, 'active.json'), JSON.stringify(active(o)));
};

describe('runHook', () => {
  it('outputs nothing without an active task or without a session', async () => {
    expect(await runHook(bash('ls'), env, { classify: boom })).toBe('');
    expect(await runHook(bash('ls'), {}, { classify: boom })).toBe('');
    setup();
    expect(await runHook(bash('git push --force'), {}, { classify: boom })).toBe('');
  });

  it('denies git push --force, records held event and audit, leaves tasks.json to the server', async () => {
    const s = setup();
    const out = decision(await runHook(bash('git push --force origin x'), env, { classify: ok }));
    expect(out).toMatchObject({ hookEventName: 'PreToolUse', permissionDecision: 'deny' });
    expect(out.permissionDecisionReason).toMatch(/^claude-bridge: .*bridge_reply/);
    expect(s.get('t1')?.status).toBe('running');
    const held = readFileSync(join(home, 'sessions', 's1', 'held-events.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    expect(held).toHaveLength(1);
    expect(held[0]).toMatchObject({ taskId: 't1' });
    expect(auditLines().at(-1)).toMatchObject({ event: 'tool-deny', taskId: 't1', tool: 'Bash' });
  });

  it('denies bridge approve even when approved', async () => {
    setup({ approved: true });
    const out = decision(await runHook(bash('bridge approve x'), env, { classify: ok }));
    expect(out.permissionDecision).toBe('deny');
    expect(ok).not.toHaveBeenCalled();
  });

  it('approved + harmless Bash allows without consulting the classifier', async () => {
    setup({ approved: true });
    expect(await runHook(bash('ls'), env, { classify: boom })).toBe('');
    expect(boom).not.toHaveBeenCalled();
    expect(auditLines().at(-1)).toMatchObject({ event: 'tool-allow', taskId: 't1' });
  });

  it('unapproved: classifier decides; throwing classifier denies', async () => {
    const s = setup();
    expect(await runHook(bash('ls'), env, { classify: ok })).toBe('');
    expect(s.get('t1')?.status).toBe('running');
    expect(decision(await runHook(bash('ls'), env, { classify: boom })).permissionDecision).toBe('deny');
    expect(s.get('t1')?.status).toBe('running');
  });

  it('writes an audit line per decision', async () => {
    setup();
    await runHook(bash('ls'), env, { classify: ok });
    await runHook(bash('rm -rf /'), env, { classify: ok });
    expect(auditLines().map((l) => l.event)).toEqual(['tool-allow', 'tool-deny']);
  });

  it('treats sender role like receiver', async () => {
    setup({ role: 'sender' });
    expect(decision(await runHook(bash('git push --force'), env, { classify: ok })).permissionDecision).toBe('deny');
  });

  it('applies per-session scope from the active record', async () => {
    setup({ scope: join(proj, 'sub') });
    const out = await runHook(call('Write', { file_path: join(proj, 'other.txt'), content: 'x' }), env, { classify: ok });
    expect(decision(out).permissionDecision).toBe('deny');
    expect(decision(out).permissionDecisionReason).toMatch(/write-outside-scope/);
  });

  it('applies policy.yaml extraDeny', async () => {
    setup({ approved: true });
    writeFileSync(join(home, 'policy.yaml'), 'extraDeny:\n  - "forbidden-word"\n');
    const out = await runHook(bash('echo forbidden-word'), env, { classify: ok });
    expect(decision(out).permissionDecisionReason).toMatch(/extra-deny/);
  });

  it('fails closed on corrupt active.json and appends an "unknown" held event', async () => {
    setup();
    writeFileSync(join(home, 'sessions', 's1', 'active.json'), '{nope');
    expect(decision(await runHook(bash('ls'), env, { classify: ok })).permissionDecision).toBe('deny');
    expect(heldEvents().at(-1)).toMatchObject({ taskId: 'unknown' });
  });

  it('ignores BRIDGE_DISABLE while an active marker exists', async () => {
    setup();
    const out = await runHook(bash('git push --force'), { ...env, BRIDGE_DISABLE: '1' }, { classify: ok });
    expect(decision(out).permissionDecision).toBe('deny');
    expect(await runHook(bash('ls'), { ...env, BRIDGE_SESSION: 'idle', BRIDGE_DISABLE: '1' }, { classify: boom })).toBe('');
  });

  it('once held, denies everything except bridge_reply/bridge_message without calling the classifier for the rest', async () => {
    setup();
    await runHook(bash('git push --force'), env, { classify: ok });
    vi.clearAllMocks();
    const out = decision(await runHook(bash('ls'), env, { classify: ok }));
    expect(out.permissionDecision).toBe('deny');
    expect(out.permissionDecisionReason).toMatch(/held/);
    expect(decision(await runHook(call('Read', { file_path: join(proj, 'a') }), env, { classify: ok })).permissionDecision).toBe('deny');
    expect(ok).not.toHaveBeenCalled();
    expect(heldEvents()).toHaveLength(1);
    expect(await runHook(call('mcp__bridge__bridge_reply', { text: 'hi' }), env, { classify: ok })).toBe('');
    expect(await runHook(call('mcp__bridge__bridge_message', { text: 'hi' }), env, { classify: ok })).toBe('');
    expect(await runHook(call('mcp__plugin_bridge_bridge__bridge_reply', { text: 'hi' }), env, { classify: ok })).toBe('');
    expect(ok).toHaveBeenCalledTimes(3);
    const bad = decision(await runHook(call('mcp__bridge__bridge_reply', { text: 'DROP TABLE users' }), env, { classify: ok }));
    expect(bad.permissionDecision).toBe('deny');
  });

  it('a held event for another task does not hold this one', async () => {
    setup();
    mkdirSync(join(home, 'sessions', 's1'), { recursive: true });
    writeFileSync(join(home, 'sessions', 's1', 'held-events.jsonl'), '{"taskId":"other","reason":"x"}\n');
    expect(await runHook(bash('ls'), env, { classify: ok })).toBe('');
  });

  it('a held event older than active.ts does not hold; a newer one does', async () => {
    setup({ ts: 10 });
    mkdirSync(join(home, 'sessions', 's1'), { recursive: true });
    const f = join(home, 'sessions', 's1', 'held-events.jsonl');
    writeFileSync(f, '{"taskId":"t1","reason":"old","ts":5}\n');
    expect(await runHook(bash('ls'), env, { classify: ok })).toBe('');
    writeFileSync(f, '{"taskId":"t1","reason":"old","ts":5}\n{"taskId":"t1","reason":"new","ts":10}\n');
    expect(decision(await runHook(bash('ls'), env, { classify: ok })).permissionDecisionReason).toMatch(/held/);
  });

  it('ignores malformed earlier held-event lines but fails closed on a malformed final line', async () => {
    setup({ ts: 10 });
    mkdirSync(join(home, 'sessions', 's1'), { recursive: true });
    const f = join(home, 'sessions', 's1', 'held-events.jsonl');
    writeFileSync(f, 'garbage\n{"taskId":"t1","reason":"old","ts":5}\n');
    expect(await runHook(bash('ls'), env, { classify: ok })).toBe('');
    writeFileSync(f, '{"taskId":"t1","reason":"old","ts":5}\n{"taskId":"t1","rea');
    expect(decision(await runHook(bash('ls'), env, { classify: ok })).permissionDecisionReason).toMatch(/held/);
  });

  describe('send-only (tmp-*) sessions without BRIDGE_SESSION', () => {
    const TMP = 'tmp-0123456789abcdef';
    const tmpMarker = (o: Partial<ActiveRec> = {}) => {
      const s = new TaskStore(TMP);
      s.add({ taskId: 't1', threadId: 't1', from: 'me', body: 'b', status: 'running', ts: 1, role: 'sender', peer: 'bob/front' });
      s.setActive(active({ role: 'sender', cwd: proj, ...o }));
    };

    it('gates tool calls in the matching cwd only', async () => {
      tmpMarker();
      expect(decision(await runHook(bash('git push --force'), {}, { classify: ok })).permissionDecision).toBe('deny');
      expect(readFileSync(join(home, 'sessions', TMP, 'held-events.jsonl'), 'utf8')).toContain('"t1"');
      const elsewhere = JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'git push --force' }, cwd: home });
      expect(await runHook(elsewhere, {}, { classify: ok })).toBe('');
    });

    it('also gates from a subdirectory of the marker cwd, but not from a sibling with a common prefix', async () => {
      tmpMarker();
      const at = (cwd: string) => JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'git push --force' }, cwd });
      expect(decision(await runHook(at(join(proj, 'src', 'deep')), {}, { classify: ok })).permissionDecision).toBe('deny');
      expect(await runHook(at(`${proj}-sibling`), {}, { classify: ok })).toBe('');
      expect(await runHook(at(join(proj, '..')), {}, { classify: ok })).toBe('');
    });

    it('fails closed when a tmp marker is unreadable or the input has no cwd', async () => {
      tmpMarker();
      expect(decision(await runHook('not json', {}, { classify: ok })).permissionDecision).toBe('deny');
      writeFileSync(join(home, 'sessions', TMP, 'active.json'), '{broken');
      const elsewhere = JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'ls' }, cwd: home });
      expect(decision(await runHook(elsewhere, {}, { classify: ok })).permissionDecision).toBe('deny');
    });

    it('the launcher denies on failure while any tmp marker exists', async () => {
      let out = '';
      const failing = async () => { throw new Error('cannot import'); };
      await launchHook({ readStdin: () => '{}', importHook: failing, env: { BRIDGE_HOME: home }, write: (x) => (out += x) });
      expect(out).toBe('');
      tmpMarker();
      await launchHook({ readStdin: () => '{}', importHook: failing, env: { BRIDGE_HOME: home }, write: (x) => (out += x) });
      expect(out).toContain('deny');
    });
  });

  describe('stale markers', () => {
    it('a marker stamped by setActive names this process\'s parent (Claude Code), so the server dying does not lift it (A)', async () => {
      setup();
      expect(JSON.parse(readFileSync(join(home, 'sessions', 's1', 'active.json'), 'utf8')).pid).toBe(process.ppid);
    });

    it('treats a marker whose Claude Code process is gone as absent (hook and launcher)', async () => {
      rawMarker('s1', { pid: deadPid() });
      expect(await runHook(bash('git push --force'), env, { classify: boom })).toBe('');
      let out = '';
      await launchHook({ readStdin: () => '{}', importHook: async () => { throw new Error('x'); }, env: { ...env, BRIDGE_HOME: home }, write: (x) => (out += x) });
      expect(out).toBe('');
      rawMarker('s1', { pid: process.pid });
      expect(decision(await runHook(bash('git push --force'), env, { classify: boom })).permissionDecision).toBe('deny');
    });

    it('treats an expired marker as absent, a not-yet-expired one as live', async () => {
      rawMarker('s1', { role: 'sender', pid: process.pid, expiresAt: Date.now() - 1 });
      expect(await runHook(bash('git push --force'), env, { classify: boom })).toBe('');
      rawMarker('s1', { role: 'sender', pid: process.pid, expiresAt: Date.now() + 60_000 });
      expect(decision(await runHook(bash('git push --force'), env, { classify: boom })).permissionDecision).toBe('deny');
    });

    it('a held marker never expires: hook, tmp lookup and launcher keep honouring it (C)', async () => {
      const heldLine = (session: string, ts: number) => {
        mkdirSync(join(home, 'sessions', session), { recursive: true });
        writeFileSync(join(home, 'sessions', session, 'held-events.jsonl'), JSON.stringify({ taskId: 't1', reason: 'r', ts }) + '\n');
      };
      rawMarker('s1', { role: 'sender', pid: process.pid, ts: 10, expiresAt: Date.now() - 1 });
      heldLine('s1', 11);
      expect(decision(await runHook(bash('ls'), env, { classify: ok })).permissionDecision).toBe('deny');
      let out = '';
      await launchHook({ readStdin: () => '{}', importHook: async () => { throw new Error('x'); }, env: { ...env, BRIDGE_HOME: home }, write: (x) => (out += x) });
      expect(out).toContain('deny');

      const at = JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'ls' }, cwd: proj });
      rawMarker('tmp-0123456789abcdef', { role: 'sender', cwd: proj, ts: 10, expiresAt: 1 });
      heldLine('tmp-0123456789abcdef', 12);
      expect(decision(await runHook(at, {}, { classify: ok })).permissionDecision).toBe('deny');
      out = '';
      await launchHook({ readStdin: () => '{}', importHook: async () => { throw new Error('x'); }, env: { BRIDGE_HOME: home }, write: (x) => (out += x) });
      expect(out).toContain('deny');
    });

    it('a deny under a result marker does not suggest messaging the finished thread', async () => {
      rawMarker('s1', { role: 'sender', pid: process.pid, expiresAt: Date.now() + 60_000 });
      const reason = decision(await runHook(bash('git push --force'), env, { classify: boom })).permissionDecisionReason as string;
      expect(reason).not.toMatch(/bridge_message|bridge_reply/);
      expect(reason).toMatch(/session owner/);
    });

    it('ignores a stale tmp-* marker for send-only processes', async () => {
      const at = JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'git push --force' }, cwd: proj });
      rawMarker('tmp-0123456789abcdef', { role: 'sender', cwd: proj, pid: deadPid() });
      expect(await runHook(at, {}, { classify: boom })).toBe('');
      rawMarker('tmp-0123456789abcdef', { role: 'sender', cwd: proj, expiresAt: 1 });
      expect(await runHook(at, {}, { classify: boom })).toBe('');
    });
  });

  describe('held peer content', () => {
    const heldDir = () => join(home, 'sessions', 'front', 'held');
    beforeEach(() => {
      mkdirSync(heldDir(), { recursive: true });
      writeFileSync(join(heldDir(), 'x-1.json'), '{}');
    });

    it('denies reads and searches of held/ in any session, with no active marker', async () => {
      for (const input of [
        call('Read', { file_path: join(heldDir(), 'x-1.json') }),
        call('Grep', { pattern: 'secret', path: heldDir() }),
        call('Grep', { pattern: 'secret', path: home }),
        call('Glob', { pattern: '**/*.json', path: join(home, 'sessions') }),
        bash(`cat ${join(home, 'sessions', 'front', 'held', 'x-1.json')}`),
        bash(`cat ${home}/sessions/*/held/*`),
      ]) {
        for (const e of [env, {}]) {
          const out = decision(await runHook(input, e, { classify: boom }));
          expect(out.permissionDecision).toBe('deny');
          expect(out.permissionDecisionReason).toMatch(/held peer content/);
        }
      }
    });

    it('leaves other bridge files and ordinary calls alone when no task is active', async () => {
      expect(await runHook(call('Read', { file_path: join(home, 'sessions', 'front', 'tasks.json') }), env, { classify: boom })).toBe('');
      expect(await runHook(call('Grep', { pattern: 'x', path: proj }), env, { classify: boom })).toBe('');
      expect(await runHook(bash('ls held'), env, { classify: boom })).toBe('');
    });
  });

  it('held events carry a ts', async () => {
    setup();
    await runHook(bash('git push --force'), env, { classify: ok });
    expect(typeof heldEvents()[0].ts).toBe('number');
  });

  it('denies when the classifier never resolves (watchdog)', async () => {
    setup();
    vi.useFakeTimers();
    try {
      const p = runHook(bash('ls'), env, { classify: () => new Promise(() => {}) });
      await vi.advanceTimersByTimeAsync(24_000);
      const out = decision(await p);
      expect(out.permissionDecision).toBe('deny');
      expect(out.permissionDecisionReason).toMatch(/watchdog/);
    } finally {
      vi.useRealTimers();
    }
  });

  it('denies writes to Claude config while active (approved)', async () => {
    setup({ approved: true, scope: proj });
    const out = await runHook(call('Write', { file_path: join(proj, '.claude', 'settings.json'), content: '{}' }), env, { classify: ok });
    expect(decision(out).permissionDecisionReason).toMatch(/claude-settings/);
  });

  it('fails closed on a schema-invalid active.json', async () => {
    mkdirSync(join(home, 'sessions', 's1'), { recursive: true });
    writeFileSync(join(home, 'sessions', 's1', 'active.json'), '{"taskId":"t1"}');
    expect(decision(await runHook(bash('ls'), env, { classify: ok })).permissionDecision).toBe('deny');
  });

  it('fails closed when policy.yaml is broken', async () => {
    setup({ approved: true });
    writeFileSync(join(home, 'policy.yaml'), 'extraDeny: [ "(" ]\n');
    expect(decision(await runHook(bash('ls'), env, { classify: ok })).permissionDecision).toBe('deny');
  });

  it('fails closed on malformed stdin while active, even without a task record', async () => {
    const s = new TaskStore('s1');
    s.setActive(active());
    expect(decision(await runHook('not json', env, { classify: ok })).permissionDecision).toBe('deny');
    expect(decision(await runHook('{}', env, { classify: ok })).permissionDecision).toBe('deny');
  });

  it('fails closed on an invalid session name', async () => {
    expect(decision(await runHook(bash('ls'), { BRIDGE_SESSION: '../x' }, { classify: ok })).permissionDecision).toBe('deny');
  });
});

describe('hooks.json command', () => {
  const command = () => JSON.parse(readFileSync(join(__dirname, '..', 'hooks', 'hooks.json'), 'utf8')).hooks.PreToolUse[0].hooks[0].command as string;

  it('on an unbuilt plugin blocks (exit 2) only while a marker exists for the session, else allows', () => {
    const root = mkdtempSync(join(tmpdir(), 'bridge-unbuilt-'));
    const run = (e: NodeJS.ProcessEnv) => {
      const base = { ...process.env, CLAUDE_PLUGIN_ROOT: root, BRIDGE_HOME: home };
      delete base.BRIDGE_SESSION;
      return spawnSync('bash', ['-c', command()], { env: { ...base, ...e }, input: '{}', encoding: 'utf8' });
    };
    try {
      // Nothing marked: the owner's own sessions keep working.
      expect(run({ BRIDGE_SESSION: 's1' })).toMatchObject({ status: 0, stdout: '' });
      expect(run({})).toMatchObject({ status: 0, stdout: '' });
      rawMarker('s1', {});
      const r = run({ BRIDGE_SESSION: 's1' });
      expect(r.status).toBe(2);
      expect(r.stderr).toMatch(/could not start/);
      expect(run({ BRIDGE_SESSION: 's2' }).status).toBe(0);
      // Without BRIDGE_SESSION any send-only (tmp-*) marker blocks, as in the launcher.
      expect(run({}).status).toBe(0);
      rawMarker('tmp-0123456789abcdef', { role: 'sender' });
      expect(run({}).status).toBe(2);
      // An unsafe session name cannot be checked: deny.
      expect(run({ BRIDGE_SESSION: '../x' }).status).toBe(2);
      // Default state dir when BRIDGE_HOME is unset.
      const fakeHome = mkdtempSync(join(tmpdir(), 'bridge-fake-home-'));
      try {
        const env = { ...process.env, CLAUDE_PLUGIN_ROOT: root, HOME: fakeHome, BRIDGE_SESSION: 'front' };
        delete env.BRIDGE_HOME;
        expect(spawnSync('bash', ['-c', command()], { env, input: '{}', encoding: 'utf8' }).status).toBe(0);
        mkdirSync(join(fakeHome, '.claude', 'channels', 'bridge', 'sessions', 'front'), { recursive: true });
        writeFileSync(join(fakeHome, '.claude', 'channels', 'bridge', 'sessions', 'front', 'active.json'), '{}');
        expect(spawnSync('bash', ['-c', command()], { env, input: '{}', encoding: 'utf8' }).status).toBe(2);
      } finally {
        rmSync(fakeHome, { recursive: true, force: true });
      }
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it('stays silent with exit 0 when the hook runs and no task is active', () => {
    const root = mkdtempSync(join(tmpdir(), 'bridge-fake-root-'));
    try {
      mkdirSync(join(root, 'dist'));
      writeFileSync(join(root, 'dist', 'hook-main.js'), 'process.exit(0)');
      const r = spawnSync('bash', ['-c', command()], { env: { ...process.env, CLAUDE_PLUGIN_ROOT: root }, input: '{}', encoding: 'utf8' });
      expect(r.status).toBe(0);
      expect(r.stdout).toBe('');
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

describe('launchHook (fail-safe launcher)', () => {
  const run = async (e: NodeJS.ProcessEnv, importHook: () => Promise<any>, readStdin = () => '{}') => {
    let out = '';
    await launchHook({ readStdin, importHook, env: { ...e, BRIDGE_HOME: home }, write: (s) => (out += s) });
    return out;
  };
  const failing = async () => { throw new Error('cannot import'); };

  it('passes through runHook output', async () => {
    expect(await run(env, async () => ({ runHook: async () => 'X' }))).toBe('X\n');
  });
  it('denies on import failure when an active marker exists', async () => {
    setup();
    const out = JSON.parse(await run(env, failing));
    expect(out.hookSpecificOutput).toMatchObject({ permissionDecision: 'deny', permissionDecisionReason: 'claude-bridge: hook failure' });
  });
  it('denies when runHook throws or stdin cannot be read while active', async () => {
    setup();
    expect(await run(env, async () => ({ runHook: async () => { throw new Error('x'); } }))).toContain('deny');
    expect(await run(env, async () => ({ runHook: async () => '' }), () => { throw new Error('eof'); })).toContain('deny');
  });
  it('stays silent on failure when there is no session or no active marker', async () => {
    expect(await run(env, failing)).toBe('');
    expect(await run({}, failing)).toBe('');
  });
  it('denies on failure for an unsafe or reserved session name', async () => {
    expect(await run({ BRIDGE_SESSION: '../x' }, failing)).toContain('deny');
    expect(await run({ BRIDGE_SESSION: '__proto__' }, failing)).toContain('deny');
    expect(await run({ BRIDGE_SESSION: 'constructor' }, failing)).toContain('deny');
  });
});
