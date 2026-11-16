#!/usr/bin/env node
import { existsSync, readdirSync, readFileSync, realpathSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fingerprint, generateKeypair, ready } from '@claude-bridge/core';
import { assertSafeName, bridgeHome, sessionDir } from './paths.js';
import { ensureDir, loadConfig, resetPin, resolvePeer, saveConfig, writeSecureFile } from './keystore.js';
import * as api from './relay-api.js';
import { listPending } from './pending.js';
import { markerLive, TaskStore } from './tasks.js';
import type { ActiveRec } from './tasks.js';

export type SessionConfig = { session: string; allow: string[]; track: string; scope?: string; threshold?: number };
export type CliDeps = {
  fetch?: api.Fetch;
  log?: (line: string) => void;
  now?: () => number;
  /** Overrides for `show`'s refusal checks (tests). */
  env?: NodeJS.ProcessEnv;
  isTTY?: boolean;
};

export type ParsedArgs = { positional: string[]; flags: Record<string, string | true> };

const BOOLEAN_FLAGS = new Set(['reset']);

export function parseArgs(argv: string[]): ParsedArgs {
  const positional: string[] = [];
  const flags: Record<string, string | true> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a.startsWith('--')) {
      const key = a.slice(2);
      if (BOOLEAN_FLAGS.has(key)) flags[key] = true;
      else {
        const v = argv[++i];
        if (v === undefined) throw new Error(`--${key} requires a value`);
        flags[key] = v;
      }
    } else positional.push(a);
  }
  return { positional, flags };
}

function need(args: ParsedArgs, n: number, usage: string): string[] {
  if (args.positional.length < n) throw new Error(`usage: bridge ${usage}`);
  return args.positional;
}

function flagStr(args: ParsedArgs, name: string): string | undefined {
  const v = args.flags[name];
  if (v === undefined) return undefined;
  if (v === true) throw new Error(`--${name} requires a value`);
  return v;
}

const lg = (d: CliDeps) => d.log ?? ((l: string) => console.log(l));

const sessionConfigPath = (session: string) => join(sessionDir(session), 'config.json');

export function readSessionConfig(session: string): SessionConfig | undefined {
  const p = sessionConfigPath(session);
  return existsSync(p) ? (JSON.parse(readFileSync(p, 'utf8')) as SessionConfig) : undefined;
}

export async function cmdInit(args: ParsedArgs, deps: CliDeps = {}): Promise<void> {
  const [relayUrl, invite] = need(args, 2, 'init <relayUrl> <invite>');
  if (!/^https?:\/\//.test(relayUrl!)) throw new Error('relayUrl must be an http(s) URL');
  if (existsSync(join(bridgeHome(), 'config.json'))) {
    throw new Error(`already initialised (${bridgeHome()}); refusing to overwrite existing keys`);
  }
  const host = new URL(relayUrl!).hostname;
  if (relayUrl!.startsWith('http://') && !['localhost', '127.0.0.1', '[::1]'].includes(host)) {
    lg(deps)(`warning: ${relayUrl} is plain http; use https for any relay that is not on this machine`);
  }
  await ready();
  const keys = generateKeypair();
  // Write the keys first: a disk failure must not burn the single-use invite.
  const pending = join(bridgeHome(), 'config.pending.json');
  writeSecureFile(pending, JSON.stringify({ relayUrl: relayUrl!, keys }, null, 2));
  const ident = await api.register(relayUrl!, invite!, keys, deps.fetch);
  try {
    saveConfig({ relayUrl: relayUrl!, id: ident.id, keys });
  } catch (e) {
    throw new Error(`registered as ${ident.id} but could not write config.json (${(e as Error).message}); the keys are in ${pending}`);
  }
  rmSync(pending, { force: true });
  lg(deps)(`registered as ${ident.id}`);
  lg(deps)(`fingerprint ${fingerprint(keys.signPub)}`);
}

export async function cmdShare(args: ParsedArgs, deps: CliDeps = {}): Promise<void> {
  const [session, ...people] = need(args, 2, 'share <session> <people...> --track "<text>" [--scope <dir>] [--threshold <0-1>]');
  const track = flagStr(args, 'track');
  if (track === undefined) throw new Error('--track "<text>" is required');
  const thrRaw = flagStr(args, 'threshold');
  // Saved only when given, so an unset session falls back to policy.yaml, then the default.
  const threshold = thrRaw === undefined ? undefined : Number(thrRaw);
  if (threshold !== undefined && (!Number.isFinite(threshold) || threshold < 0 || threshold > 1)) throw new Error('--threshold must be a number in [0, 1]');
  const scope = flagStr(args, 'scope');
  assertSafeName(session!, 'session name');
  for (const p of people) assertSafeName(p, 'person name');

  await ready();
  const cfg = loadConfig();
  const log = lg(deps);
  const allow = [...new Set(people)];
  // Resolve and pin first: a key mismatch aborts before anything is shared.
  const peers = [];
  for (const p of allow) peers.push(await resolvePeer(p, (id) => api.getIdentity(cfg.relayUrl, id, deps.fetch)));
  await api.putShare(cfg.relayUrl, cfg.id, cfg.keys, { session: session!, allow, track }, deps.fetch, deps.now?.());
  const sc: SessionConfig = { session: session!, allow, track, ...(threshold !== undefined ? { threshold } : {}), ...(scope !== undefined ? { scope } : {}) };
  writeSecureFile(sessionConfigPath(session!), JSON.stringify(sc, null, 2));
  log(`sharing session "${session}" with: ${allow.join(', ')}`);
  log('verify these fingerprints out-of-band:');
  for (const p of peers) log(`${p.id}  ${fingerprint(p.signPub)}`);
}

export async function cmdUnshare(args: ParsedArgs, deps: CliDeps = {}): Promise<void> {
  const [session] = need(args, 1, 'unshare <session>');
  assertSafeName(session!, 'session name');
  await ready();
  const cfg = loadConfig();
  await api.deleteShare(cfg.relayUrl, cfg.id, cfg.keys, session!, deps.fetch, deps.now?.());
  rmSync(sessionConfigPath(session!), { force: true });
  lg(deps)(`unshared session "${session}"`);
}

export async function cmdList(_args: ParsedArgs, deps: CliDeps = {}): Promise<void> {
  const log = lg(deps);
  log('local sessions:');
  const root = join(bridgeHome(), 'sessions');
  const names = existsSync(root) ? readdirSync(root).sort() : [];
  let n = 0;
  for (const name of names) {
    const sc = readSessionConfig(name);
    if (!sc) continue;
    n++;
    log(`  ${sc.session}  allow=[${sc.allow.join(', ')}] threshold=${sc.threshold ?? 'default'} track="${sc.track}"${sc.scope ? ` scope=${sc.scope}` : ''}`);
  }
  if (n === 0) log('  (none)');
  await ready();
  const cfg = loadConfig();
  const shares = await api.listShares(cfg.relayUrl, cfg.id, cfg.keys, deps.fetch, deps.now?.());
  log('relay shares:');
  if (shares.length === 0) log('  (none)');
  for (const s of shares) log(`  ${s.session}  allow=[${s.allow.join(', ')}] track="${s.track}"`);
}

function writeDecision(op: 'approve' | 'reject', args: ParsedArgs, deps: CliDeps): void {
  const [taskId] = need(args, 1, `${op} <taskId> --session <name>`);
  const session = flagStr(args, 'session');
  if (!session) throw new Error('--session <name> is required');
  assertSafeName(taskId!, 'task id');
  const file = join(sessionDir(session), 'control', `${op}-${taskId}.json`);
  writeSecureFile(file, JSON.stringify({ op, taskId, ts: (deps.now ?? Date.now)() }));
  lg(deps)(`${op} recorded for task ${taskId} (session ${session})`);
}

export const cmdApprove = async (args: ParsedArgs, deps: CliDeps = {}) => writeDecision('approve', args, deps);
export const cmdReject = async (args: ParsedArgs, deps: CliDeps = {}) => writeDecision('reject', args, deps);

export async function cmdPause(args: ParsedArgs, deps: CliDeps = {}): Promise<void> {
  const [session] = need(args, 1, 'pause <session>');
  writeSecureFile(join(sessionDir(session!), 'control', 'pause'), '');
  lg(deps)(`session "${session}" paused`);
}

export async function cmdResume(args: ParsedArgs, deps: CliDeps = {}): Promise<void> {
  const [session] = need(args, 1, 'resume <session>');
  ensureDir(join(sessionDir(session!), 'control'));
  rmSync(join(sessionDir(session!), 'control', 'pause'), { force: true });
  lg(deps)(`session "${session}" resumed`);
}

export async function cmdPin(args: ParsedArgs, deps: CliDeps = {}): Promise<void> {
  const [id] = need(args, 1, 'pin --reset <id>');
  if (args.flags['reset'] !== true) throw new Error('usage: bridge pin --reset <id>');
  const existed = resetPin(id!);
  lg(deps)(existed ? `pin for ${id} removed; next share re-pins from the relay` : `no pin for ${id}`);
}

/** Removes ANSI/OSC escape sequences and control characters except newline and tab. */
export function stripControl(text: string): string {
  return text
    .replace(/\x1b\][\s\S]*?(?:\x07|\x1b\\)/g, '') // OSC ... BEL / ST
    .replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, '') // CSI
    .replace(/\x1b[@-_]/g, '') // other two-byte escapes
    .replace(/[\x00-\x08\x0b-\x1f\x7f-\x9f]/g, '');
}

/** True when this process looks like it runs inside Claude Code (whose transcript must never see held text). */
function insideClaude(env: NodeJS.ProcessEnv): boolean {
  return Object.keys(env).some((k) => k === 'CLAUDECODE' || k.startsWith('CLAUDE_CODE_') || k === 'CLAUDE_PLUGIN_ROOT');
}

/** Owner-only commands run in a separate terminal: never without a TTY or inside Claude Code. */
function refuseInsideClaude(cmd: string, what: string, deps: CliDeps): void {
  const env = deps.env ?? process.env;
  const tty = deps.isTTY ?? process.stdout.isTTY === true;
  if (!tty || insideClaude(env)) {
    throw new Error(`refusing to ${what} here: run \`bridge ${cmd}\` in a separate terminal, not inside Claude Code`);
  }
}

const isSafeName = (n: string): boolean => {
  try {
    assertSafeName(n);
    return true;
  } catch {
    return false;
  }
};

/** Why a marker no longer applies, that the hook holds it (it then never expires), or undefined when simply live. */
function markerState(store: TaskStore, a: ActiveRec, now: number): string | undefined {
  if (a.pid !== undefined && !markerLive({ ...a, expiresAt: undefined }, now)) return `stale: Claude Code process ${a.pid} is gone`;
  let held: boolean;
  try {
    held = store.held(a);
  } catch {
    held = true; // unreadable held state: the hook fails closed
  }
  if (held) return 'held: waits for the owner';
  if (a.expiresAt !== undefined && a.expiresAt < now) return 'expired';
  return undefined;
}

/**
 * Overview of every local session (shared ones and send-only tmp-*): its active marker, how many inbound items are
 * held for the owner, and what is queued. Prints ids and names only, never peer-written text.
 */
export async function cmdStatus(_args: ParsedArgs, deps: CliDeps = {}): Promise<void> {
  const log = lg(deps);
  const now = (deps.now ?? Date.now)();
  const root = join(bridgeHome(), 'sessions');
  const names = existsSync(root) ? readdirSync(root).filter(isSafeName).sort() : [];
  if (names.length === 0) return log('no sessions');
  for (const name of names) {
    let sc: SessionConfig | undefined;
    try {
      sc = readSessionConfig(name);
    } catch {
      sc = undefined;
    }
    const kind = sc ? `shared with [${sc.allow.join(', ')}]` : name.startsWith('tmp-') ? 'send-only' : 'not shared';
    const paused = existsSync(join(sessionDir(name), 'control', 'pause')) ? ', paused' : '';
    log(`${name}  (${kind}${paused})`);
    if (existsSync(join(sessionDir(name), 'orphaned.json'))) {
      log('  server: orphaned (no parent Claude Code process); nothing is injected, remote work stays queued until restart');
    }
    let marker: string;
    try {
      const store = new TaskStore(name);
      const a = store.activeRaw();
      const state = a && markerState(store, a, now);
      marker = a ? `${a.role} task ${a.taskId} from ${a.from}${a.approved ? ', approved' : ''}${a.expiresAt !== undefined ? ', result marker' : ''}` +
        ` since ${new Date(a.ts).toISOString()}${state ? ` [${state}]` : ''}` : 'none';
    } catch (e) {
      marker = `unreadable (${(e as Error).message}); the hook denies every tool call in this session`;
    }
    log(`  active marker: ${stripControl(marker)}`);
    const pending = listPending(name);
    let queuedTasks = 0;
    try {
      queuedTasks = new TaskStore(name).list().filter((r) => r.status === 'queued' && r.role !== 'sender').length;
    } catch {
      /* counted as 0 */
    }
    log(`  held: ${pending.filter((p) => p.state === 'held').length}  queued: ${pending.filter((p) => p.state === 'queued').length} turn(s), ${queuedTasks} task(s)`);
  }
}

/**
 * Remove a stuck active marker of a session after printing what it was. The owner's escape hatch when a server
 * died or a marker cannot be cleared otherwise; with a running server prefer `bridge approve` / `bridge reject`.
 */
export async function cmdClear(args: ParsedArgs, deps: CliDeps = {}): Promise<void> {
  const session = flagStr(args, 'session');
  if (!session) throw new Error('usage: bridge clear --session <name>');
  assertSafeName(session, 'session name');
  refuseInsideClaude('clear', 'clear a marker', deps);
  const log = lg(deps);
  const path = join(sessionDir(session), 'active.json');
  if (!existsSync(path)) return log(`no active marker in session ${session}`);
  let raw: string;
  try {
    raw = readFileSync(path, 'utf8');
  } catch (e) {
    raw = `<unreadable: ${(e as Error).message}>`;
  }
  log(`removing active marker of session ${session}:`);
  log(stripControl(raw));
  rmSync(path, { force: true });
  log('removed');
}

/**
 * Print inbound messages/results of a thread that policy held (or that wait in the queue), for the owner to read
 * in a separate terminal. Refuses to run without a TTY or inside Claude Code, so held text never reaches a session.
 */
export async function cmdShow(args: ParsedArgs, deps: CliDeps = {}): Promise<void> {
  const [taskId] = need(args, 1, 'show <taskId> --session <name>');
  const session = flagStr(args, 'session');
  if (!session) throw new Error('--session <name> is required');
  assertSafeName(taskId!, 'task id');
  refuseInsideClaude('show', 'print held content', deps);
  const log = lg(deps);
  const items = listPending(session, taskId);
  if (items.length === 0) return log(`nothing held for task ${taskId} in session ${session}`);
  for (const it of items) {
    const what = it.kind === 'result' ? 'result' : `message #${it.seq}`;
    log(stripControl(`--- ${it.state} ${what} from ${it.from}${it.reason ? ` (reason: ${it.reason})` : ''}`));
    log(stripControl(it.body));
  }
  log('--- end (untrusted text written by another person)');
}

const COMMANDS: Record<string, (a: ParsedArgs, d: CliDeps) => Promise<void>> = {
  init: cmdInit,
  share: cmdShare,
  unshare: cmdUnshare,
  list: cmdList,
  approve: cmdApprove,
  reject: cmdReject,
  pause: cmdPause,
  resume: cmdResume,
  pin: cmdPin,
  show: cmdShow,
  status: cmdStatus,
  clear: cmdClear,
};

export async function main(argv: string[], deps: CliDeps = {}): Promise<number> {
  const [cmd, ...rest] = argv;
  const run = cmd ? COMMANDS[cmd] : undefined;
  if (!run) {
    console.error(`usage: bridge <${Object.keys(COMMANDS).join('|')}> ...`);
    return 2;
  }
  try {
    await run(parseArgs(rest), deps);
    return 0;
  } catch (e) {
    console.error(`bridge: ${(e as Error).message}`);
    return 1;
  }
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
  process.exitCode = await main(process.argv.slice(2));
}
