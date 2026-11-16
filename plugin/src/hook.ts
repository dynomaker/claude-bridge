import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { audit, appendSecureLine } from './audit.js';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';
import { sessionDir, bridgeHome } from './paths.js';
import { classify } from './policy/classifier.js';
import { gateTool } from './policy/gate.js';
import type { ClassifyFn } from './policy/gate.js';
import { checkToolCall, loadPolicy, resolvePath, toolPaths } from './policy/rules.js';
import { heldIn, markerLive, parseActive, TaskStore } from './tasks.js';
import type { ActiveRec } from './tasks.js';

export type HookDeps = { classify?: ClassifyFn };

const deny = (reason: string): string =>
  JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: `claude-bridge: ${reason}. This remote task is now held for the session owner. Stop working on it and send a short note with bridge_reply (receiver) or bridge_message (sender).`,
    },
  });

/**
 * A denial under a result marker: the thread is already finished, so there is nobody to message; the owner decides.
 * (Only results set `expiresAt`; every other marker belongs to an open thread.)
 */
const denyFinished = (reason: string): string =>
  JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: `claude-bridge: ${reason}. This session is gated by the result of a finished bridge thread and is now held for the session owner. Stop this work and tell the user; the session owner decides in their own terminal.`,
    },
  });
const denyFor = (active: ActiveRec, reason: string): string =>
  active.role === 'sender' && active.expiresAt !== undefined ? denyFinished(reason) : deny(reason);

/** A denial that is not about a remote task (no "task is now held" advice). */
const denyPlain = (reason: string): string =>
  JSON.stringify({
    hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: `claude-bridge: ${reason}` },
  });

/** Classifier budget inside the hook (Claude Code kills the hook at 30 s). */
export const CLASSIFIER_CAP_MS = 22_000;
export const WATCHDOG_MS = 24_000;
// Claude Code names plugin MCP tools mcp__plugin_<plugin>_<server>__<tool>; a project-level server is mcp__<server>__<tool>.
const HELD_EXEMPT = new Set([
  'mcp__bridge__bridge_reply', 'mcp__bridge__bridge_message',
  'mcp__plugin_bridge_bridge__bridge_reply', 'mcp__plugin_bridge_bridge__bridge_message',
]);

/**
 * Best-effort side effects of a denial; they must never turn a deny into an allow.
 * The hook never writes tasks.json: the server applies held events (it is the only writer).
 */
function recordHeld(session: string, taskId: string | undefined, tool: string, reason: string): void {
  try {
    appendSecureLine(join(sessionDir(session), 'held-events.jsonl'), JSON.stringify({ taskId: taskId ?? 'unknown', reason, ts: Date.now() }));
  } catch {
    /* deny stands regardless */
  }
  try {
    audit('tool-deny', { session, taskId, tool, reason });
  } catch {
    /* deny stands regardless */
  }
}

/**
 * Held-state contract (shared with the server, see `heldIn` in tasks.ts): the task is held iff some event for
 * `active.taskId` has `ts >= active.ts`. Whoever lifts a hold (owner approval) must rewrite active.json with a fresh
 * `ts`, which supersedes older events. Read errors throw.
 */
export function isHeld(session: string, active: ActiveRec): boolean {
  return heldIn(sessionDir(session), active);
}

const TMP_SESSION = /^tmp-[0-9a-f]{16}$/;

/** `p` equals `dir` or lies inside it. */
function isWithin(dir: string, p: string): boolean {
  const rel = relative(resolve(dir), resolve(p));
  return rel === '' || (rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
}

/**
 * Send-only processes (no BRIDGE_SESSION) keep their marker under `sessions/tmp-<hex>/active.json` with the session's
 * cwd. Returns the tmp session whose marker cwd equals or contains `cwd`. Throws (fail closed) if such a marker cannot be read, or if
 * any marker exists while `cwd` is unknown.
 */
export function findTmpSession(cwd: string | undefined): string | undefined {
  const root = join(bridgeHome(), 'sessions');
  if (!existsSync(root)) return undefined;
  for (const name of readdirSync(root)) {
    if (!TMP_SESSION.test(name)) continue;
    const p = join(root, name, 'active.json');
    if (!existsSync(p)) continue;
    let rec: ActiveRec;
    try {
      rec = parseActive(JSON.parse(readFileSync(p, 'utf8')));
    } catch (e) {
      throw new Error(`unreadable marker of ${name}: ${(e as Error).message}`);
    }
    if (!markerLive(rec, Date.now(), () => heldIn(join(root, name), rec))) continue; // expired and not held, or its Claude Code is gone
    if (cwd === undefined) throw new Error('a send-only bridge thread is active but the hook input has no cwd');
    if (rec.cwd !== undefined && isWithin(rec.cwd, cwd)) return name;
  }
  return undefined;
}

/**
 * Held peer text lives in `<bridgeHome>/sessions/<name>/held/` and must never reach any session, shared or not.
 * Returns a reason when a Read/Grep/Glob/Bash call reads there (a Grep/Glob root that contains such a directory
 * counts; Bash is checked per path token, wildcards included). Undefined otherwise or when the input is unusable.
 */
export function heldContentAccess(input: string, home: string = bridgeHome()): string | undefined {
  let payload: { tool_name?: unknown; tool_input?: unknown; cwd?: unknown };
  try {
    payload = JSON.parse(input);
  } catch {
    return undefined;
  }
  if (!payload || typeof payload !== 'object') return undefined;
  const tool = payload.tool_name;
  if (tool !== 'Read' && tool !== 'Grep' && tool !== 'Glob' && tool !== 'Bash') return undefined;
  const cwd = typeof payload.cwd === 'string' && payload.cwd ? payload.cwd : process.cwd();
  const sessions = resolve(home, 'sessions');
  // `<sessions>/<any segment, wildcards allowed>/held[/...]`
  const underHeld = (p: string) => {
    const rel = relative(sessions, resolve(p));
    return rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel) && /^[^/\\]+[/\\]held([/\\]|$)/.test(rel);
  };
  const reason = 'held peer content is readable only by the owner with `bridge show` in a separate terminal';
  if (tool === 'Bash') {
    const cmd = (payload.tool_input as { command?: unknown } | null)?.command;
    if (typeof cmd !== 'string') return undefined;
    const tokens = cmd.split(/[\s;|&<>()"'`=,]+/).filter(Boolean);
    return tokens.some((t) => underHeld(resolvePath(t, cwd))) ? reason : undefined;
  }
  const paths = toolPaths(tool, payload.tool_input, cwd) ?? [];
  if (paths.some(underHeld)) return reason;
  if (tool === 'Grep' || tool === 'Glob') {
    let heldDirs: string[] = [];
    try {
      heldDirs = existsSync(sessions) ? readdirSync(sessions).map((n) => join(sessions, n, 'held')).filter((d) => existsSync(d)) : [];
    } catch {
      return reason; // cannot tell what the search would cover
    }
    if (paths.some((root) => heldDirs.some((d) => isWithin(root, d)))) return reason;
  }
  return undefined;
}

function withWatchdog<T>(work: Promise<T>, onTimeout: T): Promise<T> {
  let timer: NodeJS.Timeout;
  const dog = new Promise<T>((resolve) => {
    timer = setTimeout(() => resolve(onTimeout), WATCHDOG_MS);
  });
  return Promise.race([work, dog]).finally(() => clearTimeout(timer));
}

/**
 * Core of the PreToolUse hook. Returns the stdout to print ('' = no opinion).
 * Fails closed (deny) whenever a remote task may be active but state cannot be read.
 * State location comes from process.env.BRIDGE_HOME (see paths.ts); `env` supplies BRIDGE_SESSION.
 * BRIDGE_DISABLE is deliberately ignored: with no active marker the hook is a no-op anyway, and with one it must not be switchable from the environment.
 */
export async function runHook(input: string, env: NodeJS.ProcessEnv, deps: HookDeps = {}): Promise<string> {
  // Applies to every session, with or without an active marker.
  const heldHit = heldContentAccess(input);
  if (heldHit) {
    try {
      audit('tool-deny', { session: env.BRIDGE_SESSION, reason: heldHit });
    } catch {
      /* deny stands regardless */
    }
    return denyPlain(heldHit);
  }
  let session = env.BRIDGE_SESSION;
  if (!session) {
    let cwd: string | undefined;
    try {
      const c = (JSON.parse(input) as { cwd?: unknown } | null)?.cwd;
      if (typeof c === 'string' && c) cwd = c;
    } catch {
      /* unknown cwd: any tmp marker then fails closed */
    }
    try {
      session = findTmpSession(cwd);
    } catch (e) {
      const reason = `cannot read bridge state: ${(e as Error).message}`;
      try {
        audit('tool-deny', { reason });
      } catch {
        /* deny stands regardless */
      }
      return deny(reason);
    }
    if (!session) return '';
  }

  let active: ActiveRec | undefined;
  let tool = '?';
  try {
    active = new TaskStore(session).active();
  } catch (e) {
    const reason = `cannot read bridge state: ${(e as Error).message}`;
    recordHeld(session, undefined, tool, reason);
    return deny(reason);
  }
  if (!active) return '';

  try {
    let payload: { tool_name?: unknown; tool_input?: unknown; cwd?: unknown };
    try {
      payload = JSON.parse(input);
    } catch {
      throw new Error('malformed hook input');
    }
    if (!payload || typeof payload !== 'object' || typeof payload.tool_name !== 'string') throw new Error('hook input has no tool_name');
    tool = payload.tool_name;
    const call = { tool, input: payload.tool_input };
    const held = isHeld(session, active);
    if (held && !HELD_EXEMPT.has(tool)) {
      try {
        audit('tool-deny', { session, taskId: active.taskId, tool, reason: 'task is held' });
      } catch {
        /* deny stands regardless */
      }
      return denyFor(active, 'this task is held');
    }
    const policy = loadPolicy();
    const cwd = typeof payload.cwd === 'string' && payload.cwd ? payload.cwd : process.cwd();
    const ctx = { cwd, scope: active.scope, bridgeHome: bridgeHome(), extraDeny: policy.extraDeny };

    let result: { decision: 'allow' | 'deny'; reason: string };
    if (active.approved) {
      const hits = checkToolCall(call.tool, call.input, ctx);
      result = hits.length > 0
        ? { decision: 'deny', reason: `rule hit: ${hits.map((h) => `${h.rule} (${h.detail})`).join('; ')}` }
        : { decision: 'allow', reason: 'approved task, no hard rule hit' };
    } else {
      const timeoutMs = Math.min(policy.classifier.timeoutMs, CLASSIFIER_CAP_MS);
      const fn: ClassifyFn = deps.classify ?? ((i) => classify(i, { timeoutMs }));
      result = await withWatchdog(gateTool(call, ctx, active, fn), { decision: 'deny', reason: 'classifier watchdog timeout' });
    }

    if (result.decision === 'allow') {
      try {
        audit('tool-allow', { session, taskId: active.taskId, tool, reason: result.reason });
      } catch {
        /* auditing must not block allowed work */
      }
      return '';
    }
    recordHeld(session, active.taskId, tool, result.reason);
    return denyFor(active, result.reason);
  } catch (e) {
    const reason = `hook error: ${(e as Error).message}`;
    recordHeld(session, active.taskId, tool, reason);
    return denyFor(active, reason);
  }
}
