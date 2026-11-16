// Fail-safe launcher for the PreToolUse hook. Imports ONLY node builtins so that a broken
// or missing hook.js cannot stop it from denying while a remote task is active.
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';

export type LaunchIO = {
  readStdin: () => string;
  importHook: () => Promise<{ runHook: (input: string, env: NodeJS.ProcessEnv) => Promise<string> }>;
  env: NodeJS.ProcessEnv;
  write: (s: string) => void;
};

const FAILURE_DENY = JSON.stringify({
  hookSpecificOutput: {
    hookEventName: 'PreToolUse',
    permissionDecision: 'deny',
    permissionDecisionReason: 'claude-bridge: hook failure',
  },
});

// Mirrors assertSafeName in paths.ts (duplicated to stay builtins-only).
const SAFE_NAME = /^[A-Za-z0-9._-]{1,128}$/;
const RESERVED = new Set(['.', '..', '__proto__', 'constructor', 'prototype']);

/** Mirrors heldIn in tasks.ts: a held event of the marker's task at or after its ts (or an unparseable final line). */
function heldMarker(dir: string, m: { taskId?: unknown; ts?: unknown }): boolean {
  const p = join(dir, 'held-events.jsonl');
  if (!existsSync(p)) return false;
  const lines = readFileSync(p, 'utf8').split('\n').filter((l) => l.trim());
  for (let i = 0; i < lines.length; i++) {
    try {
      const ev = JSON.parse(lines[i]!) as { taskId?: unknown; ts?: unknown };
      if (ev.taskId === m.taskId && (typeof ev.ts !== 'number' || typeof m.ts !== 'number' || ev.ts >= m.ts)) return true;
    } catch {
      if (i === lines.length - 1) return true;
    }
  }
  return false;
}

/**
 * False only for a marker that provably no longer applies: expired and not held, or its Claude Code pid is gone
 * (mirrors markerLive in tasks.ts). Anything unreadable counts as live.
 */
function markerMayApply(path: string): boolean {
  try {
    const m = JSON.parse(readFileSync(path, 'utf8')) as { pid?: unknown; expiresAt?: unknown; taskId?: unknown; ts?: unknown };
    if (typeof m.expiresAt === 'number' && m.expiresAt < Date.now() && !heldMarker(dirname(path), m)) return false;
    if (typeof m.pid === 'number' && Number.isSafeInteger(m.pid) && m.pid > 0) {
      try {
        process.kill(m.pid, 0);
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code === 'ESRCH') return false;
      }
    }
    return true;
  } catch {
    return true;
  }
}

/** Deny iff a remote task may be active (or that cannot be determined); otherwise stay silent. */
function failureOutput(env: NodeJS.ProcessEnv): string {
  try {
    const session = env.BRIDGE_SESSION;
    const home = env.BRIDGE_HOME || join(homedir(), '.claude', 'channels', 'bridge');
    if (!session) {
      // A send-only (tmp-*) process may be answering a thread; without the hook module its cwd cannot be matched.
      const root = join(home, 'sessions');
      if (!existsSync(root)) return '';
      const anyTmp = readdirSync(root).some((n) => {
        const p = join(root, n, 'active.json');
        return /^tmp-[0-9a-f]{16}$/.test(n) && existsSync(p) && markerMayApply(p);
      });
      return anyTmp ? FAILURE_DENY : '';
    }
    if (!SAFE_NAME.test(session) || RESERVED.has(session)) return FAILURE_DENY;
    const p = join(home, 'sessions', session, 'active.json');
    return existsSync(p) && markerMayApply(p) ? FAILURE_DENY : '';
  } catch {
    return FAILURE_DENY;
  }
}

/** Never throws and never exits non-zero (a non-blocking error would let the tool call proceed). */
export async function launchHook(io: LaunchIO): Promise<void> {
  let out: string;
  try {
    const input = io.readStdin();
    const { runHook } = await io.importHook();
    out = await runHook(input, io.env);
  } catch {
    out = failureOutput(io.env);
  }
  try {
    if (out) io.write(out + '\n');
  } catch {
    /* nothing more to do */
  }
}

export const readFd0 = (): string => readFileSync(0, 'utf8');
