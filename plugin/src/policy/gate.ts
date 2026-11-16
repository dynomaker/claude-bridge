import { classify } from './classifier.js';
import type { ClassifyInput, Verdict } from './classifier.js';
import { checkTaskText, checkToolCall, isInside, toolPaths } from './rules.js';
import type { RuleCtx, RuleHit } from './rules.js';

export const DEFAULT_THRESHOLD = 0.3;

export type ClassifyFn = (input: ClassifyInput) => Promise<Verdict>;
export type ActiveTask = { task: string; track: string; threshold: number };

const fmt = (hits: RuleHit[]) => hits.map((h) => `${h.rule} (${h.detail})`).join('; ');
const SCOPED_READ_TOOLS = new Set(['Read', 'Grep', 'Glob']);

async function score(fn: ClassifyFn, input: ClassifyInput): Promise<Verdict> {
  try {
    const v = await fn(input);
    if (!v || typeof v.risk !== 'number' || !Number.isFinite(v.risk)) return { risk: 1, reason: 'classifier returned an invalid verdict', failed: true };
    return { risk: Math.min(1, Math.max(0, v.risk)), reason: String(v.reason), failed: v.failed === true };
  } catch (e) {
    return { risk: 1, reason: `classifier unavailable: ${(e as Error).message}`, failed: true };
  }
}

function limit(threshold: number): number {
  return Number.isFinite(threshold) && threshold >= 0 && threshold <= 1 ? threshold : DEFAULT_THRESHOLD;
}

export async function gateTask(
  task: string,
  track: string,
  threshold: number,
  classifyFn: ClassifyFn = classify,
): Promise<{ decision: 'run' | 'hold'; reason: string; risk: number }> {
  try {
    if (typeof task !== 'string') throw new Error('task is not a string');
    const hits = checkTaskText(task);
    if (hits.length > 0) return { decision: 'hold', reason: `rule hit: ${fmt(hits)}`, risk: 1 };
    const v = await score(classifyFn, { task, track });
    const decision = v.failed || v.risk >= limit(threshold) ? 'hold' : 'run';
    return { decision, reason: v.reason, risk: v.risk };
  } catch (e) {
    return { decision: 'hold', reason: `gate error: ${(e as Error).message}`, risk: 1 };
  }
}

export async function gateTool(
  call: { tool: string; input: unknown },
  ctx: RuleCtx,
  active: ActiveTask,
  classifyFn: ClassifyFn = classify,
): Promise<{ decision: 'allow' | 'deny'; reason: string }> {
  try {
    const hits = checkToolCall(call.tool, call.input, ctx);
    if (hits.length > 0) return { decision: 'deny', reason: `rule hit: ${fmt(hits)}` };

    if (SCOPED_READ_TOOLS.has(call.tool)) {
      const scope = ctx.scope ?? ctx.cwd;
      const paths = toolPaths(call.tool, call.input, ctx.cwd);
      if (paths && paths.every((p) => isInside(scope, p))) return { decision: 'allow', reason: 'read inside scope' };
    }

    // Everything else (Bash, writes, WebFetch, mcp__*, reads outside scope, unknown tools) is scored.
    const v = await score(classifyFn, { task: active.task, track: active.track, toolCall: call });
    return v.failed || v.risk >= limit(active.threshold)
      ? { decision: 'deny', reason: `risk ${v.risk.toFixed(2)}: ${v.reason}` }
      : { decision: 'allow', reason: v.reason };
  } catch (e) {
    return { decision: 'deny', reason: `gate error: ${(e as Error).message}` };
  }
}
