import { existsSync, readFileSync, realpathSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, isAbsolute, join, relative, resolve } from 'node:path';
import { parse } from 'yaml';
import { bridgeHome } from '../paths.js';

export type RuleHit = { rule: string; detail: string };
export type RuleCtx = { cwd: string; scope?: string; bridgeHome: string; extraDeny?: RegExp[] };
export type Policy = { threshold?: number; extraDeny: RegExp[]; classifier: { timeoutMs: number } };

export const DEFAULT_TIMEOUT_MS = 20000;

// ---------------------------------------------------------------- paths

/** Expand a leading `~`, `$HOME` or `${HOME}`, then resolve against cwd. */
export function resolvePath(p: string, cwd: string): string {
  const home = homedir();
  let s = p.trim();
  if (s === '~') s = home;
  else if (s.startsWith('~/')) s = join(home, s.slice(2));
  s = s.replace(/^\$\{HOME\}|^\$HOME/, home);
  return resolve(cwd, s);
}

/** Resolve symlinks of the deepest existing ancestor so a link inside scope cannot lead outside. */
function canonical(p: string): string {
  let head = resolve(p);
  const tail: string[] = [];
  while (!existsSync(head)) {
    const parent = resolve(head, '..');
    if (parent === head) return resolve(p);
    tail.unshift(basename(head));
    head = parent;
  }
  try {
    return join(realpathSync(head), ...tail);
  } catch {
    return resolve(p);
  }
}

function lexicallyInside(scope: string, p: string): boolean {
  const rel = relative(scope, p);
  return rel !== '..' && !rel.startsWith('..' + '/') && !isAbsolute(rel);
}

/** Deny-list check: inside if EITHER the lexical or the symlink-resolved path is inside. */
function insideEither(dir: string, p: string): boolean {
  const d = resolve(dir);
  const r = resolve(p);
  return lexicallyInside(d, r) || lexicallyInside(canonical(d), canonical(r));
}

/** Allow-list check: true only if `p` is inside `scope` both lexically and after resolving symlinks. */
export function isInside(scope: string, p: string): boolean {
  const s = resolve(scope);
  const r = resolve(p);
  return lexicallyInside(s, r) && lexicallyInside(canonical(s), canonical(r));
}

function sensitiveFileReason(p: string): string | undefined {
  for (const name of [basename(p), basename(canonical(p))]) {
    if (/^\.env/.test(name)) return 'env file';
    if (/\.pem$/i.test(name)) return 'pem file';
    if (/^id_/.test(name)) return 'ssh identity file';
  }
  const home = homedir();
  if (insideEither(join(home, '.ssh'), p)) return '~/.ssh';
  if (insideEither(join(home, '.aws'), p)) return '~/.aws';
  if (insideEither(join(home, '.claude', '.credentials.json'), p)) return 'Claude credentials';
  return undefined;
}

function protectedStateReason(p: string, bridge: string): string | undefined {
  if (insideEither(bridge, p)) return 'bridge state directory';
  return undefined;
}

const CLAUDE_CONFIG_PATH = /(^|\/)\.claude\/(settings[^/]*\.json$|hooks\/|plugins\/)|(^|\/)\.mcp\.json$/;

/** Claude config that can change hooks/permissions/MCP servers: any project or home `.claude/settings*.json`, `.claude/hooks/**`, `.claude/plugins/**`, `.mcp.json`. */
function isSettingsFile(p: string): boolean {
  if (CLAUDE_CONFIG_PATH.test(p) || CLAUDE_CONFIG_PATH.test(canonical(p))) return true;
  return /^settings.*\.json$/.test(basename(p)) && insideEither(join(homedir(), '.claude'), p);
}

// ---------------------------------------------------------------- text rules

type TextRule = { rule: string; test: (text: string, cwd: string) => string | undefined };

/** Split a shell-ish command into rough simple-command segments. */
function segments(cmd: string): string[] {
  return cmd.split(/&&|\|\||[;|&\n`()]|\$\(/).map((s) => s.trim()).filter(Boolean);
}

function words(seg: string): string[] {
  return (seg.match(/"[^"]*"|'[^']*'|\S+/g) ?? []).map((w) => w.replace(/["']/g, '').replace(/\\/g, ''));
}

function rmRecursiveOutsideTmp(cmd: string, cwd: string): string | undefined {
  for (const seg of segments(cmd)) {
    const w = words(seg);
    const i = w.findIndex((x) => x === 'rm' || x.endsWith('/rm'));
    if (i < 0) continue;
    const args = w.slice(i + 1);
    const recursive = args.some((a) => /^-[a-zA-Z]*[rR]/.test(a) || a === '--recursive');
    if (!recursive) continue;
    for (const target of args.filter((a) => !a.startsWith('-'))) {
      if (/[$`]/.test(target)) return `rm -r target ${target} (expansion)`;
      if (!lexicallyInside('/tmp', resolvePath(target, cwd)) || resolvePath(target, cwd) === '/tmp') return `rm -r target ${target}`;
    }
  }
  return undefined;
}

function gitPushRisk(cmd: string): string | undefined {
  for (const seg of segments(cmd)) {
    const w = words(seg);
    const gi = w.findIndex((x) => x === 'git' || x.endsWith('/git'));
    const pi = w.indexOf('push', gi + 1);
    if (gi < 0 || pi < 0) continue;
    for (const a of w.slice(pi + 1)) {
      if (/^-[a-zA-Z]*f[a-zA-Z]*$/.test(a) || /^--force/.test(a)) return 'force push';
      if (a === '--all' || a === '--mirror') return `push ${a}`;
      if (a.startsWith('+') || a.includes(':+')) return 'force push (+refspec)';
      if (/(^|[:/])(main|master)$/.test(a)) return 'push to main/master';
    }
  }
  return undefined;
}

const SQL = /\bDROP\s+(TABLE|DATABASE)\b|\bTRUNCATE\b/i;
const DEPLOY = /\b(kubectl|helm|terraform)\b|\bdocker\s+push\b|\bwrangler\s+deploy\b|\bfly\s+deploy\b/;
const RESET_REMOTE = /\bgit\s+reset\s+--hard\s+(\S*\/|@\{u|FETCH_HEAD|(origin|upstream)(\s|$))/;

/** Shared text rules (apply to Bash commands and, best effort, to MCP input). */
const TEXT_RULES: TextRule[] = [
  { rule: 'rm-rf-outside-tmp', test: rmRecursiveOutsideTmp },
  { rule: 'git-push-force-or-main', test: (c) => gitPushRisk(c) },
  { rule: 'git-reset-hard-remote', test: (c) => (RESET_REMOTE.test(c) ? 'git reset --hard on a remote ref' : undefined) },
  { rule: 'deploy-tooling', test: (c) => DEPLOY.exec(c)?.[0] },
  { rule: 'destructive-sql', test: (c) => SQL.exec(c)?.[0] },
];

const BASH_ONLY_RULES: TextRule[] = [
  {
    rule: 'bridge-cli',
    test: (c) => (/(^|[\s;&|(`'"]|\/)bridge(\s|$)/.test(c) ? 'bridge CLI invocation' : undefined),
  },
];

export const DEFAULT_RULES: readonly string[] = [
  ...TEXT_RULES.map((r) => r.rule),
  ...BASH_ONLY_RULES.map((r) => r.rule),
  'sensitive-file',
  'bridge-state',
  'claude-settings',
  'write-outside-scope',
];

// ---------------------------------------------------------------- Bash path scan

function bashPathTokens(cmd: string): string[] {
  return cmd
    .split(/[\s;|&<>()"'`=,]+/)
    .map((t) => t.trim())
    .filter(Boolean);
}

function checkBashPaths(cmd: string, ctx: RuleCtx): RuleHit[] {
  const hits: RuleHit[] = [];
  const add = (rule: string, detail: string) => hits.push({ rule, detail });
  if (cmd.includes(ctx.bridgeHome)) add('bridge-state', 'command references the bridge state directory');
  if (/BRIDGE_HOME|channels\/bridge|channels[^\n]*bridge/.test(cmd)) add('bridge-state', 'command references the bridge state directory');
  if (/(~|\$HOME|\$\{HOME\})\/\.claude\b/.test(cmd) || cmd.includes(join(homedir(), '.claude'))) add('claude-config', 'command references ~/.claude');
  if (/cli\.js/.test(cmd) && /\b(share|unshare|pin|approve|reject|pause|resume|init)\b/.test(cmd)) add('bridge-cli', 'bridge CLI via cli.js');
  if (/\.claude\/settings[^\s'"]*\.json/.test(cmd)) add('claude-settings', 'command references Claude settings');
  if (/(^|[/\s'"=~}])\.(ssh|aws)(\/|\s|$|['"])/.test(cmd)) add('sensitive-file', 'command references ~/.ssh or ~/.aws');
  const hasCd = /(^|[\s;&|(`])cd(\s|$|;|&|\|)/.test(cmd);
  for (const tok of bashPathTokens(cmd)) {
    const p = resolvePath(tok, ctx.cwd);
    const why = sensitiveFileReason(p);
    if (why) add('sensitive-file', `${why}: ${tok}`);
    if (protectedStateReason(p, ctx.bridgeHome)) add('bridge-state', `bridge state: ${tok}`);
    if (isSettingsFile(p)) add('claude-settings', `Claude settings: ${tok}`);
    if (/(^|\/)\.claude(\/|$)/.test(tok) && !isInside(ctx.cwd, p)) add('claude-config', `.claude outside project: ${tok}`);
    if (hasCd && /(^|\/)\.(claude|ssh|aws)(\/|$)|\.credentials/.test(tok)) add('sensitive-file', `sensitive path after cd: ${tok}`);
  }
  // Any non-read-only command that touches a `.claude` path (copy/move/redirect into it, or via a variable).
  const MUTATING = /(^|[\s;&|(`])(cp|mv|ln|tee|install|rsync|chmod|touch|mkdir)(\s|$)|>|\bsed\s+(\S+\s+)*-[a-zA-Z-]*i/;
  const claudeToken = bashPathTokens(cmd).some((tok) => {
    const p = resolvePath(tok, ctx.cwd);
    return [tok, p, canonical(p)].some((x) => /(^|\/)\.claude(\/|$)/.test(x));
  });
  if (claudeToken && MUTATING.test(cmd)) add('claude-settings', 'mutating command on a .claude path');
  if (/(^|[\s;&|(`])[A-Za-z_][A-Za-z0-9_]*=[^\s;&|]*\.claude/.test(cmd)) add('claude-settings', 'variable assigned a .claude path');
  return hits;
}

// ---------------------------------------------------------------- tool calls

const WRITE_TOOLS = new Set(['Write', 'Edit', 'MultiEdit', 'NotebookEdit']);

function field(input: unknown, key: string): string | undefined {
  if (input && typeof input === 'object') {
    const v = (input as Record<string, unknown>)[key];
    if (typeof v === 'string' && v.length > 0) return v;
  }
  return undefined;
}

/** Paths a file-oriented tool call will touch (cwd when Grep/Glob omit `path`). Undefined when it cannot be determined. */
export function toolPaths(tool: string, input: unknown, cwd: string): string[] | undefined {
  if (tool === 'Write' || tool === 'Edit' || tool === 'MultiEdit') {
    const p = field(input, 'file_path');
    return p ? [resolvePath(p, cwd)] : undefined;
  }
  if (tool === 'NotebookEdit') {
    const p = field(input, 'notebook_path');
    return p ? [resolvePath(p, cwd)] : undefined;
  }
  if (tool === 'Read') {
    const p = field(input, 'file_path');
    return p ? [resolvePath(p, cwd)] : undefined;
  }
  if (tool === 'Grep' || tool === 'Glob') {
    const out = [resolvePath(field(input, 'path') ?? '.', cwd)];
    const pattern = field(input, 'pattern');
    if (tool === 'Glob' && pattern && (/^(~|\$HOME|\$\{HOME\}|\/)/.test(pattern) || pattern.includes('..'))) {
      out.push(resolvePath(pattern.split(/[*?[{]/)[0] || '.', cwd));
    }
    return out;
  }
  return undefined;
}

export function checkToolCall(tool: string, input: unknown, ctx: RuleCtx): RuleHit[] {
  const hits: RuleHit[] = [];
  const add = (rule: string, detail: string) => hits.push({ rule, detail });
  const scope = ctx.scope ?? ctx.cwd;
  let text = '';

  if (tool === 'Bash') {
    const cmd = field(input, 'command');
    if (cmd === undefined) return [{ rule: 'malformed-input', detail: 'Bash call without a command' }];
    text = cmd;
    for (const r of [...TEXT_RULES, ...BASH_ONLY_RULES]) {
      const d = r.test(cmd, ctx.cwd);
      if (d) add(r.rule, d);
    }
    hits.push(...checkBashPaths(cmd, ctx));
  } else {
    try {
      text = JSON.stringify(input ?? null);
    } catch {
      return [{ rule: 'malformed-input', detail: 'tool input is not serializable' }];
    }
    if (tool.startsWith('mcp__')) {
      for (const r of TEXT_RULES) {
        if (r.rule === 'rm-rf-outside-tmp') continue;
        const d = r.test(text, ctx.cwd);
        if (d) add(r.rule, d);
      }
    }
    const paths = toolPaths(tool, input, ctx.cwd);
    const fileTool = WRITE_TOOLS.has(tool) || tool === 'Read' || tool === 'Grep' || tool === 'Glob';
    if (fileTool && !paths) add('malformed-input', `${tool} call without a usable path`);
    for (const p of paths ?? []) {
      const why = sensitiveFileReason(p);
      if (why) add('sensitive-file', `${why}: ${p}`);
      if (protectedStateReason(p, ctx.bridgeHome)) add('bridge-state', `bridge state: ${p}`);
      if (tool === 'Grep' || tool === 'Glob') {
        // A recursive search rooted above a protected directory would read it.
        const home = homedir();
        for (const d of [join(home, '.ssh'), join(home, '.aws'), ctx.bridgeHome]) {
          if (insideEither(p, d)) add('sensitive-file', `search root ${p} contains ${d}`);
        }
      }
      if (WRITE_TOOLS.has(tool)) {
        if (isSettingsFile(p)) add('claude-settings', `Claude settings: ${p}`);
        if (!isInside(scope, p)) add('write-outside-scope', `${p} is outside ${scope}`);
      }
    }
    if (/(^|[/"'\s])\.(ssh|aws)\//.test(text)) add('sensitive-file', 'input references ~/.ssh or ~/.aws');
  }

  for (const re of ctx.extraDeny ?? []) {
    if (re.test(text)) add('extra-deny', String(re));
  }
  return hits;
}

// ---------------------------------------------------------------- task text

const INTENT: Array<[string, RegExp]> = [
  ['destructive-delete', /\brm\s+-[a-zA-Z]*[rR]|\b(wipe|erase|delete|remove)\s+(all|everything|the\s+(whole\s+)?(repo|repository|disk|database|home|server))\b|\bformat\s+(the\s+)?(disk|drive)\b|\bmkfs\b/i],
  ['force-push', /\bforce[- ]push\b|\bpush\s+(--force|-f)\b|\bgit\s+push\b[^\n]*\b(main|master)\b|\bpush\b[^\n.]*\b(to|into)\s+(main|master)\b/i],
  ['history-rewrite', /\breset\s+--hard\b/i],
  ['destructive-sql', /\bDROP\s+(TABLE|DATABASE)\b|\bTRUNCATE\b/i],
  ['deploy', /\b(kubectl|helm|terraform|wrangler\s+deploy|fly\s+deploy|docker\s+push)\b|\bdeploy\b[^\n.]*\b(prod|production)\b/i],
  ['secret-access', /(\.env\b|\.pem\b|\bid_(rsa|ed25519|ecdsa|dsa)\b|~\/\.(ssh|aws)|\bprivate\s+key|\bapi[_ -]?key|\bcredentials?\b|\bpasswords?\b|\bsecrets?\b|\btokens?\b)/i],
  ['policy-tamper', /\b(ignore|disregard|override|bypass|disable)\b[^\n.]*\b(previous|prior|above|all)?\s*(instructions|rules|polic(y|ies)|safeguards|restrictions|permissions)\b|\bsettings\.json\b|\bbridge\s+(share|pin|approve|revoke)\b/i],
  ['remote-code', /\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(sh|bash)\b/i],
];

export function checkTaskText(text: string): RuleHit[] {
  const hits: RuleHit[] = [];
  for (const [rule, re] of INTENT) {
    const m = re.exec(text);
    if (m) hits.push({ rule, detail: m[0].slice(0, 80) });
  }
  return hits;
}

// ---------------------------------------------------------------- policy.yaml

export function loadPolicy(path: string = join(bridgeHome(), 'policy.yaml')): Policy {
  const out: Policy = { extraDeny: [], classifier: { timeoutMs: DEFAULT_TIMEOUT_MS } };
  if (!existsSync(path)) return out;
  const doc: unknown = parse(readFileSync(path, 'utf8')) ?? {};
  if (typeof doc !== 'object' || Array.isArray(doc)) throw new Error('policy.yaml: top level must be a mapping');
  const d = doc as Record<string, unknown>;
  if (d.threshold !== undefined) {
    if (typeof d.threshold !== 'number' || !(d.threshold >= 0 && d.threshold <= 1)) throw new Error('policy.yaml: threshold must be a number in [0,1]');
    out.threshold = d.threshold;
  }
  if (d.extraDeny !== undefined) {
    if (!Array.isArray(d.extraDeny) || d.extraDeny.some((x) => typeof x !== 'string')) throw new Error('policy.yaml: extraDeny must be a list of regex strings');
    out.extraDeny = (d.extraDeny as string[]).map((s) => {
      try {
        return new RegExp(s);
      } catch (e) {
        throw new Error(`policy.yaml: invalid regex ${JSON.stringify(s)}: ${(e as Error).message}`);
      }
    });
  }
  if (d.classifier !== undefined) {
    const c = d.classifier as Record<string, unknown> | null;
    if (!c || typeof c !== 'object' || Array.isArray(c)) throw new Error('policy.yaml: classifier must be a mapping');
    if (c.timeoutMs !== undefined) {
      if (typeof c.timeoutMs !== 'number' || !Number.isFinite(c.timeoutMs) || c.timeoutMs <= 0) throw new Error('policy.yaml: classifier.timeoutMs must be a positive number');
      out.classifier.timeoutMs = c.timeoutMs;
    }
  }
  return out;
}
