import { appendFileSync, chmodSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { ensureDir } from './keystore.js';
import { bridgeHome } from './paths.js';

/** Append one line to a file with mode 0600 (parent dirs 0700). */
export function appendSecureLine(path: string, line: string): void {
  ensureDir(dirname(path));
  appendFileSync(path, line + '\n', { mode: 0o600 });
  chmodSync(path, 0o600);
}

/** Append a JSONL audit record to `bridgeHome/audit.log`. */
export function audit(event: string, data: object): void {
  appendSecureLine(join(bridgeHome(), 'audit.log'), JSON.stringify({ ts: Date.now(), event, ...data }));
}
