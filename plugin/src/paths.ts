import { AsyncLocalStorage } from 'node:async_hooks';
import { homedir } from 'node:os';
import { join } from 'node:path';

const homeOverride = new AsyncLocalStorage<string>();

export function bridgeHome(): string {
  return homeOverride.getStore() || process.env.BRIDGE_HOME || join(homedir(), '.claude', 'channels', 'bridge');
}

/** Run `fn` (and everything async it starts) with `bridgeHome()` pinned to `home`; lets several bridges share one process. */
export function withBridgeHome<T>(home: string | undefined, fn: () => T): T {
  return home ? homeOverride.run(home, fn) : fn();
}

const SAFE_NAME = /^[A-Za-z0-9._-]{1,128}$/;
const RESERVED = new Set(['.', '..', '__proto__', 'constructor', 'prototype']);

/** Throw unless `name` is usable as a path segment and as an object key. */
export function assertSafeName(name: string, what = 'name'): void {
  if (!SAFE_NAME.test(name) || RESERVED.has(name)) throw new Error(`invalid ${what}: ${name}`);
}

export function sessionDir(name: string): string {
  assertSafeName(name, 'session name');
  return join(bridgeHome(), 'sessions', name);
}
