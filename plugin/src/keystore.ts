import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fingerprint } from '@claude-bridge/core';
import type { Keypair, PublicIdentity } from '@claude-bridge/core';
import { assertSafeName, bridgeHome } from './paths.js';

export type BridgeConfig = { relayUrl: string; id: string; keys: Keypair };

export class PinMismatchError extends Error {
  constructor(id: string, changed: string, pinned: string, offered: string) {
    super(
      `${changed} for "${id}" changed: pinned fingerprint ${pinned}, relay now returns ${offered}. ` +
        `If this is expected, verify it out-of-band and run: bridge pin --reset ${id}`,
    );
    this.name = 'PinMismatchError';
  }
}

/** Create a directory (and parents) with mode 0700. */
export function ensureDir(dir: string): void {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
}

/** Write a file with mode 0600, atomically, creating parent dirs 0700. */
export function writeSecureFile(path: string, data: string): void {
  ensureDir(dirname(path));
  const tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, data, { mode: 0o600 });
  chmodSync(tmp, 0o600);
  renameSync(tmp, path);
}

const configPath = () => join(bridgeHome(), 'config.json');
const pinsPath = () => join(bridgeHome(), 'pins.json');

export function loadConfig(): BridgeConfig {
  const p = configPath();
  if (!existsSync(p)) throw new Error('not initialised: run `bridge init <relayUrl> <invite>`');
  return JSON.parse(readFileSync(p, 'utf8')) as BridgeConfig;
}

export function saveConfig(cfg: BridgeConfig): void {
  writeSecureFile(configPath(), JSON.stringify(cfg, null, 2));
}

type Pins = Record<string, { signPub: string; boxPub: string }>;

function readPins(): Pins {
  const p = pinsPath();
  const pins: Pins = Object.create(null);
  if (existsSync(p)) Object.assign(pins, JSON.parse(readFileSync(p, 'utf8')) as Pins);
  return pins;
}

function getPin(id: string): { signPub: string; boxPub: string } | undefined {
  assertSafeName(id, 'identity id');
  return readPins()[id];
}

export function pinKey(id: string, signPub: string, boxPub: string): void {
  assertSafeName(id, 'identity id');
  const pins = readPins();
  pins[id] = { signPub, boxPub };
  writeSecureFile(pinsPath(), JSON.stringify(pins, null, 2));
}

/** Remove a pin; returns whether one existed. */
export function resetPin(id: string): boolean {
  assertSafeName(id, 'identity id');
  const pins = readPins();
  if (!Object.hasOwn(pins, id)) return false;
  delete pins[id];
  writeSecureFile(pinsPath(), JSON.stringify(pins, null, 2));
  return true;
}

/** The pinned public identity of `id`, if any (no relay round trip). */
export function pinnedPeer(id: string): PublicIdentity | undefined {
  const p = getPin(id);
  return p ? { id, signPub: p.signPub, boxPub: p.boxPub } : undefined;
}

/** Trust on first use: pin the key on first sight; afterwards the relay must return the same key. */
export async function resolvePeer(
  id: string,
  fetchFn: (id: string) => Promise<PublicIdentity>,
): Promise<PublicIdentity> {
  const pinned = getPin(id);
  const got = await fetchFn(id);
  if (!pinned) {
    pinKey(id, got.signPub, got.boxPub);
    return got;
  }
  if (pinned.signPub !== got.signPub) {
    throw new PinMismatchError(id, 'Signing key', fingerprint(pinned.signPub), fingerprint(got.signPub));
  }
  if (pinned.boxPub !== got.boxPub) {
    throw new PinMismatchError(id, 'Encryption key', fingerprint(pinned.boxPub), fingerprint(got.boxPub));
  }
  return { id, signPub: pinned.signPub, boxPub: pinned.boxPub };
}
