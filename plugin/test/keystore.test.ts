import { mkdtempSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { fingerprint, generateKeypair, ready } from '@claude-bridge/core';
import type { PublicIdentity } from '@claude-bridge/core';
import { loadConfig, PinMismatchError, pinKey, resetPin, resolvePeer, saveConfig } from '../src/keystore.js';

let home: string;
let a: PublicIdentity;
let b: PublicIdentity;

beforeAll(async () => {
  await ready();
  const ka = generateKeypair();
  const kb = generateKeypair();
  a = { id: 'bob', signPub: ka.signPub, boxPub: ka.boxPub };
  b = { id: 'bob', signPub: kb.signPub, boxPub: kb.boxPub };
});
beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'bridge-'));
  process.env.BRIDGE_HOME = home;
});
afterEach(() => {
  delete process.env.BRIDGE_HOME;
  rmSync(home, { recursive: true, force: true });
});

describe('resolvePeer', () => {
  it('pins on first sight, accepts same key, rejects a different key', async () => {
    expect(await resolvePeer('bob', async () => a)).toEqual(a);
    expect(await resolvePeer('bob', async () => a)).toEqual(a);
    const err = await resolvePeer('bob', async () => b).catch((e) => e);
    expect(err).toBeInstanceOf(PinMismatchError);
    expect(err.message).toContain('bridge pin --reset bob');
  });

  it('accepts a new key after reset', async () => {
    await resolvePeer('bob', async () => a);
    expect(resetPin('bob')).toBe(true);
    expect(await resolvePeer('bob', async () => b)).toEqual(b);
  });

  it('pinKey pre-pins', async () => {
    pinKey('bob', a.signPub, a.boxPub);
    await expect(resolvePeer('bob', async () => b)).rejects.toBeInstanceOf(PinMismatchError);
  });
});

describe('reserved ids', () => {
  it.each(['__proto__', 'constructor', 'prototype'])('rejects %s', async (id) => {
    expect(() => pinKey(id, a.signPub, a.boxPub)).toThrow(/invalid identity id/);
    await expect(resolvePeer(id, async () => ({ ...a, id }))).rejects.toThrow(/invalid identity id/);
  });
});

describe('mismatch detail', () => {
  it('names the box key when only boxPub differs', async () => {
    await resolvePeer('bob', async () => a);
    const err = await resolvePeer('bob', async () => ({ ...a, boxPub: b.boxPub })).catch((e) => e);
    expect(err).toBeInstanceOf(PinMismatchError);
    expect(err.message).toContain('Encryption key');
    expect(err.message).toContain(fingerprint(b.boxPub));
  });
});

describe('config', () => {
  it('round-trips and is written with mode 0600', () => {
    const cfg = { relayUrl: 'https://relay.example.com', id: 'alice', keys: generateKeypair() };
    saveConfig(cfg);
    expect(loadConfig()).toEqual(cfg);
    expect(statSync(join(home, 'config.json')).mode & 0o777).toBe(0o600);
  });

  it('pins file is 0600 and a fresh nested home is 0700', () => {
    process.env.BRIDGE_HOME = join(home, 'nested', 'bridge');
    pinKey('bob', a.signPub, a.boxPub);
    expect(statSync(join(home, 'nested', 'bridge', 'pins.json')).mode & 0o777).toBe(0o600);
    expect(statSync(join(home, 'nested', 'bridge')).mode & 0o777).toBe(0o700);
  });
});
