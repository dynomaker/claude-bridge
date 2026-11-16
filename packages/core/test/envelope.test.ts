import { beforeAll, describe, expect, it } from 'vitest';
import { EnvelopeError, fingerprint, generateKeypair, open, ready, seal } from '../src/index.js';
import type { Inner, Keypair } from '../src/index.js';

let alice: Keypair, bob: Keypair, mallory: Keypair;
const inner: Inner = {
  v: 1, kind: 'task', taskId: 't1', seq: 0, from: 'alice', fromSession: 'a1', to: 'bob',
  session: 'main', body: 'hello', ts: 1700000000000,
};

beforeAll(async () => {
  await ready();
  alice = generateKeypair();
  bob = generateKeypair();
  mallory = generateKeypair();
});

describe('envelope', () => {
  it('roundtrip', () => {
    expect(open(seal(inner, alice, bob.boxPub), bob, alice.signPub)).toEqual(inner);
  });

  it('rejects wrong sender key', () => {
    const outer = seal(inner, alice, bob.boxPub);
    expect(() => open(outer, bob, mallory.signPub)).toThrow(EnvelopeError);
  });

  it('rejects re-routed outer', () => {
    const outer = { ...seal(inner, alice, bob.boxPub), session: 'other' };
    expect(() => open(outer, bob, alice.signPub)).toThrow(EnvelopeError);
    expect(() => open(outer, bob, alice.signPub)).toThrow(/mismatch/);
  });

  it('rejects a spoofed fromSession on the outer', () => {
    const outer = { ...seal(inner, alice, bob.boxPub), fromSession: 'other' };
    expect(() => open(outer, bob, alice.signPub)).toThrow(/mismatch/);
  });

  it('rejects tampered ct', () => {
    const outer = seal(inner, alice, bob.boxPub);
    const bytes = Buffer.from(outer.ct, 'base64');
    bytes[bytes.length - 1] ^= 1;
    expect(() => open({ ...outer, ct: bytes.toString('base64') }, bob, alice.signPub)).toThrow(EnvelopeError);
  });

  it('fingerprint format', () => {
    expect(fingerprint(alice.signPub)).toMatch(/^[0-9a-f]{4}(-[0-9a-f]{4}){3}$/);
  });
});
