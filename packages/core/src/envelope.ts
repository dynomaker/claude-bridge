import sodium from 'libsodium-wrappers';
import { fromB64, openBytes, sealBytes, signDetached, toB64, verifyDetached } from './crypto.js';
import type { Inner, Keypair, Outer } from './types.js';

export class EnvelopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'EnvelopeError';
  }
}

export function seal(inner: Inner, sender: Keypair, recipientBoxPub: string): Outer {
  const payload = JSON.stringify(inner);
  const sig = signDetached(sodium.from_string(payload), sender.signSec);
  const ct = sealBytes(sodium.from_string(JSON.stringify({ payload, sig })), recipientBoxPub);
  return { from: inner.from, fromSession: inner.fromSession, to: inner.to, session: inner.session, ct: toB64(ct) };
}

export function open(outer: Outer, recipient: Keypair, senderSignPub: string): Inner {
  let plain: Uint8Array;
  try {
    plain = openBytes(fromB64(outer.ct), recipient.boxPub, recipient.boxSec);
  } catch {
    throw new EnvelopeError('decrypt failed');
  }
  let payload: string;
  let sig: string;
  try {
    ({ payload, sig } = JSON.parse(sodium.to_string(plain)) as { payload: string; sig: string });
    if (typeof payload !== 'string' || typeof sig !== 'string') throw new Error('shape');
  } catch {
    throw new EnvelopeError('malformed envelope');
  }
  if (!verifyDetached(sodium.from_string(payload), sig, senderSignPub)) {
    throw new EnvelopeError('bad signature');
  }
  let inner: Inner;
  try {
    inner = JSON.parse(payload) as Inner;
  } catch {
    throw new EnvelopeError('malformed payload');
  }
  if (inner.from !== outer.from || inner.fromSession !== outer.fromSession || inner.to !== outer.to || inner.session !== outer.session) {
    throw new EnvelopeError('routing mismatch between outer and inner');
  }
  return inner;
}
