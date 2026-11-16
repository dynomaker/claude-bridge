import { createHash } from 'node:crypto';
import sodium from 'libsodium-wrappers';
import type { Keypair } from './types.js';

const B64 = () => sodium.base64_variants.ORIGINAL;
export const toB64 = (b: Uint8Array): string => sodium.to_base64(b, B64());
export const fromB64 = (s: string): Uint8Array => sodium.from_base64(s, B64());

export async function ready(): Promise<void> {
  await sodium.ready;
}

export function generateKeypair(): Keypair {
  const sign = sodium.crypto_sign_keypair();
  const box = sodium.crypto_box_keypair();
  return {
    signPub: toB64(sign.publicKey),
    signSec: toB64(sign.privateKey),
    boxPub: toB64(box.publicKey),
    boxSec: toB64(box.privateKey),
  };
}

export function fingerprint(signPub: string): string {
  const hex = createHash('sha256').update(fromB64(signPub)).digest('hex').slice(0, 16);
  return hex.match(/.{4}/g)!.join('-');
}

export function signDetached(msg: Uint8Array, signSec: string): string {
  return toB64(sodium.crypto_sign_detached(msg, fromB64(signSec)));
}

export function verifyDetached(msg: Uint8Array, sig: string, signPub: string): boolean {
  try {
    return sodium.crypto_sign_verify_detached(fromB64(sig), msg, fromB64(signPub));
  } catch {
    return false;
  }
}

export function sealBytes(msg: Uint8Array, recipientBoxPub: string): Uint8Array {
  return sodium.crypto_box_seal(msg, fromB64(recipientBoxPub));
}

export function openBytes(ct: Uint8Array, boxPub: string, boxSec: string): Uint8Array {
  return sodium.crypto_box_seal_open(ct, fromB64(boxPub), fromB64(boxSec));
}
