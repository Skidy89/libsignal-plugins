export interface KeyPairType {
  pubKey: Buffer;
  privKey: Buffer;
}

export function generateKeyPair(): KeyPairType;

export function calculateAgreement(
  publicKey: Uint8Array,
  privateKey: Uint8Array
): Uint8Array;

export function calculateSignature(
  privateKey: Uint8Array,
  message: Uint8Array
): Buffer;

export function verifySignature(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array
): boolean;
