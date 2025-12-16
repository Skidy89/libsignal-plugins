
> [!CAUTION]
> NOTICE OF BREAKING CHANGE.
>
> This library is under active development. Breaking changes may occur between versions.


LibSignal Plugins is a Rust + NAPI-RS library for cryptographic operations like key generation, signature verification, group encryption, and more, compatible with Node.js via TypeScript bindings.


# Usage & Guide

> [!IMPORTANT]
> The guide is a work in progress. Expect incomplete pages/content. [Report missing or incorrect content](https://github.com/skidy89/libsignal-plugins/issues/new).

You can also access the auto-generated TypeScript definitions here:

```ts
import {
  calculateAgreement,
  createKeyPair,
  curve25519Sign,
  generateKeyPair,
  generatePreKey,
  generateRegistrationId,
  generateSignedPreKey,
  groupEncrypt,
  keyPair,
  sharedSecret,
  verify,
  verifySignature
} from 'libsignal-plugins';
```

## examples

### generate a keypair!
```ts
const keys = generateKeyPair();
console.log(keys.pubKey, keys.privKey);
// pub key is always a 33 bytes key, the first byte is always the version (5)
```

### create a keypair from private key
```ts
const keys = createKeyPair(Buffer.from('...32-byte private key...'));
// you can use randomBytes to make a dummy priv key!

console.log(keys.pubKey, keys.privKey);
```

### sharedSecret

```ts
const secret = sharedSecret(pubKeyBuffer, privKeyBuffer);
console.log(secret.toString('hex'));
```

### signature Verification

```ts
const valid = verify(sigBuffer, pubKeyBuffer, messageBuffer);
console.log(valid); // true or false
```

### sign a message!
this sign uses curve25519 donna to sign a message, if youre looking for a modern version this may not be your repo to work with!

```ts
const sig = curve25519Sign(privKeyBuffer, messageBuffer);
console.log(sig.toString('hex'));
```
