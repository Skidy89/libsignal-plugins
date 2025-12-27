'use strict';
const curve25519Rust = require('libsignal-plugins');


function validatePrivKey(privKey) {
    if (privKey === undefined) {
        throw new Error("Undefined private key");
    }
    if (!(privKey instanceof Buffer)) {
        throw new Error(`Invalid private key type: ${privKey.constructor.name}`);
    }
    if (privKey.byteLength != 32) {
        throw new Error(`Incorrect private key length: ${privKey.byteLength}`);
    }
}



exports.createKeyPair = function(privKey) {
    validatePrivKey(privKey);
    const keys = curve25519Rust.keyPair(privKey);
    return {
        pubKey: keys.pubKey,
        privKey: keys.privKey
    };
};


exports.calculateAgreement = function(pubKey, privKey) {
    return curve25519Rust.calculateAgreement(pubKey, privKey);
};


exports.calculateSignature = function(privKey, message) {
    validatePrivKey(privKey);
    if (!message) {
        throw new Error("Invalid message");
    }
    return curve25519Rust.curve25519Sign(privKey, message);
};


exports.verifySignature = function(pubKey, msg, sig, isInit = false) {
    return curve25519Rust.verifySignature(pubKey, msg, sig, isInit);
};



exports.generateKeyPair = function() {
    return curve25519Rust.generateKeyPair();
};
