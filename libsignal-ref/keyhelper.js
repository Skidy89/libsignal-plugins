// vim: ts=4:sw=4:expandtab

const curve = require('./curve');
const plugins = require('libsignal-plugins');

function isNonNegativeInteger(n) {
    return (typeof n === 'number' && (n % 1) === 0  && n >= 0);
}

exports.generateIdentityKeyPair = curve.generateKeyPair;

exports.generateRegistrationId = plugins.generateRegistrationId;

exports.generateSignedPreKey = function(identityKeyPair, signedKeyId) {
    const d = plugins.generateSignedPreKey(identityKeyPair, signedKeyId);
    return {
        keyId: d.keyId,
        keyPair: {
            pubKey: d.pubKey,
            privKey: d.privKey
        },
        signature: d.signature
    };
};

exports.generatePreKey = function(keyId) {
    if (!isNonNegativeInteger(keyId)) {
        throw new TypeError('Invalid argument for keyId: ' + keyId);
    }
    const keyPair = curve.generateKeyPair();
    return {
        keyId,
        keyPair
    };
};
