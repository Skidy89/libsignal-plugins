"use strict";
const d = require("libsignal-plugins");

// this are just thin wrappers around the libsignal-plugins functions
// to avoid breaking changes in the libsignal-node API

function encrypt(key, data, iv) {
  return d.encryptData(key, data, iv);
}

function decrypt(key, data, iv) {
  return d.decryptData(key, data, iv);
}

function calculateMAC(key, data) {
  return d.calculateMac(key, data);
}

function hash(data) {
  return d.hash(data);
}

function deriveSecrets(input, salt, info, chunks = 3) {
  return d.deriveSecrets(input, salt, info, chunks);
}

function verifyMAC(data, key, mac, length) {
  d.verifyMac(key, data, mac, length);
}

module.exports = {
  deriveSecrets,
  decrypt,
  encrypt,
  hash,
  calculateMAC,
  verifyMAC,
};
