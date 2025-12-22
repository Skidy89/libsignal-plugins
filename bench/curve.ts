import { bench, do_not_optimize, boxplot, summary, run } from "mitata";
import * as rust from "./../index";
import * as nodeCurve from "libsignal-node/src/curve.js";

const message = Buffer.from("message");

const bobNodeKeyPair = nodeCurve.generateKeyPair();
const aliceNodeKeyPair = nodeCurve.generateKeyPair();

const bobRustKeyPair = rust.generateKeyPair();
const aliceRustKeyPair = rust.generateKeyPair();

boxplot(() => {

  summary(() => {
    bench("Generate Key Pair Node", () => {
      const keyPair = nodeCurve.generateKeyPair();
      do_not_optimize(keyPair);
    });

    bench("Generate Key Pair Rust Custom", () => {
      const keyPair = rust.generateKeyPair();
      do_not_optimize(keyPair);
    });
  });

  // Calculate agreement benchmark
  summary(() => {
    bench("Calculate Agreement Node", () => {
      const shared1 = nodeCurve.calculateAgreement(
        bobNodeKeyPair.pubKey,
        aliceNodeKeyPair.privKey
      );
      const shared2 = nodeCurve.calculateAgreement(
        aliceNodeKeyPair.pubKey,
        bobNodeKeyPair.privKey
      );
      do_not_optimize(shared1);
      do_not_optimize(shared2);
    });

    bench("Calculate Agreement Rust Custom", () => {
      const shared1 = rust.calculateAgreement(
        bobRustKeyPair.pubKey,
        aliceRustKeyPair.privKey
      );
      const shared2 = rust.calculateAgreement(
        aliceRustKeyPair.pubKey,
        bobRustKeyPair.privKey
      );
      do_not_optimize(shared1);
      do_not_optimize(shared2);
    });
  });

  // Signature calculation benchmark
  summary(() => {
    bench("Calculate Signature Node", () => {
      const signature = nodeCurve.calculateSignature(
        aliceNodeKeyPair.privKey,
        message
      );
      do_not_optimize(signature);
    });

    bench("Calculate Signature Rust Custom", () => {
      const signature = rust.curve25519Sign(
        aliceRustKeyPair.privKey,
        message
      );
      do_not_optimize(signature);
    });
  });

  // Signature verification benchmark
  summary(() => {
    const nodeSignature = nodeCurve.calculateSignature(
      aliceNodeKeyPair.privKey,
      message
    );
    const rustSignature = rust.curve25519Sign(
      aliceRustKeyPair.privKey,
      message
    );

    bench("Verify Signature Node", () => {
      const isValid = nodeCurve.verifySignature(
        aliceNodeKeyPair.pubKey,
        message,
        nodeSignature
      );
      do_not_optimize(isValid);
    });

    bench("Verify Signature Rust Custom", () => {
      const isValid = rust.verifySignature(
        aliceRustKeyPair.pubKey,
        message,
        rustSignature,
        false
      );
      do_not_optimize(isValid);
    });
  });

});

(async () => {
  await run();
})();
