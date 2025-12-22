# Crypto Benchmark Results

Benchmarks for key pair generation, agreement calculation, signature creation, and verification across different implementations:

* **Rust/WASM** (`WhiskeySockets` compiled WASM module)
* **libsignal-node** (Node.js pure JS/crypto implementation)
* **libsignal-plugins** (`napi-rs` native Rust module)

**Tested on:**

* **CPU:** Intel(R) Core(TM) i7-4790 CPU @ 3.60GHz (~2.05–1.97 GHz)
* **Runtimes:**

  * Bun 1.3.5 (x64-win32)
  * Node 22.13.0 (x64-win32)

---

## Key Pair Generation

| Implementation    | Avg / Iter | Relative Speed |
| ----------------- | ---------- | -------------- |
| Rust/WASM         | 59.52 µs   | 1.0x           |
| libsignal-node    | 34.90 µs   | 1.71x faster   |
| libsignal-plugins | 474.42 µs  | 0.64x          |


---

## Agreement Calculation

| Implementation    | Avg / Iter | Relative Speed                        |
| ----------------- | ---------- | ------------------------------------- |
| Rust/WASM         | 370.36 µs  | 1.0x                                  |
| libsignal-node    | 174.74 µs  | 2.12x faster                          |
| libsignal-plugins | 977.55 µs  | 1.92x faster than Node in second test |


---

## Signature Calculation

| Implementation    | Avg / Iter | Relative Speed |
| ----------------- | ---------- | -------------- |
| Rust/WASM         | 121.73 µs  | 35.68x faster  |
| libsignal-node    | 4.34 ms    | 1.0x           |
| libsignal-plugins | 80.94 µs   | 100.09x faster |


---

## Signature Verification

| Implementation    | Avg / Iter | Relative Speed |
| ----------------- | ---------- | -------------- |
| Rust/WASM         | 197.24 µs  | 22.84x faster  |
| libsignal-node    | 4.50 ms    | 1.0x           |
| libsignal-plugins | 133.56 µs  | 61.77x faster  |


---

## Notes
* **libsignal-plugins** is faster than the WASM/Node.js version.
* **Limitation:** libsignal-plugins is **not yet supported on Bun**, so it may not be suitable for Bun-based projects at this time.