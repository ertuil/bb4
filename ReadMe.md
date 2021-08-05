# bb4, a stream cipher with 64bit register vectors

bb4 is a stream cipher with a 256-bit key, 128-bit nonce, and 512-bit internal states.
bb4 has a similar structure to `chacha20`. Instead of using 16 32-bit registers, bb4 uses 8 64-bit registers.
Due to the reduced complexity of Permutation and replacement in a single round, bb4 uses 32 rounds. 
Consequently, a 512 (or 384) bit PRN is produced after each 32 round.
**bb4 is supposed to be the author's toy. It is still in the prototype phase and before cryptanalysis, use it as your own risk.**

This repo is implemented in Golang, and we also use `chacha20` (without AEAD) as the baseline.
bb4 is designed to:
* Use 64-bit register vectors;
* Be with (or without) AEAD;
* Be fast and vectorized.

Judging from the preliminary results, it passes tests in `Dieharder` and `PractRand`.
It is also 29% faster than the `chacha20` implementation of the Golang official library (`golang.org/x/chacha20`).