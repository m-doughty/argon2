# Independent H′ oracle

`blake2b.c`, `blake2.h`, `blake2-impl.h`, `argon2.h` and `LICENSE` are
unmodified files from the official
[P-H-C/phc-winner-argon2 repository](https://github.com/P-H-C/phc-winner-argon2),
commit `f57e61e19229e23c4445b85494dbf7c07de721cb`:

- `src/blake2/blake2b.c`
- `src/blake2/blake2.h`
- `src/blake2/blake2-impl.h`
- `include/argon2.h`
- `LICENSE`

The tests call the upstream `blake2b_long` function, including its own
independent BLAKE2b implementation. `oracle_shim.c` supplies the memory wipe
symbol required by that implementation, using volatile byte writes. No
Argon2 hashing logic is replaced by the shim.

The upstream files are available under CC0 1.0 or Apache 2.0, at the user's
option; both texts are retained in `LICENSE`. The shim uses BSD-3-Clause.
These files are linked only into the test executable.
