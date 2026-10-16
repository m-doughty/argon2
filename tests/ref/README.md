# Independent Argon2 oracles

These files are unmodified files from the official
[P-H-C/phc-winner-argon2 repository](https://github.com/P-H-C/phc-winner-argon2),
commit `f57e61e19229e23c4445b85494dbf7c07de721cb`:

| File here | Upstream path |
|---|---|
| `blake2/blake2b.c` | `src/blake2/blake2b.c` |
| `blake2/blake2.h` | `src/blake2/blake2.h` |
| `blake2/blake2-impl.h` | `src/blake2/blake2-impl.h` |
| `blake2/blamka-round-ref.h` | `src/blake2/blamka-round-ref.h` |
| `core.c`, `core.h`, `thread.h`, `ref.c` | `src/core.c`, `src/core.h`, `src/thread.h`, `src/ref.c` |
| `argon2.h` | `include/argon2.h` |
| `LICENSE` | `LICENSE` |

The `blake2/` directory is how the upstream sources include each other
(`#include "blake2/blake2.h"`).

What the tests use them for:

- **H′.** The tests call the upstream `blake2b_long`, including its own
  independent BLAKE2b implementation.
- **Block compression.** The reference's compression function `fill_block`
  (RFC 9106 sections 3.5 and 3.6) is `static` in `ref.c`. `compress_oracle.c`,
  a test-only file of this crate (BSD-3-Clause), does `#include "ref.c"` and
  exports one wrapper, `compress_oracle`, around it. `ref.c` is therefore
  included, never compiled on its own (`argon2_tests.gpr` excludes it from the
  C sources). Nothing in the reference is replaced or stubbed.
- **The rest of the reference.** `core.c` is compiled because `ref.c` calls
  into it (block copy and XOR, the memory wipe `clear_internal_memory`, index
  mapping) and because later stages will use its whole fill loop for
  differential tests. It is built with `-DARGON2_NO_THREADS`, so `thread.h` and
  the platform threads are not used.
- **Published vectors.** `kat-blocks.json` holds blocks from the reference's
  own known-answer files (`kats/argon2id`, `kats/argon2d`, `kats/argon2i` at
  the commit above), from which `scripts/compression-vectors.py` generates
  `../src/compression_vectors.ads`. See that script for how they are found and
  checked. The KAT files themselves are not kept here.

The upstream files are available under CC0 1.0 or Apache 2.0, at the user's
option; both texts are retained in `LICENSE`. These files are linked only into
the test executable.
