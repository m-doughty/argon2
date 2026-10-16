/* Copyright (c) 2026, Matt Doughty
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Test-only oracle for Argon2's block compression G (RFC 9106 sections 3.5
 * and 3.6), reached through the unmodified official reference.
 *
 * The reference's compression function, fill_block, is static in ref.c. This
 * file includes ref.c (it is not compiled on its own; see
 * argon2_tests.gpr) and exports one wrapper around it. Nothing in the
 * reference is replaced or stubbed.
 */
#include "ref.c"

/* z = G(x, y), or z = z xor G(x, y) when with_xor is not zero. Each of x, y
 * and z points at 128 64-bit words. fill_block takes (prev, ref, next); G is
 * symmetric in its first two arguments. z may be x or y: the reference's own
 * address generation calls fill_block with the same block as input and output. */
void compress_oracle(const uint64_t *x, const uint64_t *y, uint64_t *z,
                     int with_xor) {
    fill_block((const block *)x, (const block *)y, (block *)z, with_xor);
}
