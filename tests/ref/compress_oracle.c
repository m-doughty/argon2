/* Copyright (c) 2026, Matt Doughty
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Test-only oracles for Argon2's block compression G (RFC 9106 sections 3.5
 * and 3.6) and its indexing (section 3.4), reached through the unmodified
 * official reference.
 *
 * The reference's compression function, fill_block, and its address-block
 * function, next_addresses, are static in ref.c. This file includes ref.c (it
 * is not compiled on its own; see argon2_tests.gpr) and exports three
 * wrappers: around fill_block, around core.c's index_alpha, and around
 * next_addresses. Nothing in the reference is replaced or stubbed.
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

/* The reference's index_alpha (core.c): the index, within the reference
 * lane, of the reference block of block `index` of the segment (pass, slice,
 * lane), for the 32-bit J1 and whether the reference lane is the block's own
 * lane. The instance is built on the stack with the fields index_alpha reads
 * (segment_length, lane_length) and the rest as the reference sets them. */
uint32_t index_alpha_oracle(uint32_t lanes, uint32_t segment_length,
                            uint32_t passes, uint32_t type, uint32_t pass,
                            uint32_t lane, uint32_t slice, uint32_t index,
                            uint32_t pseudo_rand, int same_lane) {
    argon2_instance_t instance;
    argon2_position_t position;

    memset(&instance, 0, sizeof(instance));
    instance.version = ARGON2_VERSION_13;
    instance.passes = passes;
    instance.segment_length = segment_length;
    instance.lane_length = 4 * segment_length;
    instance.lanes = lanes;
    instance.memory_blocks = (uint32_t)((uint64_t)lanes * instance.lane_length);
    instance.threads = 1;
    instance.type = (argon2_type)type;

    position.pass = pass;
    position.lane = lane;
    position.slice = (uint8_t)slice;
    position.index = index;
    return index_alpha(&instance, &position, pseudo_rand, same_lane);
}

/* The reference's next_addresses (ref.c): the 128 words of an address block
 * from the first seven words of the input block as fill_segment holds them
 * before the call (pass, lane, slice, m', t, y, N - 1; next_addresses adds 1
 * to word 6). The other words of the input block and the zero block are zero,
 * as fill_segment initialises them. */
void next_addresses_oracle(const uint64_t *input_words,
                           uint64_t *address_words) {
    block address_block, input_block, zero_block;

    init_block_value(&zero_block, 0);
    init_block_value(&input_block, 0);
    memcpy(input_block.v, input_words, 7 * sizeof(uint64_t));
    next_addresses(&address_block, &input_block, &zero_block);
    memcpy(address_words, address_block.v, sizeof(address_block.v));
}
