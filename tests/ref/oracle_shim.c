/* Copyright (c) 2026, Matt Doughty
 * SPDX-License-Identifier: BSD-3-Clause
 * Test-only support for the unmodified Argon2 reference implementation.
 */
#include <stddef.h>
#include <stdint.h>

void clear_internal_memory(void *memory, size_t length) {
    volatile uint8_t *bytes = (volatile uint8_t *)memory;
    while (length != 0) {
        *bytes++ = 0;
        --length;
    }
}
