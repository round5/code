/*
 * Copyright (c) 2018, PQShield and Koninklijke Philips N.V.
 * Markku-Juhani O. Saarinen, Oscar Garcia-Morchon, Hayo Baan
 *
 * All rights reserved. A copyright license for redistribution and use in
 * source and binary forms, with or without modification, is hereby granted for
 * non-commercial, experimental, research, public review and evaluation
 * purposes, provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "r5_parameter_sets.h"

#ifdef CM_CACHE

#include "probe_cm.h"

#if !SHIFT_LEFT_IS_CONSTANT_TIME
// Constant-time 64-bit left shift
// o: output
// i: input

static uint64_t constant_time_shift_left64(int i, int flag) {
    uint64_t a, o;
    o = 1llu;
    a = (uint64_t) (-(i & 1));
    o = ((o << 1) & a) ^ (o & ~a);
    a = (uint64_t) (-((i >> 1) & 1));
    o = ((o << 2) & a) ^ (o & ~a);
    a = (uint64_t) (-((i >> 2) & 1));
    o = ((o << 4) & a) ^ (o & ~a);
    a = (uint64_t) (-((i >> 3) & 1));
    o = ((o << 8) & a) ^ (o & ~a);
    a = (uint64_t) (-((i >> 4) & 1));
    o = ((o << 16) & a) ^ (o & ~a);
    if (flag) {
        a = (uint64_t) (-((i >> 5) & 1));
        o = ((o << 32) & a) ^ (o & ~a);
    }
    return o;
}
#endif

// Cache-resistant "occupancy probe". Tests and "occupies" a single slot at x.
// Return value zero (false) indicates the slot was originally empty.

int probe_cm(uint64_t *v, int x) {
    int i;
    uint64_t a, b, c, y, z;

    // construct the selector
#if SHIFT_LEFT_IS_CONSTANT_TIME
    y = (1llu) << (x & 0x3F); // low bits of index
    z = (1llu) << (x >> 6); // high bits of index
#else
    y = constant_time_shift_left64(x & 0x3F, 1);
    z = constant_time_shift_left64(x >> 6, 0);
#endif

    c = 0;
    for (i = 0; i < PROBEVEC64; i++) { // always scan through all
        a = v[i];
        b = a | (y & (-(z & 1))); // set bit if not occupied.
        c |= a ^ b; // If change, mask.
        v[i] = b; // update value of v[i]
        z >>= 1;
    }

    // final comparison doesn't need to be constant time
    return c == 0; // return true if was occupied before
}

#endif
