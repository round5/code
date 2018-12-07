/*
 * Copyright (c) 2018, Koninklijke Philips N.V.
 * Hayo Baan
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

/**
 * @file
 * Implementation of the memory handling functions.
 */

#include "r5_memory.h"

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#undef checked_malloc
#undef checked_calloc
#undef checked_realloc

extern void *checked_malloc(size_t size, const char *file, int line);
extern void *checked_calloc(size_t count, size_t size, const char *file, const int line);
extern void *checked_realloc(void *ptr, size_t size, const char *file, const int line);

int constant_time_memcmp(const void *s1, const void *s2, size_t n) {
    const uint8_t * a = s1;
    const uint8_t * b = s2;
    int ret = 0;
    size_t i;

    for (i = 0; i < n; ++i) {
        ret |= *a++ ^ *b++;
    }

    return ret;
}

void conditional_constant_time_memcpy(void * restrict dst, const void * restrict src, size_t n, uint8_t flag) {
    uint8_t * d = dst;
    const uint8_t * s = src;
    flag = (unsigned char) (-(flag | -flag) >> 7); // Force flag into 0x00 or 0xff
    size_t i;

    for (i = 0; i < n; ++i) {
        d[i] = (uint8_t) (d[i] ^ (flag & (d[i] ^ s[i])));
    }
}
