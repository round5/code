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
 * Implementation of a “true” random bytes function.
 *
 * Uses /dev/urandom fro generating the random bytes.
 */

#include "rng.h"

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

/** Read the random bytes from /dev/urandom in blocks of 1MB (max). */
#define MAX_URANDOM_BLOCK_SIZE 1048576

/** The file descriptor of /dev/urandom, -1 means uninitialised  */
static int fd = -1;

void randombytes_init(unsigned char *entropy_input, unsigned char *personalization_string, int security_strength) {
    (void) entropy_input;
    (void) personalization_string;
    (void) security_strength;

    /* Open /dev/urandom (if not already done) */
    while (fd == -1) {
        fd = open("/dev/urandom", O_RDONLY);
        if (fd == -1) sleep(1); /* Wait a bit before retrying */
    }
}

int randombytes(unsigned char *r, unsigned long long n) {
    if (fd == -1) {
        randombytes_init(NULL, NULL, 0);
    }

    /* Get the random bytes in chunks */
    ssize_t s;
    while (n > 0) {
        s = read(fd, r, (size_t) (n < MAX_URANDOM_BLOCK_SIZE ? n : MAX_URANDOM_BLOCK_SIZE));
        if (s < 1) {
            sleep(1); /* Wait a bit before retrying */
        } else {
            /* Move to next chunk */
            r += s;
            n -= (unsigned long long) s;
        }
    }

    return 0;
}
