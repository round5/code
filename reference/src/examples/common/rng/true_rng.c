/*
 * Copyright (c) 2018, Koninklijke Philips N.V.
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
