/*
 * Copyright (c) 2018, Koninklijke Philips N.V.
 */

/**
 * @file
 * Implementation of the fixed A matrix generation function.
 */

#include "a_fixed.h"
#include "a_random.h"
#include "r5_memory.h"

#include <stdlib.h>
#include <string.h>

size_t A_fixed_len = 0;
uint16_t *A_fixed = NULL;

int create_A_fixed(const unsigned char *seed, const parameters *params) {
    A_fixed_len = (size_t) (2 * params->d * params->k);

    /* (Re)allocate space for A_fixed */
    A_fixed = checked_realloc(A_fixed, A_fixed_len * sizeof (*A_fixed));

    /* Create A_fixed randomly */
    if (create_A_random(A_fixed, seed, params)) {
        return 1;
    }

    /* Duplicate rows */
    for (int i = params->k - 1; i >= 0; --i) {
        memcpy(A_fixed + (2 * i + 1) * params->d, A_fixed + i * params->d, params->d * sizeof (*A_fixed));
        if (i != 0) {
            memcpy(A_fixed + (2 * i) * params->d, A_fixed + i * params->d, params->d * sizeof (*A_fixed));
        }
    }

    return 0;
}
