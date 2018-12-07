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
 * Implementation of the fixed A matrix generation function.
 */

#include "a_fixed.h"
#include "a_random.h"

#include <stdio.h>
#include <string.h>

#if PARAMS_TAU == 1
modq_t A_fixed[PARAMS_D * 2 * PARAMS_K];
#endif

int create_A_fixed(const unsigned char *seed) {
#if PARAMS_TAU == 1
    /* Create A_fixed randomly */
    create_A_random(A_fixed, seed);

    /* Duplicate rows */
    for (int i = PARAMS_K - 1; i >= 0; --i) {
        memcpy(A_fixed + (2 * i + 1) * PARAMS_D, A_fixed + i*PARAMS_D, PARAMS_D * sizeof (modq_t));
        if (i != 0) {
            memcpy(A_fixed + (2 * i) * PARAMS_D, A_fixed + i*PARAMS_D, PARAMS_D * sizeof (modq_t));
        }
    }

    return 0;
#else
    (void) seed;
    fprintf(stderr, "Can not call create_A_fixed with PARAMS_TAU=%d\n", PARAMS_TAU);
    exit(1);
#endif
}
