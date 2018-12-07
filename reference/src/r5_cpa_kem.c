/*
 * Copyright (c) 2018, Koninklijke Philips N.V.
 * Hayo Baan, Jose Luis Torre Arce
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
 * Implementation of the CPA KEM functions.
 */

#include "r5_cpa_kem.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "r5_core.h"
#include "r5_cpa_pke.h"
#include "pack.h"
#include "r5_hash.h"
#include "misc.h"
#include "r5_memory.h"
#include "rng.h"
#include "drbg.h"

/*******************************************************************************
 * Public functions
 ******************************************************************************/

int r5_cpa_kem_keygen_p(unsigned char *pk, unsigned char *sk, const parameters *params) {
    return r5_cpa_pke_keygen(pk, sk, params);
}

int r5_cpa_kem_encapsulate_p(unsigned char *ct, unsigned char *k, const unsigned char *pk, const parameters *params) {
    unsigned char *rho;
    unsigned char *m;
    unsigned char *hash_input;

    /* Generate a random m */
    m = checked_malloc(params->kappa_bytes);
    randombytes(m, params->kappa_bytes);

    /* Randomly generate rho */
    rho = checked_malloc(params->kappa_bytes);
    randombytes(rho, params->kappa_bytes);

    /* Encrypt m */
    r5_cpa_pke_encrypt(ct, pk, m, rho, params);

    /* k = H(m, ct) */
    hash_input = checked_malloc((size_t) (params->kappa_bytes + params->ct_size));
    memcpy(hash_input, m, params->kappa_bytes);
    memcpy(hash_input + params->kappa_bytes, ct, params->ct_size);
    hash(k, params->kappa_bytes, hash_input, (size_t) (params->kappa_bytes + params->ct_size), params->kappa_bytes);

    free(hash_input);
    free(rho);
    free(m);

    return 0;
}

int r5_cpa_kem_decapsulate_p(unsigned char *k, const unsigned char *ct, const unsigned char *sk, const parameters *params) {
    unsigned char *hash_input;
    unsigned char *m;

    /* Allocate space */
    hash_input = checked_malloc((size_t) (params->kappa_bytes + params->ct_size));
    m = checked_malloc(params->kappa_bytes);

    /* Decrypt m */
    r5_cpa_pke_decrypt(m, sk, ct, params);

    /* k = H(m, ct) */
    memcpy(hash_input, m, params->kappa_bytes);
    memcpy(hash_input + params->kappa_bytes, ct, params->ct_size);
    hash(k, params->kappa_bytes, hash_input, (size_t) (params->kappa_bytes + params->ct_size), params->kappa_bytes);

    free(hash_input);
    free(m);

    return 0;
}
