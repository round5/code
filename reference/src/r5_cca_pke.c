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
 * Implementation of the encrypt and decrypt functions based on the CCA KEM
 * algorithm.
 */

#include "r5_cca_pke.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "r5_dem.h"
#include "r5_cca_kem.h"
#include "r5_hash.h"
#include "misc.h"
#include "r5_memory.h"
#include "rng.h"

/*******************************************************************************
 * Public functions
 ******************************************************************************/

int r5_cca_pke_keygen_p(unsigned char *pk, unsigned char *sk, const parameters * params) {
    return r5_cca_kem_keygen_p(pk, sk, params);
}

int r5_cca_pke_encrypt_p(unsigned char *ct, unsigned long long *ct_len, const unsigned char *m, const unsigned long long m_len, const unsigned char *pk, const parameters *params) {
    int result = 1;
    const unsigned long long c1_len = (unsigned long long) (params->ct_size + params->kappa_bytes);
    unsigned char *c1 = checked_malloc(c1_len);
    unsigned long long c2_len;
    unsigned char *k = checked_malloc(params->kappa_bytes);
    *ct_len = 0;

    /* Determine c1 and k */
    r5_cca_kem_encapsulate_p(c1, k, pk, params);

    /* Copy c1 into first part of ct */
    memcpy(ct, c1, c1_len);
    *ct_len = c1_len;

    /* Apply DEM to get second part of ct */
    if (round5_dem(ct + c1_len, &c2_len, k, params->kappa_bytes, m, m_len)) {
        fprintf(stderr, "Failed to apply DEM\n");
        goto done_encrypt;
    }
    *ct_len += c2_len;

    /* All OK */
    result = 0;

done_encrypt:
    free(c1);
    free(k);

    return result;
}

int r5_cca_pke_decrypt_p(unsigned char *m, unsigned long long *m_len, const unsigned char *ct, const unsigned long long ct_len, const unsigned char *sk, const parameters *params) {
    int result = 1;
    unsigned char *k = checked_malloc(params->kappa_bytes);
    const unsigned char * const c1 = ct;
    const unsigned long long c1_len = (unsigned long long) (params->ct_size + params->kappa_bytes);
    const unsigned char * const c2 = ct + c1_len;
    const unsigned long c2_len = ct_len - c1_len;
    *m_len = 0;

    /* Check length, should be at least c1_len + 16 (for the DEM tag) */
    if (ct_len < (c1_len + 16U)) {
        fprintf(stderr, "Invalid ciphertext message: %llu < %llu\n", ct_len, c1_len + 16U);
        goto done_decrypt;
    }

    /* Determine k */
    r5_cca_kem_decapsulate_p(k, c1, sk, params);

    /* Apply DEM-inverse to get m */
    if (round5_dem_inverse(m, m_len, k, params->kappa_bytes, c2, c2_len)) {
        fprintf(stderr, "Failed to apply DEM-inverse\n");
        goto done_decrypt;
    }

    /* OK */
    result = 0;

done_decrypt:
    free(k);

    return result;
}
