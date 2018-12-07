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
 * Implementation of the encrypt and decrypt functions based on the CCA KEM.
 * algorithm.
 */

#include "api.h"

#include "r5_cca_kem.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "r5_dem.h"
#include "r5_hash.h"
#include "misc.h"
#include "rng.h"

/*******************************************************************************
 * Public functions
 ******************************************************************************/

#ifdef ROUND5_CCA_PKE

int crypto_encrypt_keypair(unsigned char *pk, unsigned char *sk) {
    return r5_cca_kem_keygen(pk, sk);
}

int crypto_encrypt(unsigned char *ct, unsigned long long *ct_len, const unsigned char *m, const unsigned long long m_len, const unsigned char *pk) {
    int result = 1;
    const unsigned long long c1_len = PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES;
    unsigned char c1[PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES];
    unsigned long long c2_len;
    unsigned char k[PARAMS_KAPPA_BYTES];

    /* Determine c1 and k */
    r5_cca_kem_encapsulate(c1, k, pk);

    /* Copy c1 into first part of ct */
    memcpy(ct, c1, c1_len);
    *ct_len = c1_len;

    /* Apply DEM to get second part of ct */
    if (round5_dem(ct + c1_len, &c2_len, k, PARAMS_KAPPA_BYTES, m, m_len)) {
        fprintf(stderr, "Failed to apply DEM\n");
        goto done_encrypt;
    }
    *ct_len += c2_len;

    /* All OK */
    result = 0;

done_encrypt:

    return result;
}

int crypto_encrypt_open(unsigned char *m, unsigned long long *m_len, const unsigned char *ct, unsigned long long ct_len, const unsigned char *sk) {
    int result = 1;
    unsigned char k[PARAMS_KAPPA_BYTES];
    const unsigned char * const c1 = ct;
    const unsigned long long c1_len = PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES;
    const unsigned char * const c2 = ct + c1_len;
    const unsigned long c2_len = ct_len - c1_len;

    /* Check length, should be at least c1_len + 16 (for the DEM tag) */
    if (ct_len < (c1_len + 16U)) {
        fprintf(stderr, "Invalid ciphertext message: %llu < %llu\n", ct_len, c1_len + 16U);
        goto done_decrypt;
    }

    /* Determine k */
    r5_cca_kem_decapsulate(k, c1, sk);

    /* Apply DEM-inverse to get m */
    if (round5_dem_inverse(m, m_len, k, PARAMS_KAPPA_BYTES, c2, c2_len)) {
        fprintf(stderr, "Failed to apply DEM-inverse\n");
        goto done_decrypt;
    }

    /* OK */
    result = 0;

done_decrypt:

    return result;
}

#endif /* ROUND5_CCA_PKE */
