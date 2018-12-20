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
 * algorithm (NIST api).
 */

#include "cca_encrypt.h"
#include "r5_cca_pke.h"

#include <stdlib.h>

/*******************************************************************************
 * Public functions
 ******************************************************************************/

#if CRYPTO_CIPHERTEXTBYTES == 0

int crypto_encrypt_keypair(unsigned char *pk, unsigned char *sk) {
    parameters * params;
    if ((params = set_parameters_from_api()) == NULL) {
        exit(EXIT_FAILURE);
    }
    return r5_cca_pke_keygen_p(pk, sk, params);
}

int crypto_encrypt(unsigned char *ct, unsigned long long *ct_len, const unsigned char *m, const unsigned long long m_len, const unsigned char *pk) {
    parameters * params;
    if ((params = set_parameters_from_api()) == NULL) {
        exit(EXIT_FAILURE);
    }
    return r5_cca_pke_encrypt_p(ct, ct_len, m, m_len, pk, params);
}

int crypto_encrypt_open(unsigned char *m, unsigned long long *m_len, const unsigned char *ct, const unsigned long long ct_len, const unsigned char *sk) {
    parameters * params;
    if ((params = set_parameters_from_api()) == NULL) {
        exit(EXIT_FAILURE);
    }
    return r5_cca_pke_decrypt_p(m, m_len, ct, ct_len, sk, params);
}

#endif /* CRYPTO_CIPHERTEXTBYTES */
