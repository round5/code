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
 * Declaration of the encryption functions used within the implementation.
 */

#ifndef PST_ENCRYPT_H
#define PST_ENCRYPT_H

#include "parameters.h"

#ifdef __cplusplus
extern "C" {
#endif

    /**
     * Generates a key pair. Uses the parameters as specified.
     *
     * @param[out] pk     public key
     * @param[out] sk     secret key
     * @param[in]  params the algorithm parameters to use
     * @return __0__ in case of success
     */
    int r5_cpa_pke_keygen(unsigned char *pk, unsigned char *sk, const parameters *params);

    /**
     * Encrypts a plaintext using the provided seed for R.
     *
     * @param[out] ct     ciphertext
     * @param[in]  pk     public key with which the message is encrypted
     * @param[in]  m      plaintext
     * @param[in]  rho    seed of R
     * @param[in]  params the algorithm parameters to use
     * @return __0__ in case of success
     */
    int r5_cpa_pke_encrypt(unsigned char *ct, const unsigned char *pk, const unsigned char *m, const unsigned char *rho, const parameters *params);

    /**
     * Decrypts a ciphertext.
     *
     * @param[out] m     plaintext
     * @param[in]  ct     ciphertext
     * @param[in]  sk    secret key with which the message is decrypted
     * @param[in]  params the algorithm parameters to use
     * @return __0__ in case of success
     */
    int r5_cpa_pke_decrypt(unsigned char *m, const unsigned char *sk, const unsigned char *ct, const parameters *params);

#ifdef __cplusplus
}
#endif

#endif /* PST_ENCRYPT_H */
