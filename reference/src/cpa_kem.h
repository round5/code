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
 * Declaration of the CPA KEM functions (NIST api).
 */

#ifndef _CPA_KEM_H_
#define _CPA_KEM_H_

#include "r5_parameter_sets.h"

#ifdef __cplusplus
extern "C" {
#endif

    /*
     * Conditionally provide the KEM NIST API functions.
     */

#if CRYPTO_CIPHERTEXTBYTES != 0

    /**
     * Generates a CPA KEM key pair. Uses the fixed parameter configuration.
     *
     * @param[out] pk public key
     * @param[out] sk secret key
     * @return __0__ in case of success
     */
    int crypto_kem_keypair(unsigned char *pk, unsigned char *sk);

    /**
     * CPA KEM encapsulate. Uses the fixed parameter configuration.
     *
     * @param[out] ct    key encapsulation message (ciphertext)
     * @param[out] k     shared secret
     * @param[in]  pk    public key with which the message is encapsulated
     * @return __0__ in case of success
     */
    int crypto_kem_enc(unsigned char *ct, unsigned char *k, const unsigned char *pk);

    /**
     * CPA KEM de-capsulate. Uses the fixed parameter configuration.
     *
     * @param[out] k     shared secret
     * @param[in]  ct    key encapsulation message (ciphertext)
     * @param[in]  sk    secret key with which the message is to be de-capsulated
     * @return __0__ in case of success
     */
    int crypto_kem_dec(unsigned char *k, const unsigned char *ct, const unsigned char *sk);

#endif

#ifdef __cplusplus
}
#endif

#endif /* CPA_KEM_H */
