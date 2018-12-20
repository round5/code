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
 * Declaration of the random bytes functions.
 */

#ifndef RNG_H
#define RNG_H

#ifdef __cplusplus
extern "C" {
#endif

    /**
     * Initializes the random number generator used for generating the random
     * bytes.
     *
     * @param[in] entropy_input the bytes to use as input entropy (48 bytes)
     * @param[in] personalization_string an optional personalization string (48 bytes)
     * @param[in] security_strength parameter to specify the security strength of the random bytes
     */
    void randombytes_init(unsigned char *entropy_input, unsigned char *personalization_string, int security_strength);

    /**
     * Generates a sequence of random bytes.
     *
     * @param[out] x destination of the random bytes
     * @param[in] xlen the number of random bytes
     * @return _0_ in case of success, non-zero otherwise
     */
    int randombytes(unsigned char *x, unsigned long long xlen);

#ifdef __cplusplus
}
#endif

#endif /* RNG_H */
