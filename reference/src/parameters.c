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
 * Implementation of the parameters, structure, and functions.
 */

#include "parameters.h"
#include "misc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


/*******************************************************************************
 * Private variables & functions
 ******************************************************************************/

/**
 * The algorithm parameters in case the NIST API functions are used.
 */
static parameters api_params;

/**
 * The parameter set number (see file `r5_parameter_sets.h`)
 * that corresponds to the settings as specified by the NIST API (i.e.
 * `CRYPTO_SECRETKEYBYTES`, `CRYPTO_PUBLICKEYBYTES`, `CRYPTO_BYTES`,
 * and `CRYPTO_CIPHERTEXTBYTES`).
 * -1 when the `api_params` have not yet been initialized.
 */
static int api_params_set_number = -1;

#ifdef DEBUG

/**
 * Checks the parameters that have been set.
 *
 * @param[in] params the algorithm parameters to check
 * @return __0__ if everything is correct, error code otherwise
 */
static int check_parameters(const parameters *params) {
    /* n must be either d or 1 and both must be > 0 */
    if (params->n == 0 || params->d == 0 || !(params->n == params->d || params->n == 1)) {
        fprintf(stderr, "Error: Incorrect parameters. ");
        fprintf(stderr, "n and d must be non zero and n must be equal to d or 1.\n");
        fprintf(stderr, "n=%u, d=%u\n", params->n, params->d);
        return 1;
    }
    /* Hamming weight must be even, > 0, and < d */
    if (params->h == 0 || params->h > params->d || params->h & 1) {
        fprintf(stderr, "Error: Incorrect parameter. ");
        fprintf(stderr, "Hamming weight h must be even, greater than, 0, and smaller than d.\n");
        fprintf(stderr, "h=%u, d=%u\n", params->h, params->d);
        return 2;
    }
    /* p, q, and t must be > 0 */
    /* q must be a power of 2 */
    /* p must be < q and a power of 2 */
    /* t must be < p */
    if (params->q_bits == 0 || params->p_bits == 0 || params->t_bits == 0 || ((uint32_t) (1 << params->p_bits)) >= params->q || params->t_bits >= params->p_bits) {
        fprintf(stderr, "Error: Incorrect parameters. ");
        fprintf(stderr, "q and p must be a power of 2, p must be smaller than q, t_bits must be less than p_bits\n");
        fprintf(stderr, "p_bits=%u, q_bits=%u, p=%u, q=%u, t_bits=%u\n", params->p_bits, params->q_bits, params->p, params->q, params->t_bits);
        return 3;
    }
    /* Dimensions must be > 0 */
    if (params->n_bar == 0 || params->m_bar == 0) {
        fprintf(stderr, "Error: Incorrect parameters. ");
        fprintf(stderr, "Dimensions n_bar and m_bar must be greater than 0.\n");
        fprintf(stderr, "n_bar=%u, m_bar=%u\n", params->n_bar, params->m_bar);
        return 4;
    }
    /* b_bits must be > 0, < p */
    if (params->b_bits == 0 || params->b_bits >= params->p_bits) {
        fprintf(stderr, "Error: Incorrect parameter. ");
        fprintf(stderr, "b_bits must be greater than 0, smaller than p_bits.\n");
        fprintf(stderr, "b_bits=%u\n", params->b_bits);
        return 5;
    }
    /* Seed size must be > 0 */
    if (params->kappa_bytes == 0) {
        fprintf(stderr, "Error: Incorrect parameter. ");
        fprintf(stderr, "Seed size must be greater than 0.\n");
        fprintf(stderr, "kappa_bytes=%u\n", params->kappa_bytes);
        return 6;
    }

    /* tau must be 0, 1, or 2 for non-ring, 0 for ring */
    if (params->k == 1 && params->tau != 0) {
        fprintf(stderr, "Error: Incorrect parameter. ");
        fprintf(stderr, "tau must be 0 for ring parameter sets\n");
        fprintf(stderr, "tau=%u\n", params->tau);
        return 7;
    }
    if (params->k != 1 && params->tau > 2) {
        fprintf(stderr, "Error: Incorrect parameter. ");
        fprintf(stderr, "tau must be 0, 1, or 2 for non-ring parameter sets\n");
        fprintf(stderr, "tau=%u\n", params->tau);
        return 7;
    }

    return 0;
}

#endif

/*******************************************************************************
 * Public functions
 ******************************************************************************/

uint32_t get_crypto_secret_key_bytes(const parameters *params, const int is_cca_or_encrypt) {
    return is_cca_or_encrypt ? ((uint32_t) params->kappa_bytes + (uint32_t) params->kappa_bytes + params->pk_size) : params->kappa_bytes;
}

uint32_t get_crypto_public_key_bytes(const parameters *params) {
    return params->pk_size;
}

uint16_t get_crypto_bytes(const parameters *params, const int is_encrypt) {
    return is_encrypt ? (uint16_t) (params->ct_size + params->kappa_bytes + 16) : params->kappa_bytes;
}

uint16_t get_crypto_cipher_text_bytes(const parameters *params, const int is_cca, const int is_encrypt) {
    return is_encrypt ? 0U : (uint16_t) (params->ct_size + (is_cca ? params->kappa_bytes : 0U));
}

uint16_t get_crypto_seed_bytes(const parameters *params) {
    return params->kappa_bytes;
}

parameters *set_parameters_from_api() {
    if (api_params_set_number >= 0) {
        return &api_params;
    }

    api_params_set_number = ROUND5_API_SET;

    /* Set up parameters from set */
    int err;

    /* Algorithm parameters */
    uint8_t kappa_bytes;
    uint16_t d;
    uint16_t n;
    uint16_t h;
    uint8_t q_bits;
    uint8_t p_bits;
    uint8_t t_bits;
    uint16_t n_bar;
    uint16_t m_bar;
    uint8_t b_bits;
    uint8_t f;
    uint8_t xe;

    kappa_bytes = (uint8_t) r5_parameter_sets[api_params_set_number][POS_KAPPA_BYTES];
    d = (uint16_t) r5_parameter_sets[api_params_set_number][POS_D];
    n = (uint16_t) r5_parameter_sets[api_params_set_number][POS_N];
    h = (uint16_t) r5_parameter_sets[api_params_set_number][POS_H];
    q_bits = (uint8_t) r5_parameter_sets[api_params_set_number][POS_Q_BITS];
    p_bits = (uint8_t) r5_parameter_sets[api_params_set_number][POS_P_BITS];
    t_bits = (uint8_t) r5_parameter_sets[api_params_set_number][POS_T_BITS];
    n_bar = (uint16_t) r5_parameter_sets[api_params_set_number][POS_N_BAR];
    m_bar = (uint16_t) r5_parameter_sets[api_params_set_number][POS_M_BAR];
    b_bits = (uint8_t) r5_parameter_sets[api_params_set_number][POS_B_BITS];
    f = (uint8_t) r5_parameter_sets[api_params_set_number][POS_F];
    xe = (uint8_t) r5_parameter_sets[api_params_set_number][POS_XE];

    err = set_parameters(&api_params, ROUND5_API_TAU, kappa_bytes, d, n, h, q_bits, p_bits, t_bits, b_bits, n_bar, m_bar, f, xe);

#ifdef DEBUG
    if (!err) {
        /* Sanity check of derived NIST parameters */
        const int is_cca = (CRYPTO_SECRETKEYBYTES == get_crypto_secret_key_bytes(&api_params, 1) || CRYPTO_CIPHERTEXTBYTES == get_crypto_cipher_text_bytes(&api_params, 1, 0));
        const int is_encrypt = CRYPTO_CIPHERTEXTBYTES == 0;
        if (CRYPTO_SECRETKEYBYTES != get_crypto_secret_key_bytes(&api_params, is_cca || is_encrypt)) {
            if (is_cca || is_encrypt) {
                fprintf(stderr, "NIST parameters do not match: CRYPTO_SECRETKEYBYTES(%u) != sk_size(%u) + kappa_bytes(%u) + pk_size(%u) = %u\n",
                        CRYPTO_SECRETKEYBYTES, api_params.kappa_bytes, api_params.kappa_bytes, api_params.pk_size, get_crypto_secret_key_bytes(&api_params, is_cca || is_encrypt));
            } else {
                fprintf(stderr, "NIST parameters do not match: CRYPTO_SECRETKEYBYTES(%u) != sk_size(%u)\n", CRYPTO_SECRETKEYBYTES, get_crypto_secret_key_bytes(&api_params, is_cca || is_encrypt));
            }
            err += 2;
        }
        if (CRYPTO_PUBLICKEYBYTES != get_crypto_public_key_bytes(&api_params)) {
            fprintf(stderr, "NIST parameters do not match: CRYPTO_PUBLICKEYBYTES(%u) != pk_size(%u)\n", CRYPTO_PUBLICKEYBYTES, api_params.pk_size);
            err += 4;
        }
        if (CRYPTO_BYTES != get_crypto_bytes(&api_params, is_encrypt)) {
            if (is_encrypt) {
                fprintf(stderr, "NIST parameters do not match: CRYPTO_BYTES(%u) != ct_size(%u) + kappa_bytes(%u) + 16 = %u\n", CRYPTO_BYTES, api_params.ct_size, api_params.kappa_bytes, get_crypto_bytes(&api_params, is_encrypt));
            } else {
                fprintf(stderr, "NIST parameters do not match: CRYPTO_BYTES(%u) != kappa_bytes(%u)\n", CRYPTO_BYTES, get_crypto_bytes(&api_params, is_encrypt));
            }
            err += 8;
        }
        if (CRYPTO_CIPHERTEXTBYTES != get_crypto_cipher_text_bytes(&api_params, is_cca, is_encrypt)) {
            if (is_encrypt) {
                fprintf(stderr, "NIST parameters do not match: CRYPTO_CIPHERTEXTBYTES(%u) != %u\n", CRYPTO_CIPHERTEXTBYTES, get_crypto_cipher_text_bytes(&api_params, is_cca, is_encrypt));
            } else if (is_cca) {
                fprintf(stderr, "NIST parameters do not match: CRYPTO_CIPHERTEXTBYTES(%u) != ct_size(%u) + kappa_bytes(%u) = %u\n", CRYPTO_CIPHERTEXTBYTES, api_params.ct_size, api_params.kappa_bytes, get_crypto_cipher_text_bytes(&api_params, is_cca, is_encrypt));
            } else {
                fprintf(stderr, "NIST parameters do not match: CRYPTO_CIPHERTEXTBYTES(%u) != ct_size(%u)\n", CRYPTO_CIPHERTEXTBYTES, get_crypto_cipher_text_bytes(&api_params, is_cca, is_encrypt));
            }
            err += 16;
        }
    }
#endif

    if (err) {
        api_params_set_number = -1;
        return NULL;
    } else {
        return &api_params;
    }

}

int set_parameters(parameters *params, const uint8_t tau, const uint8_t kappa_bytes, const uint16_t d, const uint16_t n, const uint16_t h, const uint8_t q_bits, const uint8_t p_bits, const uint8_t t_bits, const uint8_t b_bits, const uint16_t n_bar, const uint16_t m_bar, const uint8_t f, const uint8_t xe) {
    params->kappa_bytes = kappa_bytes;
    params->d = d;
    params->n = n;
    params->h = h;
    params->q_bits = q_bits;
    params->p_bits = p_bits;
    params->t_bits = t_bits;
    params->b_bits = b_bits;
    params->n_bar = n_bar;
    params->m_bar = m_bar;
    params->f = f;
    params->xe = xe;

    /* Derived parameters */
    params->kappa = (uint16_t) (8 * kappa_bytes);
    params->k = (uint16_t) (n ? d / n : 0); /* Avoid arithmetic exception if n = 0 */
    params->mu = (uint16_t) (b_bits ? CEIL_DIV((params->kappa + params->xe), b_bits) : 0); /* Avoid arithmetic exception if B = 0 */
    params->q = (uint32_t) (1U << q_bits);
    params->p = (uint16_t) (1U << p_bits);

    /* Message sizes */
    params->pk_size = (uint32_t) (kappa_bytes + BITS_TO_BYTES(d * n_bar * p_bits));
    params->ct_size = (uint16_t) (BITS_TO_BYTES(d * m_bar * p_bits) + BITS_TO_BYTES(params->mu * t_bits));

    /* Rounding constants */
    params->z_bits = (uint16_t) (params->q_bits - params->p_bits + params->t_bits);
    if (params->z_bits < params->p_bits) {
        params->z_bits = params->p_bits;
    }
    params->h1 = (uint16_t) ((uint16_t) 1 << (params->q_bits - params->p_bits - 1));
    params->h2 = (uint16_t) (1 << (params->q_bits - params->z_bits - 1));
    params->h3 = (uint16_t) ((uint16_t) (1 << (params->p_bits - params->t_bits - 1)) + (uint16_t) (1 << (params->p_bits - params->b_bits - 1)) - (uint16_t) (1 << (params->q_bits - params->z_bits - 1)));

    /* tau */
    set_parameter_tau(params, tau);

#ifdef DEBUG
    return check_parameters(params);
#else
    return 0;
#endif
}

void set_parameter_tau(parameters *params, const uint8_t tau) {
    params->tau = params->k == 1 ? 0 : tau;
}
