/*
 * Copyright (c) 2018, Koninklijke Philips N.V.
 */

/**
 * @file
 * Implementation of the parameters, structure, and functions.
 */

#include "chooseparameters.h"
#include "misc.h"

#include <assert.h>
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

/*******************************************************************************
 * Public functions
 ******************************************************************************/

uint32_t get_crypto_secret_key_bytes(const parameters *params, const int is_cca_or_encrypt) {
    return is_cca_or_encrypt ? ((uint32_t) PARAMS_KAPPA_BYTES + (uint32_t) PARAMS_KAPPA_BYTES + PARAMS_PK_SIZE) : PARAMS_KAPPA_BYTES;
}

uint32_t get_crypto_public_key_bytes(const parameters *params) {
    return PARAMS_PK_SIZE;
}

uint16_t get_crypto_bytes(const parameters *params, const int is_encrypt) {
    return is_encrypt ? (uint16_t) (PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES + 16) : PARAMS_KAPPA_BYTES;
}

uint16_t get_crypto_cipher_text_bytes(const parameters *params, const int is_cca, const int is_encrypt) {
    return is_encrypt ? 0U : (uint16_t) (PARAMS_CT_SIZE + (is_cca ? PARAMS_KAPPA_BYTES : 0U));
}

uint16_t get_crypto_seed_bytes(const parameters *params) {
    return PARAMS_KAPPA_BYTES;
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

    err = set_parameters(&api_params, ROUND5_API_TAU, ROUND5_API_TAU2_LEN, kappa_bytes, d, n, h, q_bits, p_bits, t_bits, b_bits, n_bar, m_bar, f, xe);

#ifdef DEBUG
    if (!err) {
        /* Sanity check of derived NIST parameters */
        const int is_cca = (CRYPTO_SECRETKEYBYTES == get_crypto_secret_key_bytes(&api_params, 1) || CRYPTO_CIPHERTEXTBYTES == get_crypto_cipher_text_bytes(&api_params, 1, 0));
        const int is_encrypt = CRYPTO_CIPHERTEXTBYTES == 0;
        if (CRYPTO_SECRETKEYBYTES != get_crypto_secret_key_bytes(&api_params, is_cca || is_encrypt)) {
            if (is_cca || is_encrypt) {
                DEBUG_ERROR("NIST parameters do not match: CRYPTO_SECRETKEYBYTES(%u) != sk_size(%u) + kappa_bytes(%u) + pk_size(%u) = %u\n",
                        CRYPTO_SECRETKEYBYTES, api_params.kappa_bytes, api_params.kappa_bytes, api_params.pk_size, get_crypto_secret_key_bytes(&api_params, is_cca || is_encrypt));
            } else {
                DEBUG_ERROR("NIST parameters do not match: CRYPTO_SECRETKEYBYTES(%u) != sk_size(%u)\n", CRYPTO_SECRETKEYBYTES, get_crypto_secret_key_bytes(&api_params, is_cca || is_encrypt));
            }
            err += 2;
        }
        if (CRYPTO_PUBLICKEYBYTES != get_crypto_public_key_bytes(&api_params)) {
            DEBUG_ERROR("NIST parameters do not match: CRYPTO_PUBLICKEYBYTES(%u) != pk_size(%u)\n", CRYPTO_PUBLICKEYBYTES, api_params.pk_size);
            err += 4;
        }
        if (CRYPTO_BYTES != get_crypto_bytes(&api_params, is_encrypt)) {
            if (is_encrypt) {
                DEBUG_ERROR("NIST parameters do not match: CRYPTO_BYTES(%u) != ct_size(%u) + kappa_bytes(%u) + 16 = %u\n", CRYPTO_BYTES, api_params.ct_size, api_params.kappa_bytes, get_crypto_bytes(&api_params, is_encrypt));
            } else {
                DEBUG_ERROR("NIST parameters do not match: CRYPTO_BYTES(%u) != kappa_bytes(%u)\n", CRYPTO_BYTES, get_crypto_bytes(&api_params, is_encrypt));
            }
            err += 8;
        }
        if (CRYPTO_CIPHERTEXTBYTES != get_crypto_cipher_text_bytes(&api_params, is_cca, is_encrypt)) {
            if (is_encrypt) {
                DEBUG_ERROR("NIST parameters do not match: CRYPTO_CIPHERTEXTBYTES(%u) != %u\n", CRYPTO_CIPHERTEXTBYTES, get_crypto_cipher_text_bytes(&api_params, is_cca, is_encrypt));
            } else if (is_cca) {
                DEBUG_ERROR("NIST parameters do not match: CRYPTO_CIPHERTEXTBYTES(%u) != ct_size(%u) + kappa_bytes(%u) = %u\n", CRYPTO_CIPHERTEXTBYTES, api_params.ct_size, api_params.kappa_bytes, get_crypto_cipher_text_bytes(&api_params, is_cca, is_encrypt));
            } else {
                DEBUG_ERROR("NIST parameters do not match: CRYPTO_CIPHERTEXTBYTES(%u) != ct_size(%u)\n", CRYPTO_CIPHERTEXTBYTES, get_crypto_cipher_text_bytes(&api_params, is_cca, is_encrypt));
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

int set_parameters(parameters *params, const uint8_t tau, const uint32_t tau2_len, const uint8_t kappa_bytes, const uint16_t d, const uint16_t n, const uint16_t h, const uint8_t q_bits, const uint8_t p_bits, const uint8_t t_bits, const uint8_t b_bits, const uint16_t n_bar, const uint16_t m_bar, const uint8_t f, const uint8_t xe) {
    PARAMS_KAPPA_BYTES = kappa_bytes;
    PARAMS_D = d;
    PARAMS_N = n;
    PARAMS_H = h;
    PARAMS_Q_BITS = q_bits;
    PARAMS_P_BITS = p_bits;
    PARAMS_T_BITS = t_bits;
    PARAMS_B_BITS = b_bits;
    PARAMS_N_BAR = n_bar;
    PARAMS_M_BAR = m_bar;
    PARAMS_F = f;
    PARAMS_XE = xe;

    /* Derived parameters */
    PARAMS_KAPPA = (uint16_t) (8 * kappa_bytes);
    PARAMS_K = (uint16_t) (n ? d / n : 0); /* Avoid arithmetic exception if n = 0 */
    PARAMS_MU = (uint16_t) (b_bits ? CEIL_DIV((PARAMS_KAPPA + PARAMS_XE), b_bits) : 0); /* Avoid arithmetic exception if B = 0 */
    PARAMS_Q = (uint32_t) (1U << q_bits);
    PARAMS_P = (uint16_t) (1U << p_bits);

    /* Message sizes */
    PARAMS_PK_SIZE = (uint32_t) (kappa_bytes + BITS_TO_BYTES(d * n_bar * p_bits));
    PARAMS_CT_SIZE = (uint16_t) (BITS_TO_BYTES(d * m_bar * p_bits) + BITS_TO_BYTES(PARAMS_MU * t_bits));

    /* Rounding constants */
    params->z_bits = (uint16_t) (PARAMS_Q_BITS - PARAMS_P_BITS + PARAMS_T_BITS);
    if (params->z_bits < PARAMS_P_BITS) {
        params->z_bits = PARAMS_P_BITS;
    }
    PARAMS_H1 = (uint16_t) ((uint16_t) 1 << (PARAMS_Q_BITS - PARAMS_P_BITS - 1));
    PARAMS_H2 = (uint16_t) (1 << (PARAMS_Q_BITS - params->z_bits - 1));
    PARAMS_H3 = (uint16_t) ((uint16_t) (1 << (PARAMS_P_BITS - PARAMS_T_BITS - 1)) + (uint16_t) (1 << (PARAMS_P_BITS - PARAMS_B_BITS - 1)) - (uint16_t) (1 << (PARAMS_Q_BITS - params->z_bits - 1)));

    /* n must be either d or 1 and both must be > 0 */
    assert(PARAMS_N != 0 && PARAMS_D != 0 && (PARAMS_N == PARAMS_D || PARAMS_N == 1));
    /* Hamming weight must be even, > 0, and < d */
    assert(PARAMS_H != 0 && PARAMS_H <= PARAMS_D && !(PARAMS_H & 1));
    /* p, q, and t must be > 0 and power of 2 */
    /* p must be < q */
    /* t must be < p */
    assert(PARAMS_Q_BITS > 0 && PARAMS_P_BITS > 0 && PARAMS_T_BITS > 0 && PARAMS_P_BITS < PARAMS_Q_BITS && PARAMS_T_BITS < PARAMS_P_BITS);
    /* Dimensions must be > 0 */
    assert(PARAMS_N_BAR > 0 && PARAMS_M_BAR > 0);
    /* b must be > 0, < p */
    assert(PARAMS_B_BITS > 0 && PARAMS_B_BITS < PARAMS_P_BITS);
    /* Seed size must be > 0 */
    assert(PARAMS_KAPPA_BYTES > 0);

    /* tau */
    set_parameter_tau(params, tau);

    /* tau2 length */
    set_parameter_tau2_len(params, tau2_len);

    return 0;
}

void set_parameter_tau(parameters *params, const uint8_t tau) {
    PARAMS_TAU = PARAMS_K == 1 ? 0 : tau;

    /* tau must be 0, 1, or 2 for non-ring, 0 for ring (but this is actually already enforced) */
    assert(PARAMS_TAU <= 2 && (PARAMS_K != 1 || PARAMS_TAU == 0));
}

void set_parameter_tau2_len(parameters *params, const uint32_t tau2_len) {
    if (tau2_len == 0) {
        PARAMS_TAU2_LEN = 1 << 11;
    } else {
        PARAMS_TAU2_LEN = tau2_len;
    }

    /* For non-ring, tau2_len must be a power of two and larger than or equal to d */
    assert(PARAMS_K == 1 || (PARAMS_TAU2_LEN >= PARAMS_D && (PARAMS_TAU2_LEN & (PARAMS_TAU2_LEN - 1)) == 0));
}
