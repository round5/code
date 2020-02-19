/*
 * Copyright (c) 2018, PQShield and Koninklijke Philips N.V.
 * Markku-Juhani O. Saarinen, Koninklijke Philips N.V.
 */

// Fast ring arithmetic (with cache attack countermeasures)

#include "ringmul.h"

#if PARAMS_K == 1 && defined(CM_CACHE)

#include "drbg.h"
#include "little_endian.h"

#include <string.h>


// multiplication mod q, result length n

void ringmul_q(modq_t d[PARAMS_N], modq_t a[PARAMS_N], tern_secret idx) {
    size_t i, j, k;
    modq_t p[PARAMS_N + 1];

    // Note: order of coefficients a[1..n] is reversed!
    // "lift" -- multiply by (x - 1)
    p[0] = (modq_t) (-a[0]);
    for (i = 1; i < PARAMS_N; i++) {
        p[PARAMS_N + 1 - i] = (modq_t) (a[i - 1] - a[i]);
    }
    p[1] = a[PARAMS_N - 1];

    // Initialize result
    memset(d, 0, PARAMS_N * sizeof (modq_t));

    for (i = 0; i < PARAMS_H / 2; i++) {
        // Modified to always scan the same ranges

        k = idx[i][0]; // positive coefficients
        d[0] = (modq_t) (d[0] + p[k]);
        for (j = 1; k > 0;) {
            d[j] = (modq_t) (d[j] + p[--k]);
            j++;
        }
        for (k = PARAMS_N + 1; j < PARAMS_N;) {
            d[j] = (modq_t) (d[j] + p[--k]);
            j++;
        }

        k = idx[i][1]; // negative coefficients
        d[0] = (modq_t) (d[0] - p[k]);
        for (j = 1; k > 0;) {
            d[j] = (modq_t) (d[j] - p[--k]);
            j++;
        }
        for (k = PARAMS_N + 1; j < PARAMS_N;) {
            d[j] = (modq_t) (d[j] - p[--k]);
            j++;
        }
    }

    // "unlift"
    d[0] = (uint16_t) (-d[0]);
    for (i = 1; i < PARAMS_N; ++i) {
        d[i] = (uint16_t) (d[i - 1] - d[i]);
    }
}

// multiplication mod p, result length mu

void ringmul_p(modp_t d[PARAMS_MU], modp_t a[PARAMS_N], tern_secret idx) {
    size_t i, j, k;
    modp_t p[PARAMS_N + 1];

    // Note: order of coefficients a[1..n] is reversed!
#if (PARAMS_XE == 0) && (PARAMS_F == 0)
    // Without error correction we "lift" -- i.e. multiply by (x - 1)
    p[0] = (modp_t) (-a[0]);
    for (i = 1; i < PARAMS_N; i++) {
        p[PARAMS_N + 1 - i] = (modp_t) (a[i - 1] - a[i]);
    }
    p[1] = a[PARAMS_N - 1];
#define SIZE_TMP_D PARAMS_N
#else
    // With error correction we do not "lift"
    p[0] = a[0];
    for (i = 2; i < PARAMS_N + 1; i++) {
        p[i] = a[PARAMS_N + 1 - i];
    }
    p[1] = 0;
    // Since we do not unlift at the end, we actually need to compute one element more.
#define SIZE_TMP_D (PARAMS_N+1)
#endif

    modp_t tmp_d[SIZE_TMP_D];

    // Initialize result
    memset(tmp_d, 0, SIZE_TMP_D * sizeof (modp_t));

    for (i = 0; i < PARAMS_H / 2; i++) {
        // Modified to always scan the same ranges

        k = idx[i][0]; // positive coefficients
        tmp_d[0] = (modp_t) (tmp_d[0] + p[k]);
        for (j = 1; k > 0;) {
            tmp_d[j] = (modp_t) (tmp_d[j] + p[--k]);
            j++;
        }
        for (k = PARAMS_N + 1; j < SIZE_TMP_D;) {
            tmp_d[j] = (modp_t) (tmp_d[j] + p[--k]);
            j++;
        }

        k = idx[i][1]; // negative coefficients
        tmp_d[0] = (modp_t) (tmp_d[0] - p[k]);
        for (j = 1; k > 0;) {
            tmp_d[j] = (modp_t) (tmp_d[j] - p[--k]);
            j++;
        }
        for (k = PARAMS_N + 1; j < SIZE_TMP_D;) {
            tmp_d[j] = (modp_t) (tmp_d[j] - p[--k]);
            j++;
        }
    }

#if (PARAMS_XE == 0) && (PARAMS_F == 0)
    // Without error correction we "lifted" so we now need to "unlift"
    tmp_d[0] = (modp_t) (-tmp_d[0]);
    for (i = 1; i < PARAMS_MU; ++i) {
        tmp_d[i] = (modp_t) (tmp_d[i - 1] - tmp_d[i]);
    }
    // Copy result
    memcpy(d, tmp_d, PARAMS_MU * sizeof (modp_t));
#else
    // Copy result, skipping the “additional” element
    memcpy(d, tmp_d + 1, PARAMS_MU * sizeof (modp_t));
#endif
}

#endif /* PARAMS_K == 1 && defined(CM_CACHE) */
