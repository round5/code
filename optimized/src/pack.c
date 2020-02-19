
/*
 * Copyright (c) 2020, Koninklijke Philips N.V.
 */

#include "pack.h"
#include "r5_parameter_sets.h"

#include <stdint.h>
#include <string.h>

void pack_qp(uint8_t *pv, const modq_t *vq, const modq_t rounding_constant, size_t num_coeff, size_t size) {
#if (PARAMS_P_BITS == 8)
    size_t i;
    
    for (i = 0; i < num_coeff; i++) {
        pv[i] = (uint8_t) (((vq[i] + rounding_constant) >> (PARAMS_Q_BITS - PARAMS_P_BITS)) & (PARAMS_P - 1));
    }
#else
    size_t i, j;
    modp_t t;
    
    memset(pv, 0, size);
    j = 0;
    for (i = 0; i < num_coeff; i++) {
        t = ((vq[i] + rounding_constant) >> (PARAMS_Q_BITS - PARAMS_P_BITS)) & (PARAMS_P - 1);
        pv[j >> 3] = (uint8_t) (pv[j >> 3] | (t << (j & 7))); // pack p bits
        if ((j & 7) + PARAMS_P_BITS > 8) {
            pv[(j >> 3) + 1] |= (uint8_t) (t >> (8 - (j & 7)));
            if ((j & 7) + PARAMS_P_BITS > 16) {
                pv[(j >> 3) + 2] |= (uint8_t) (t >> (16 - (j & 7)));
            }
            
        }
        j += PARAMS_P_BITS;
    }
#endif
}

void unpack_p(modp_t *vp, const uint8_t *pv, size_t num_coeff) {
    
    // memcpy(vp, pv, PARAMS_N) can be used if PARAMS_P_BITS == 8
    size_t i, j;
    modp_t t;
    
    j = 0;
    for (i = 0; i < num_coeff; i++) {
        t = (modp_t) (pv[j >> 3] >> (j & 7)); // unpack p bits
        if ((j & 7) + PARAMS_P_BITS > 8) {
            t |=  ((modp_t) pv[(j >> 3) + 1]) << (8 - (j & 7));
            if ((j & 7) + PARAMS_P_BITS > 16) {
                t |= (modp_t)(pv[(j >> 3) + 2] << (16 - (j & 7)));
            }
            
        }
        vp[i] = t & (PARAMS_P - 1);
        j += PARAMS_P_BITS;
    }
}
