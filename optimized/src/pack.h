/*
 * Copyright (c) 2020, Koninklijke Philips N.V.
 */

#include <stdint.h>
#include "r5_parameter_sets.h"

void pack_qp(uint8_t *pv, const modq_t *vq, const modq_t rounding_constant, size_t num_coeff, size_t size);
void unpack_p(modp_t *vp, const uint8_t *pv, size_t num_coeff);


