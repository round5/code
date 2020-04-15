/*
 * Copyright (c) 2020, PQShield and Koninklijke Philips N.V.
 * Markku-Juhani O. Saarinen, Koninklijke Philips N.V.
 */

#ifndef secretkeygen_h
#define secretkeygen_h

#include "r5_parameter_sets.h"

void create_secret_vector_s(tern_secret secret_vector, const uint8_t *seed);
void create_secret_vector_r(tern_secret secret_vector, const uint8_t *seed);
void create_secret_matrix_s_t(tern_secret_s secret_vector, const uint8_t *seed);
void create_secret_matrix_r_t(tern_secret_r secret_vector, const uint8_t *seed);

#endif /* secretkeygen_h */

