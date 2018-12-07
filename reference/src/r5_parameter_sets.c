/*
 * Copyright (c) 2018, Koninklijke Philips N.V.
 * Hayo Baan, Jose Luis Torre Arce, Sauvik Bhattacharya
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
 * Definition of the (internal) Round5 parameter set variables.
 */

#include "r5_parameter_sets.h"

/** The Round5 parameter set parameter values. */
const uint32_t r5_parameter_sets[81][16] = {
    /* C_SK, C_PK, C_B, C_CT, kappa_bytes, d, n, h, q_bits, p_bits, t_bits, b_bits, n_bar, m_bar, f, xe */
    {16, 634, 16, 682, 16, 618, 618, 104, 11, 8, 4, 1, 1, 1, 0U, 0}, /* R5ND_1KEM_0c */
    {24, 909, 24, 981, 24, 786, 786, 384, 13, 9, 4, 1, 1, 1, 0U, 0}, /* R5ND_3KEM_0c */
    {32, 1178, 32, 1274, 32, 1018, 1018, 428, 14, 9, 4, 1, 1, 1, 0U, 0}, /* R5ND_5KEM_0c */
    {708, 676, 756, 0, 16, 586, 586, 182, 13, 9, 4, 1, 1, 1, 0U, 0}, /* R5ND_1PKE_0c */
    {1031, 983, 1119, 0, 24, 852, 852, 212, 12, 9, 5, 1, 1, 1, 0U, 0}, /* R5ND_3PKE_0c */
    {1413, 1349, 1525, 0, 32, 1170, 1170, 222, 13, 9, 5, 1, 1, 1, 0U, 0}, /* R5ND_5PKE_0c */
    {16, 445, 16, 549, 16, 490, 490, 162, 10, 7, 3, 1, 1, 1, 5U, 190}, /* R5ND_1KEM_5c */
    {24, 780, 24, 859, 24, 756, 756, 242, 12, 8, 2, 1, 1, 1, 5U, 218}, /* R5ND_3KEM_5c */
    {32, 972, 32, 1063, 32, 940, 940, 414, 12, 8, 2, 1, 1, 1, 5U, 234}, /* R5ND_5KEM_5c */
    {493, 461, 636, 0, 16, 508, 508, 136, 10, 7, 4, 1, 1, 1, 5U, 190}, /* R5ND_1PKE_5c */
    {828, 780, 950, 0, 24, 756, 756, 242, 12, 8, 3, 1, 1, 1, 5U, 218}, /* R5ND_3PKE_5c */
    {1036, 972, 1172, 0, 32, 940, 940, 414, 12, 8, 3, 1, 1, 1, 5U, 234}, /* R5ND_5PKE_5c */
    {16, 5214, 16, 5236, 16, 594, 1, 238, 13, 10, 7, 3, 7, 7, 0U, 0}, /* R5N1_1KEM_0c */
    {24, 8834, 24, 8866, 24, 881, 1, 238, 13, 10, 7, 3, 8, 8, 0U, 0}, /* R5N1_3KEM_0c */
    {32, 14264, 32, 14288, 32, 1186, 1, 712, 15, 12, 7, 4, 8, 8, 0U, 0}, /* R5N1_5KEM_0c */
    {5772, 5740, 5804, 0, 16, 636, 1, 114, 12, 9, 6, 2, 8, 8, 0U, 0}, /* R5N1_1PKE_0c */
    {9708, 9660, 9732, 0, 24, 876, 1, 446, 15, 11, 7, 3, 8, 8, 0U, 0}, /* R5N1_3PKE_0c */
    {14700, 14636, 14724, 0, 32, 1217, 1, 462, 15, 12, 9, 4, 8, 8, 0U, 0}, /* R5N1_5PKE_0c */
    {16, 342, 16, 394, 16, 372, 372, 178, 11, 7, 3, 1, 1, 1, 2U, 53}, /* R5ND_0KEM_2iot */
    {24, 453, 24, 563, 24, 490, 490, 162, 10, 7, 3, 1, 1, 1, 4U, 163}, /* R5ND_1KEM_4longkey */
    {163584, 163536, 988, 0, 24, 757, 1, 378, 14, 9, 4, 1, 192, 1, 0U, 0}, /* R5N1_3PKE_0smallCT */
    {16, 716, 16, 764, 16, 800, 800, 170, 11, 7, 4, 1, 1, 1, 0U, 0}, /* R5ND_0KEM_0fail_phi_0 */
    {16, 716, 16, 764, 16, 800, 800, 180, 11, 7, 4, 1, 1, 1, 0U, 0}, /* R5ND_0KEM_0fail_phi_1 */
    {16, 716, 16, 764, 16, 800, 800, 200, 11, 7, 4, 1, 1, 1, 0U, 0}, /* R5ND_0KEM_0fail_phi_2 */
    {16, 716, 16, 764, 16, 800, 800, 220, 11, 7, 4, 1, 1, 1, 0U, 0}, /* R5ND_0KEM_0fail_phi_3 */
    {16, 716, 16, 764, 16, 800, 800, 250, 11, 7, 4, 1, 1, 1, 0U, 0}, /* R5ND_0KEM_0fail_phi_4 */
    {16, 716, 16, 764, 16, 800, 800, 270, 11, 7, 4, 1, 1, 1, 0U, 0}, /* R5ND_0KEM_0fail_phi_5 */
    {16, 716, 16, 764, 16, 800, 800, 300, 11, 7, 4, 1, 1, 1, 0U, 0}, /* R5ND_0KEM_0fail_phi_6 */
    {16, 716, 16, 764, 16, 800, 800, 320, 11, 7, 4, 1, 1, 1, 0U, 0}, /* R5ND_0KEM_0fail_phi_7 */
    {16, 716, 16, 764, 16, 800, 800, 350, 11, 7, 4, 1, 1, 1, 0U, 0}, /* R5ND_0KEM_0fail_phi_8 */
    {16, 716, 16, 764, 16, 800, 800, 370, 11, 7, 4, 1, 1, 1, 0U, 0}, /* R5ND_0KEM_0fail_phi_9 */
    {16, 716, 16, 764, 16, 800, 800, 400, 11, 7, 4, 1, 1, 1, 0U, 0}, /* R5ND_0KEM_0fail_phi_10 */
    {16, 716, 16, 764, 16, 800, 800, 420, 11, 7, 4, 1, 1, 1, 0U, 0}, /* R5ND_0KEM_0fail_phi_11 */
    {16, 716, 16, 764, 16, 800, 800, 440, 11, 7, 4, 1, 1, 1, 0U, 0}, /* R5ND_0KEM_0fail_phi_12 */
    {16, 716, 16, 764, 16, 800, 800, 450, 11, 7, 4, 1, 1, 1, 0U, 0}, /* R5ND_0KEM_0fail_phi_13 */
    {16, 716, 16, 764, 16, 800, 800, 470, 11, 7, 4, 1, 1, 1, 0U, 0}, /* R5ND_0KEM_0fail_phi_14 */
    {16, 716, 16, 764, 16, 800, 800, 500, 11, 7, 4, 1, 1, 1, 0U, 0}, /* R5ND_0KEM_0fail_phi_15 */
    {16, 716, 16, 764, 16, 800, 800, 520, 11, 7, 4, 1, 1, 1, 0U, 0}, /* R5ND_0KEM_0fail_phi_16 */
    {16, 716, 16, 764, 16, 800, 800, 540, 11, 7, 4, 1, 1, 1, 0U, 0}, /* R5ND_0KEM_0fail_phi_17 */
    {16, 716, 16, 764, 16, 800, 800, 550, 11, 7, 4, 1, 1, 1, 0U, 0}, /* R5ND_0KEM_0fail_phi_18 */
    {16, 716, 16, 764, 16, 800, 800, 570, 11, 7, 4, 1, 1, 1, 0U, 0}, /* R5ND_0KEM_0fail_phi_19 */
    {16, 716, 16, 764, 16, 800, 800, 590, 11, 7, 4, 1, 1, 1, 0U, 0}, /* R5ND_0KEM_0fail_phi_20 */
    {16, 716, 16, 764, 16, 800, 800, 600, 11, 7, 4, 1, 1, 1, 0U, 0}, /* R5ND_0KEM_0fail_phi_21 */
    {16, 716, 16, 764, 16, 800, 800, 620, 11, 7, 4, 1, 1, 1, 0U, 0}, /* R5ND_0KEM_0fail_phi_22 */
    {16, 716, 16, 764, 16, 800, 800, 640, 11, 7, 4, 1, 1, 1, 0U, 0}, /* R5ND_0KEM_0fail_phi_23 */
    {16, 716, 16, 764, 16, 800, 800, 650, 11, 7, 4, 1, 1, 1, 0U, 0}, /* R5ND_0KEM_0fail_phi_24 */
    {16, 716, 16, 764, 16, 800, 800, 670, 11, 7, 4, 1, 1, 1, 0U, 0}, /* R5ND_0KEM_0fail_phi_25 */
    {16, 716, 16, 764, 16, 800, 800, 700, 11, 7, 4, 1, 1, 1, 0U, 0}, /* R5ND_0KEM_0fail_phi_26 */
    {16, 716, 16, 764, 16, 800, 800, 720, 11, 7, 4, 1, 1, 1, 0U, 0}, /* R5ND_0KEM_0fail_phi_27 */
    {16, 716, 16, 764, 16, 800, 800, 740, 11, 7, 4, 1, 1, 1, 0U, 0}, /* R5ND_0KEM_0fail_phi_28 */
    {16, 716, 16, 764, 16, 800, 800, 750, 11, 7, 4, 1, 1, 1, 0U, 0}, /* R5ND_0KEM_0fail_phi_29 */
    {16, 716, 16, 764, 16, 800, 800, 170, 11, 7, 4, 1, 1, 1, -1U, 0}, /* R5ND_0KEM_xfail_ntru_0 */
    {16, 716, 16, 764, 16, 800, 800, 180, 11, 7, 4, 1, 1, 1, -1U, 0}, /* R5ND_0KEM_xfail_ntru_1 */
    {16, 716, 16, 764, 16, 800, 800, 200, 11, 7, 4, 1, 1, 1, -1U, 0}, /* R5ND_0KEM_xfail_ntru_2 */
    {16, 716, 16, 764, 16, 800, 800, 220, 11, 7, 4, 1, 1, 1, -1U, 0}, /* R5ND_0KEM_xfail_ntru_3 */
    {16, 716, 16, 764, 16, 800, 800, 250, 11, 7, 4, 1, 1, 1, -1U, 0}, /* R5ND_0KEM_xfail_ntru_4 */
    {16, 716, 16, 764, 16, 800, 800, 270, 11, 7, 4, 1, 1, 1, -1U, 0}, /* R5ND_0KEM_xfail_ntru_5 */
    {16, 716, 16, 764, 16, 800, 800, 300, 11, 7, 4, 1, 1, 1, -1U, 0}, /* R5ND_0KEM_xfail_ntru_6 */
    {16, 716, 16, 764, 16, 800, 800, 320, 11, 7, 4, 1, 1, 1, -1U, 0}, /* R5ND_0KEM_xfail_ntru_7 */
    {16, 716, 16, 764, 16, 800, 800, 350, 11, 7, 4, 1, 1, 1, -1U, 0}, /* R5ND_0KEM_xfail_ntru_8 */
    {16, 716, 16, 764, 16, 800, 800, 370, 11, 7, 4, 1, 1, 1, -1U, 0}, /* R5ND_0KEM_xfail_ntru_9 */
    {16, 716, 16, 764, 16, 800, 800, 400, 11, 7, 4, 1, 1, 1, -1U, 0}, /* R5ND_0KEM_xfail_ntru_10 */
    {16, 716, 16, 764, 16, 800, 800, 420, 11, 7, 4, 1, 1, 1, -1U, 0}, /* R5ND_0KEM_xfail_ntru_11 */
    {16, 716, 16, 764, 16, 800, 800, 440, 11, 7, 4, 1, 1, 1, -1U, 0}, /* R5ND_0KEM_xfail_ntru_12 */
    {16, 716, 16, 764, 16, 800, 800, 450, 11, 7, 4, 1, 1, 1, -1U, 0}, /* R5ND_0KEM_xfail_ntru_13 */
    {16, 716, 16, 764, 16, 800, 800, 470, 11, 7, 4, 1, 1, 1, -1U, 0}, /* R5ND_0KEM_xfail_ntru_14 */
    {16, 716, 16, 764, 16, 800, 800, 500, 11, 7, 4, 1, 1, 1, -1U, 0}, /* R5ND_0KEM_xfail_ntru_15 */
    {16, 716, 16, 764, 16, 800, 800, 520, 11, 7, 4, 1, 1, 1, -1U, 0}, /* R5ND_0KEM_xfail_ntru_16 */
    {16, 716, 16, 764, 16, 800, 800, 540, 11, 7, 4, 1, 1, 1, -1U, 0}, /* R5ND_0KEM_xfail_ntru_17 */
    {16, 716, 16, 764, 16, 800, 800, 550, 11, 7, 4, 1, 1, 1, -1U, 0}, /* R5ND_0KEM_xfail_ntru_18 */
    {16, 716, 16, 764, 16, 800, 800, 570, 11, 7, 4, 1, 1, 1, -1U, 0}, /* R5ND_0KEM_xfail_ntru_19 */
    {16, 716, 16, 764, 16, 800, 800, 590, 11, 7, 4, 1, 1, 1, -1U, 0}, /* R5ND_0KEM_xfail_ntru_20 */
    {16, 716, 16, 764, 16, 800, 800, 600, 11, 7, 4, 1, 1, 1, -1U, 0}, /* R5ND_0KEM_xfail_ntru_21 */
    {16, 716, 16, 764, 16, 800, 800, 620, 11, 7, 4, 1, 1, 1, -1U, 0}, /* R5ND_0KEM_xfail_ntru_22 */
    {16, 716, 16, 764, 16, 800, 800, 640, 11, 7, 4, 1, 1, 1, -1U, 0}, /* R5ND_0KEM_xfail_ntru_23 */
    {16, 716, 16, 764, 16, 800, 800, 650, 11, 7, 4, 1, 1, 1, -1U, 0}, /* R5ND_0KEM_xfail_ntru_24 */
    {16, 716, 16, 764, 16, 800, 800, 670, 11, 7, 4, 1, 1, 1, -1U, 0}, /* R5ND_0KEM_xfail_ntru_25 */
    {16, 716, 16, 764, 16, 800, 800, 700, 11, 7, 4, 1, 1, 1, -1U, 0}, /* R5ND_0KEM_xfail_ntru_26 */
    {16, 716, 16, 764, 16, 800, 800, 720, 11, 7, 4, 1, 1, 1, -1U, 0}, /* R5ND_0KEM_xfail_ntru_27 */
    {16, 716, 16, 764, 16, 800, 800, 740, 11, 7, 4, 1, 1, 1, -1U, 0}, /* R5ND_0KEM_xfail_ntru_28 */
    {16, 716, 16, 764, 16, 800, 800, 750, 11, 7, 4, 1, 1, 1, -1U, 0}, /* R5ND_0KEM_xfail_ntru_29 */
};

/** The names of the Round5 parameter sets. */
const char *r5_parameter_set_names[81] = {"R5ND_1KEM_0c", "R5ND_3KEM_0c", "R5ND_5KEM_0c", "R5ND_1PKE_0c", "R5ND_3PKE_0c", "R5ND_5PKE_0c", "R5ND_1KEM_5c", "R5ND_3KEM_5c", "R5ND_5KEM_5c", "R5ND_1PKE_5c", "R5ND_3PKE_5c", "R5ND_5PKE_5c", "R5N1_1KEM_0c", "R5N1_3KEM_0c", "R5N1_5KEM_0c", "R5N1_1PKE_0c", "R5N1_3PKE_0c", "R5N1_5PKE_0c", "R5ND_0KEM_2iot", "R5ND_1KEM_4longkey", "R5N1_3PKE_0smallCT", "R5ND_0KEM_0fail_phi_0", "R5ND_0KEM_0fail_phi_1", "R5ND_0KEM_0fail_phi_2", "R5ND_0KEM_0fail_phi_3", "R5ND_0KEM_0fail_phi_4", "R5ND_0KEM_0fail_phi_5", "R5ND_0KEM_0fail_phi_6", "R5ND_0KEM_0fail_phi_7", "R5ND_0KEM_0fail_phi_8", "R5ND_0KEM_0fail_phi_9", "R5ND_0KEM_0fail_phi_10", "R5ND_0KEM_0fail_phi_11", "R5ND_0KEM_0fail_phi_12", "R5ND_0KEM_0fail_phi_13", "R5ND_0KEM_0fail_phi_14", "R5ND_0KEM_0fail_phi_15", "R5ND_0KEM_0fail_phi_16", "R5ND_0KEM_0fail_phi_17", "R5ND_0KEM_0fail_phi_18", "R5ND_0KEM_0fail_phi_19", "R5ND_0KEM_0fail_phi_20", "R5ND_0KEM_0fail_phi_21", "R5ND_0KEM_0fail_phi_22", "R5ND_0KEM_0fail_phi_23", "R5ND_0KEM_0fail_phi_24", "R5ND_0KEM_0fail_phi_25", "R5ND_0KEM_0fail_phi_26", "R5ND_0KEM_0fail_phi_27", "R5ND_0KEM_0fail_phi_28", "R5ND_0KEM_0fail_phi_29", "R5ND_0KEM_xfail_ntru_0", "R5ND_0KEM_xfail_ntru_1", "R5ND_0KEM_xfail_ntru_2", "R5ND_0KEM_xfail_ntru_3", "R5ND_0KEM_xfail_ntru_4", "R5ND_0KEM_xfail_ntru_5", "R5ND_0KEM_xfail_ntru_6", "R5ND_0KEM_xfail_ntru_7", "R5ND_0KEM_xfail_ntru_8", "R5ND_0KEM_xfail_ntru_9", "R5ND_0KEM_xfail_ntru_10", "R5ND_0KEM_xfail_ntru_11", "R5ND_0KEM_xfail_ntru_12", "R5ND_0KEM_xfail_ntru_13", "R5ND_0KEM_xfail_ntru_14", "R5ND_0KEM_xfail_ntru_15", "R5ND_0KEM_xfail_ntru_16", "R5ND_0KEM_xfail_ntru_17", "R5ND_0KEM_xfail_ntru_18", "R5ND_0KEM_xfail_ntru_19", "R5ND_0KEM_xfail_ntru_20", "R5ND_0KEM_xfail_ntru_21", "R5ND_0KEM_xfail_ntru_22", "R5ND_0KEM_xfail_ntru_23", "R5ND_0KEM_xfail_ntru_24", "R5ND_0KEM_xfail_ntru_25", "R5ND_0KEM_xfail_ntru_26", "R5ND_0KEM_xfail_ntru_27", "R5ND_0KEM_xfail_ntru_28", "R5ND_0KEM_xfail_ntru_29"};
