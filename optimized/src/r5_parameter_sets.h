/*
 * Copyright (c) 2018, PQShield and Koninklijke Philips N.V.
 * Markku-Juhani O. Saarinen, Koninklijke Philips N.V.
 */

#ifndef _R5_PARAMETER_SETS_H_
#define _R5_PARAMETER_SETS_H_

#include <stdint.h>
#include <stddef.h>
#include "misc.h"

// Parameter Set definitions

/* NIST API Round5 parameter set definitions */
#if defined(R5ND_1KEM_0d)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           618
#define PARAMS_N           618
#define PARAMS_H           104
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      8
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           0
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_1KEM_0d"
#elif defined(R5ND_3KEM_0d)
#define PARAMS_KAPPA_BYTES 24
#define PARAMS_D           786
#define PARAMS_N           786
#define PARAMS_H           384
#define PARAMS_Q_BITS      13
#define PARAMS_P_BITS      9
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           0
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_3KEM_0d"
#elif defined(R5ND_5KEM_0d)
#define PARAMS_KAPPA_BYTES 32
#define PARAMS_D           1018
#define PARAMS_N           1018
#define PARAMS_H           428
#define PARAMS_Q_BITS      14
#define PARAMS_P_BITS      9
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           0
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_5KEM_0d"
#elif defined(R5ND_1PKE_0d)
#define ROUND5_CCA_PKE
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           586
#define PARAMS_N           586
#define PARAMS_H           182
#define PARAMS_Q_BITS      13
#define PARAMS_P_BITS      9
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           0
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_1PKE_0d"
#elif defined(R5ND_3PKE_0d)
#define ROUND5_CCA_PKE
#define PARAMS_KAPPA_BYTES 24
#define PARAMS_D           852
#define PARAMS_N           852
#define PARAMS_H           212
#define PARAMS_Q_BITS      12
#define PARAMS_P_BITS      9
#define PARAMS_T_BITS      5
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           0
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_3PKE_0d"
#elif defined(R5ND_5PKE_0d)
#define ROUND5_CCA_PKE
#define PARAMS_KAPPA_BYTES 32
#define PARAMS_D           1170
#define PARAMS_N           1170
#define PARAMS_H           222
#define PARAMS_Q_BITS      13
#define PARAMS_P_BITS      9
#define PARAMS_T_BITS      5
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           0
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_5PKE_0d"
#elif defined(R5ND_1KEM_5d)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           490
#define PARAMS_N           490
#define PARAMS_H           162
#define PARAMS_Q_BITS      10
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      3
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           5
#define PARAMS_XE          190
#define CRYPTO_ALGNAME     "R5ND_1KEM_5d"
#elif defined(R5ND_3KEM_5d)
#define PARAMS_KAPPA_BYTES 24
#define PARAMS_D           756
#define PARAMS_N           756
#define PARAMS_H           242
#define PARAMS_Q_BITS      12
#define PARAMS_P_BITS      8
#define PARAMS_T_BITS      2
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           5
#define PARAMS_XE          218
#define CRYPTO_ALGNAME     "R5ND_3KEM_5d"
#elif defined(R5ND_5KEM_5d)
#define PARAMS_KAPPA_BYTES 32
#define PARAMS_D           940
#define PARAMS_N           940
#define PARAMS_H           414
#define PARAMS_Q_BITS      12
#define PARAMS_P_BITS      8
#define PARAMS_T_BITS      2
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           5
#define PARAMS_XE          234
#define CRYPTO_ALGNAME     "R5ND_5KEM_5d"
#elif defined(R5ND_1PKE_5d)
#define ROUND5_CCA_PKE
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           508
#define PARAMS_N           508
#define PARAMS_H           136
#define PARAMS_Q_BITS      10
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           5
#define PARAMS_XE          190
#define CRYPTO_ALGNAME     "R5ND_1PKE_5d"
#elif defined(R5ND_3PKE_5d)
#define ROUND5_CCA_PKE
#define PARAMS_KAPPA_BYTES 24
#define PARAMS_D           756
#define PARAMS_N           756
#define PARAMS_H           242
#define PARAMS_Q_BITS      12
#define PARAMS_P_BITS      8
#define PARAMS_T_BITS      3
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           5
#define PARAMS_XE          218
#define CRYPTO_ALGNAME     "R5ND_3PKE_5d"
#elif defined(R5ND_5PKE_5d)
#define ROUND5_CCA_PKE
#define PARAMS_KAPPA_BYTES 32
#define PARAMS_D           946
#define PARAMS_N           946
#define PARAMS_H           388
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      8
#define PARAMS_T_BITS      5
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           5
#define PARAMS_XE          234
#define CRYPTO_ALGNAME     "R5ND_5PKE_5d"
#elif defined(R5N1_1KEM_0d)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           594
#define PARAMS_N           1
#define PARAMS_H           238
#define PARAMS_Q_BITS      13
#define PARAMS_P_BITS      10
#define PARAMS_T_BITS      7
#define PARAMS_B_BITS      3
#define PARAMS_N_BAR       7
#define PARAMS_M_BAR       7
#define PARAMS_F           0
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5N1_1KEM_0d"
#elif defined(R5N1_3KEM_0d)
#define PARAMS_KAPPA_BYTES 24
#define PARAMS_D           881
#define PARAMS_N           1
#define PARAMS_H           238
#define PARAMS_Q_BITS      13
#define PARAMS_P_BITS      10
#define PARAMS_T_BITS      7
#define PARAMS_B_BITS      3
#define PARAMS_N_BAR       8
#define PARAMS_M_BAR       8
#define PARAMS_F           0
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5N1_3KEM_0d"
#elif defined(R5N1_5KEM_0d)
#define PARAMS_KAPPA_BYTES 32
#define PARAMS_D           1186
#define PARAMS_N           1
#define PARAMS_H           712
#define PARAMS_Q_BITS      15
#define PARAMS_P_BITS      12
#define PARAMS_T_BITS      7
#define PARAMS_B_BITS      4
#define PARAMS_N_BAR       8
#define PARAMS_M_BAR       8
#define PARAMS_F           0
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5N1_5KEM_0d"
#elif defined(R5N1_1PKE_0d)
#define ROUND5_CCA_PKE
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           636
#define PARAMS_N           1
#define PARAMS_H           114
#define PARAMS_Q_BITS      12
#define PARAMS_P_BITS      9
#define PARAMS_T_BITS      6
#define PARAMS_B_BITS      2
#define PARAMS_N_BAR       8
#define PARAMS_M_BAR       8
#define PARAMS_F           0
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5N1_1PKE_0d"
#elif defined(R5N1_3PKE_0d)
#define ROUND5_CCA_PKE
#define PARAMS_KAPPA_BYTES 24
#define PARAMS_D           876
#define PARAMS_N           1
#define PARAMS_H           446
#define PARAMS_Q_BITS      15
#define PARAMS_P_BITS      11
#define PARAMS_T_BITS      7
#define PARAMS_B_BITS      3
#define PARAMS_N_BAR       8
#define PARAMS_M_BAR       8
#define PARAMS_F           0
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5N1_3PKE_0d"
#elif defined(R5N1_5PKE_0d)
#define ROUND5_CCA_PKE
#define PARAMS_KAPPA_BYTES 32
#define PARAMS_D           1217
#define PARAMS_N           1
#define PARAMS_H           462
#define PARAMS_Q_BITS      15
#define PARAMS_P_BITS      12
#define PARAMS_T_BITS      9
#define PARAMS_B_BITS      4
#define PARAMS_N_BAR       8
#define PARAMS_M_BAR       8
#define PARAMS_F           0
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5N1_5PKE_0d"
#elif defined(R5ND_0KEM_2iot)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           372
#define PARAMS_N           372
#define PARAMS_H           178
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      3
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           2
#define PARAMS_XE          53
#define CRYPTO_ALGNAME     "R5ND_0KEM_2iot"
#elif defined(R5ND_1KEM_4longkey)
#define PARAMS_KAPPA_BYTES 24
#define PARAMS_D           490
#define PARAMS_N           490
#define PARAMS_H           162
#define PARAMS_Q_BITS      10
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      3
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           4
#define PARAMS_XE          163
#define CRYPTO_ALGNAME     "R5ND_1KEM_4longkey"
#elif defined(R5N1_3PKE_0smallCT)
#define ROUND5_CCA_PKE
#define PARAMS_KAPPA_BYTES 24
#define PARAMS_D           757
#define PARAMS_N           1
#define PARAMS_H           378
#define PARAMS_Q_BITS      14
#define PARAMS_P_BITS      9
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       192
#define PARAMS_M_BAR       1
#define PARAMS_F           0
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5N1_3PKE_0smallCT"
#elif defined(R5ND_0KEM_0fail_phi_0)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           170
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           0
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_0fail_phi_0"
#elif defined(R5ND_0KEM_0fail_phi_1)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           180
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           0
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_0fail_phi_1"
#elif defined(R5ND_0KEM_0fail_phi_2)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           200
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           0
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_0fail_phi_2"
#elif defined(R5ND_0KEM_0fail_phi_3)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           220
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           0
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_0fail_phi_3"
#elif defined(R5ND_0KEM_0fail_phi_4)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           250
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           0
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_0fail_phi_4"
#elif defined(R5ND_0KEM_0fail_phi_5)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           270
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           0
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_0fail_phi_5"
#elif defined(R5ND_0KEM_0fail_phi_6)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           300
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           0
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_0fail_phi_6"
#elif defined(R5ND_0KEM_0fail_phi_7)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           320
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           0
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_0fail_phi_7"
#elif defined(R5ND_0KEM_0fail_phi_8)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           350
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           0
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_0fail_phi_8"
#elif defined(R5ND_0KEM_0fail_phi_9)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           370
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           0
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_0fail_phi_9"
#elif defined(R5ND_0KEM_0fail_phi_10)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           400
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           0
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_0fail_phi_10"
#elif defined(R5ND_0KEM_0fail_phi_11)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           420
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           0
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_0fail_phi_11"
#elif defined(R5ND_0KEM_0fail_phi_12)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           440
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           0
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_0fail_phi_12"
#elif defined(R5ND_0KEM_0fail_phi_13)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           450
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           0
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_0fail_phi_13"
#elif defined(R5ND_0KEM_0fail_phi_14)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           470
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           0
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_0fail_phi_14"
#elif defined(R5ND_0KEM_0fail_phi_15)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           500
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           0
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_0fail_phi_15"
#elif defined(R5ND_0KEM_0fail_phi_16)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           520
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           0
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_0fail_phi_16"
#elif defined(R5ND_0KEM_0fail_phi_17)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           540
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           0
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_0fail_phi_17"
#elif defined(R5ND_0KEM_0fail_phi_18)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           550
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           0
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_0fail_phi_18"
#elif defined(R5ND_0KEM_0fail_phi_19)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           570
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           0
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_0fail_phi_19"
#elif defined(R5ND_0KEM_0fail_phi_20)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           590
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           0
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_0fail_phi_20"
#elif defined(R5ND_0KEM_0fail_phi_21)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           600
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           0
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_0fail_phi_21"
#elif defined(R5ND_0KEM_0fail_phi_22)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           620
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           0
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_0fail_phi_22"
#elif defined(R5ND_0KEM_0fail_phi_23)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           640
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           0
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_0fail_phi_23"
#elif defined(R5ND_0KEM_0fail_phi_24)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           650
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           0
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_0fail_phi_24"
#elif defined(R5ND_0KEM_0fail_phi_25)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           670
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           0
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_0fail_phi_25"
#elif defined(R5ND_0KEM_0fail_phi_26)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           700
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           0
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_0fail_phi_26"
#elif defined(R5ND_0KEM_0fail_phi_27)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           720
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           0
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_0fail_phi_27"
#elif defined(R5ND_0KEM_0fail_phi_28)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           740
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           0
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_0fail_phi_28"
#elif defined(R5ND_0KEM_0fail_phi_29)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           750
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           0
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_0fail_phi_29"
#elif defined(R5ND_0KEM_xfail_ntru_0)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           170
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           -1
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_xfail_ntru_0"
#elif defined(R5ND_0KEM_xfail_ntru_1)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           180
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           -1
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_xfail_ntru_1"
#elif defined(R5ND_0KEM_xfail_ntru_2)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           200
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           -1
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_xfail_ntru_2"
#elif defined(R5ND_0KEM_xfail_ntru_3)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           220
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           -1
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_xfail_ntru_3"
#elif defined(R5ND_0KEM_xfail_ntru_4)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           250
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           -1
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_xfail_ntru_4"
#elif defined(R5ND_0KEM_xfail_ntru_5)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           270
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           -1
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_xfail_ntru_5"
#elif defined(R5ND_0KEM_xfail_ntru_6)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           300
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           -1
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_xfail_ntru_6"
#elif defined(R5ND_0KEM_xfail_ntru_7)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           320
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           -1
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_xfail_ntru_7"
#elif defined(R5ND_0KEM_xfail_ntru_8)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           350
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           -1
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_xfail_ntru_8"
#elif defined(R5ND_0KEM_xfail_ntru_9)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           370
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           -1
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_xfail_ntru_9"
#elif defined(R5ND_0KEM_xfail_ntru_10)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           400
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           -1
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_xfail_ntru_10"
#elif defined(R5ND_0KEM_xfail_ntru_11)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           420
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           -1
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_xfail_ntru_11"
#elif defined(R5ND_0KEM_xfail_ntru_12)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           440
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           -1
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_xfail_ntru_12"
#elif defined(R5ND_0KEM_xfail_ntru_13)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           450
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           -1
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_xfail_ntru_13"
#elif defined(R5ND_0KEM_xfail_ntru_14)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           470
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           -1
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_xfail_ntru_14"
#elif defined(R5ND_0KEM_xfail_ntru_15)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           500
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           -1
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_xfail_ntru_15"
#elif defined(R5ND_0KEM_xfail_ntru_16)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           520
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           -1
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_xfail_ntru_16"
#elif defined(R5ND_0KEM_xfail_ntru_17)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           540
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           -1
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_xfail_ntru_17"
#elif defined(R5ND_0KEM_xfail_ntru_18)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           550
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           -1
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_xfail_ntru_18"
#elif defined(R5ND_0KEM_xfail_ntru_19)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           570
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           -1
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_xfail_ntru_19"
#elif defined(R5ND_0KEM_xfail_ntru_20)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           590
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           -1
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_xfail_ntru_20"
#elif defined(R5ND_0KEM_xfail_ntru_21)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           600
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           -1
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_xfail_ntru_21"
#elif defined(R5ND_0KEM_xfail_ntru_22)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           620
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           -1
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_xfail_ntru_22"
#elif defined(R5ND_0KEM_xfail_ntru_23)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           640
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           -1
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_xfail_ntru_23"
#elif defined(R5ND_0KEM_xfail_ntru_24)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           650
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           -1
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_xfail_ntru_24"
#elif defined(R5ND_0KEM_xfail_ntru_25)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           670
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           -1
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_xfail_ntru_25"
#elif defined(R5ND_0KEM_xfail_ntru_26)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           700
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           -1
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_xfail_ntru_26"
#elif defined(R5ND_0KEM_xfail_ntru_27)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           720
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           -1
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_xfail_ntru_27"
#elif defined(R5ND_0KEM_xfail_ntru_28)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           740
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           -1
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_xfail_ntru_28"
#elif defined(R5ND_0KEM_xfail_ntru_29)
#define PARAMS_KAPPA_BYTES 16
#define PARAMS_D           800
#define PARAMS_N           800
#define PARAMS_H           750
#define PARAMS_Q_BITS      11
#define PARAMS_P_BITS      7
#define PARAMS_T_BITS      4
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           -1
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "R5ND_0KEM_xfail_ntru_29"
#else
#error You must define one of: R5ND_1KEM_0d, R5ND_3KEM_0d, R5ND_5KEM_0d, R5ND_1PKE_0d, R5ND_3PKE_0d, R5ND_5PKE_0d, R5ND_1KEM_5d, R5ND_3KEM_5d, R5ND_5KEM_5d, R5ND_1PKE_5d, R5ND_3PKE_5d, R5ND_5PKE_5d, R5N1_1KEM_0d, R5N1_3KEM_0d, R5N1_5KEM_0d, R5N1_1PKE_0d, R5N1_3PKE_0d, R5N1_5PKE_0d, R5ND_0KEM_2iot, R5ND_1KEM_4longkey, R5N1_3PKE_0smallCT, R5ND_0KEM_0fail_phi_0, R5ND_0KEM_0fail_phi_1, R5ND_0KEM_0fail_phi_2, R5ND_0KEM_0fail_phi_3, R5ND_0KEM_0fail_phi_4, R5ND_0KEM_0fail_phi_5, R5ND_0KEM_0fail_phi_6, R5ND_0KEM_0fail_phi_7, R5ND_0KEM_0fail_phi_8, R5ND_0KEM_0fail_phi_9, R5ND_0KEM_0fail_phi_10, R5ND_0KEM_0fail_phi_11, R5ND_0KEM_0fail_phi_12, R5ND_0KEM_0fail_phi_13, R5ND_0KEM_0fail_phi_14, R5ND_0KEM_0fail_phi_15, R5ND_0KEM_0fail_phi_16, R5ND_0KEM_0fail_phi_17, R5ND_0KEM_0fail_phi_18, R5ND_0KEM_0fail_phi_19, R5ND_0KEM_0fail_phi_20, R5ND_0KEM_0fail_phi_21, R5ND_0KEM_0fail_phi_22, R5ND_0KEM_0fail_phi_23, R5ND_0KEM_0fail_phi_24, R5ND_0KEM_0fail_phi_25, R5ND_0KEM_0fail_phi_26, R5ND_0KEM_0fail_phi_27, R5ND_0KEM_0fail_phi_28, R5ND_0KEM_0fail_phi_29, R5ND_0KEM_xfail_ntru_0, R5ND_0KEM_xfail_ntru_1, R5ND_0KEM_xfail_ntru_2, R5ND_0KEM_xfail_ntru_3, R5ND_0KEM_xfail_ntru_4, R5ND_0KEM_xfail_ntru_5, R5ND_0KEM_xfail_ntru_6, R5ND_0KEM_xfail_ntru_7, R5ND_0KEM_xfail_ntru_8, R5ND_0KEM_xfail_ntru_9, R5ND_0KEM_xfail_ntru_10, R5ND_0KEM_xfail_ntru_11, R5ND_0KEM_xfail_ntru_12, R5ND_0KEM_xfail_ntru_13, R5ND_0KEM_xfail_ntru_14, R5ND_0KEM_xfail_ntru_15, R5ND_0KEM_xfail_ntru_16, R5ND_0KEM_xfail_ntru_17, R5ND_0KEM_xfail_ntru_18, R5ND_0KEM_xfail_ntru_19, R5ND_0KEM_xfail_ntru_20, R5ND_0KEM_xfail_ntru_21, R5ND_0KEM_xfail_ntru_22, R5ND_0KEM_xfail_ntru_23, R5ND_0KEM_xfail_ntru_24, R5ND_0KEM_xfail_ntru_25, R5ND_0KEM_xfail_ntru_26, R5ND_0KEM_xfail_ntru_27, R5ND_0KEM_xfail_ntru_28, R5ND_0KEM_xfail_ntru_29.
#define PARAMS_KAPPA_BYTES 1
#define PARAMS_D           1
#define PARAMS_N           1
#define PARAMS_H           1
#define PARAMS_Q_BITS      1
#define PARAMS_P_BITS      1
#define PARAMS_T_BITS      1
#define PARAMS_B_BITS      1
#define PARAMS_N_BAR       1
#define PARAMS_M_BAR       1
#define PARAMS_F           0
#define PARAMS_XE          0
#define CRYPTO_ALGNAME     "INVALID"
#endif

// appropriate types
typedef uint16_t modq_t;
#if (PARAMS_P_BITS <= 8)
typedef uint8_t modp_t;
#else
typedef uint16_t modp_t;
#endif
typedef uint8_t modt_t;

#define PARAMS_ND       PARAMS_D
#define PARAMS_K        (PARAMS_D/PARAMS_N)
#define PARAMS_Q        (1 << PARAMS_Q_BITS)
#define PARAMS_Q_MASK   (PARAMS_Q - 1)
#define PARAMS_P        (1 << PARAMS_P_BITS)
#define PARAMS_P_MASK   (PARAMS_P - 1)
#define PARAMS_KAPPA    (8 * PARAMS_KAPPA_BYTES)
#define PARAMS_MU       CEIL_DIV((PARAMS_KAPPA + PARAMS_XE), PARAMS_B_BITS)
#define PARAMS_MUT_SIZE BITS_TO_BYTES(PARAMS_MU * PARAMS_T_BITS)
#if PARAMS_K == 1
#define PARAMS_RS_DIV   (0x10000 / PARAMS_ND)
#define PARAMS_RS_LIM   (PARAMS_ND * PARAMS_RS_DIV)
#define PARAMS_NDP_SIZE BITS_TO_BYTES(PARAMS_ND * PARAMS_P_BITS)
#else
#define PARAMS_RS_DIV   (0x10000 / PARAMS_D)
#define PARAMS_RS_LIM   (PARAMS_D * PARAMS_RS_DIV)
#define PARAMS_DP_SIZE  BITS_TO_BYTES(PARAMS_N_BAR * PARAMS_D * PARAMS_P_BITS)
#define PARAMS_DPU_SIZE BITS_TO_BYTES(PARAMS_M_BAR * PARAMS_D * PARAMS_P_BITS)
#endif

// Definition of TAU parameter, defaults to 0 unless otherwise defined and non-ring
#if PARAMS_K == 1 || !defined(ROUND5_API_TAU)
#undef ROUND5_API_TAU
#define ROUND5_API_TAU 0
#endif
#define PARAMS_TAU      ROUND5_API_TAU

// Define the length of the random vector when TAU is 2 is used for generating A, defaults to parameter 2^11.
// Important: Must be a power of two and > d
#if !defined(ROUND5_API_TAU2_LEN) || ROUND5_API_TAU2_LEN == 0
#undef ROUND5_API_TAU2_LEN
#define ROUND5_API_TAU2_LEN (1<<11)
#endif
#if ROUND5_API_TAU2_LEN > (1<<31)
#error ROUND5_API_TAU2_LEN must be less than or equal to 2^31
#endif
#if (ROUND5_API_TAU2_LEN & (ROUND5_API_TAU2_LEN - 1)) != 0 || ROUND5_API_TAU2_LEN < PARAMS_D
#error ROUND5_API_TAU2_LEN must be a power of two and greater than or equal to PARAMS_D
#endif
#define PARAMS_TAU2_LEN ROUND5_API_TAU2_LEN

// Rounding constants
#if ((PARAMS_Q_BITS - PARAMS_P_BITS + PARAMS_T_BITS) < PARAMS_P_BITS)
#define PARAMS_Z_BITS   PARAMS_P_BITS
#else
#define PARAMS_Z_BITS   (PARAMS_Q_BITS - PARAMS_P_BITS + PARAMS_T_BITS)
#endif
#define PARAMS_H1       (1 << (PARAMS_Q_BITS - PARAMS_P_BITS - 1))
#define PARAMS_H2       (1 << (PARAMS_Q_BITS - PARAMS_Z_BITS - 1))
#define PARAMS_H3       ((1 << (PARAMS_P_BITS - PARAMS_T_BITS - 1)) + (1 << (PARAMS_P_BITS - PARAMS_B_BITS - 1)) - (1 << (PARAMS_Q_BITS - PARAMS_Z_BITS - 1)))

#if PARAMS_K == 1
#define PARAMS_PK_SIZE  (PARAMS_KAPPA_BYTES + PARAMS_NDP_SIZE)
#define PARAMS_CT_SIZE  (PARAMS_NDP_SIZE + PARAMS_MUT_SIZE)
#else
#define PARAMS_PK_SIZE  (PARAMS_KAPPA_BYTES + PARAMS_DP_SIZE)
#define PARAMS_CT_SIZE  (PARAMS_DPU_SIZE + PARAMS_MUT_SIZE)

// Packing shift
#if PARAMS_B_BITS == 1
#define PACK_SHIFT 3
#define PACK_AND 7
#endif
#if PARAMS_B_BITS == 2
#define PACK_SHIFT 2
#define PACK_AND 3
#endif
#if PARAMS_B_BITS == 4
#define PACK_SHIFT 1
#define PACK_AND 1
#endif

#endif

// Derive the NIST parameters
#ifdef ROUND5_CCA_PKE

// CCA_PKE Variant
#define CRYPTO_SECRETKEYBYTES  (PARAMS_KAPPA_BYTES + PARAMS_KAPPA_BYTES + PARAMS_PK_SIZE)
#define CRYPTO_PUBLICKEYBYTES  PARAMS_PK_SIZE
#define CRYPTO_BYTES           (PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES + 16)
#define CRYPTO_CIPHERTEXTBYTES 0

#else

// CPA_KEM Variant
#define CRYPTO_SECRETKEYBYTES  PARAMS_KAPPA_BYTES
#define CRYPTO_PUBLICKEYBYTES  PARAMS_PK_SIZE
#define CRYPTO_BYTES           PARAMS_KAPPA_BYTES
#define CRYPTO_CIPHERTEXTBYTES PARAMS_CT_SIZE

#endif /* ROUND5_CCA_PKE */

// AVX2 implies CM_CACHE
#ifdef AVX2
#undef CM_CACHE
#define CM_CACHE
// Disable AVX2 if not supported by platform
#ifndef __AVX2__
#warning AVX2 not supported by platform
#undef AVX2
#endif
#endif

#endif /* _R5_PARAMETER_SETS_H_ */
