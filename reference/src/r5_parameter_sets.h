/*
 * Copyright (c) 2018, Koninklijke Philips N.V.
 */

/**
 * @file
 * Definition of the NIST API Round5 parameter sets and declaration of the
 * (internal) Round5 parameter set variables.
 */

#ifndef R5_PARAMETER_SETS_H
#define R5_PARAMETER_SETS_H

#include <stdint.h>

/* Positions of the NIST API parameters */

/** The location of API parameter `CRYPTO_SECRETKEYBYTES` in the parameter set.  */
#define API_SECRET   0
/** The location of API parameter `CRYPTO_PUBLICKEYBYTES` in the parameter set.  */
#define API_PUBLIC   1
/** The location of API parameter `CRYPTO_BYTES` in the parameter set. */
#define API_BYTES    2
/** The location of API parameter `CRYPTO_CIPHERETEXTBYTES` in the parameter set.  */
#define API_CIPHER   3

/* Positions of our internal parameters */

/** The location of algorithm parameter `kappa_bytes` in the parameter set */
#define POS_KAPPA_BYTES 4
/** The location of algorithm parameter `d` in the parameter set */
#define POS_D           5
/** The location of algorithm parameter `n` in the parameter set */
#define POS_N           6
/** The location of algorithm parameter `h` in the parameter set */
#define POS_H           7
/** The location of algorithm parameter `q_bits` in the parameter set */
#define POS_Q_BITS      8
/** The location of algorithm parameter `p_bits` in the parameter set */
#define POS_P_BITS      9
/** The location of algorithm parameter `t_bits` in the parameter set */
#define POS_T_BITS     10
/** The location of algorithm parameter `b_bits` in the parameter set */
#define POS_B_BITS     11
/** The location of algorithm parameter `n_bar` in the parameter set */
#define POS_N_BAR      12
/** The location of algorithm parameter `m_bar` in the parameter set */
#define POS_M_BAR      13
/** The location of algorithm parameter `f` in the parameter set */
#define POS_F          14
/** The location of algorithm parameter `xe` in the parameter set */
#define POS_XE         15

/* NIST API Round5 parameter set definitions */
#if defined(R5ND_1CPA_0d)
#define ROUND5_API_SET 0
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 634
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 682
#define CRYPTO_ALGNAME "R5ND_1CPA_0d"
#elif defined(R5ND_3CPA_0d)
#define ROUND5_API_SET 1
#define CRYPTO_SECRETKEYBYTES 24
#define CRYPTO_PUBLICKEYBYTES 909
#define CRYPTO_BYTES 24
#define CRYPTO_CIPHERTEXTBYTES 981
#define CRYPTO_ALGNAME "R5ND_3CPA_0d"
#elif defined(R5ND_5CPA_0d)
#define ROUND5_API_SET 2
#define CRYPTO_SECRETKEYBYTES 32
#define CRYPTO_PUBLICKEYBYTES 1178
#define CRYPTO_BYTES 32
#define CRYPTO_CIPHERTEXTBYTES 1274
#define CRYPTO_ALGNAME "R5ND_5CPA_0d"
#elif defined(R5ND_1CCA_0d)
#define ROUND5_API_SET 3
#define CRYPTO_SECRETKEYBYTES 708
#define CRYPTO_PUBLICKEYBYTES 676
#define CRYPTO_BYTES 756
#define CRYPTO_CIPHERTEXTBYTES 0
#define CRYPTO_ALGNAME "R5ND_1CCA_0d"
#elif defined(R5ND_3CCA_0d)
#define ROUND5_API_SET 4
#define CRYPTO_SECRETKEYBYTES 1031
#define CRYPTO_PUBLICKEYBYTES 983
#define CRYPTO_BYTES 1119
#define CRYPTO_CIPHERTEXTBYTES 0
#define CRYPTO_ALGNAME "R5ND_3CCA_0d"
#elif defined(R5ND_5CCA_0d)
#define ROUND5_API_SET 5
#define CRYPTO_SECRETKEYBYTES 1413
#define CRYPTO_PUBLICKEYBYTES 1349
#define CRYPTO_BYTES 1525
#define CRYPTO_CIPHERTEXTBYTES 0
#define CRYPTO_ALGNAME "R5ND_5CCA_0d"
#elif defined(R5ND_1CPA_5d)
#define ROUND5_API_SET 6
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 445
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 549
#define CRYPTO_ALGNAME "R5ND_1CPA_5d"
#elif defined(R5ND_3CPA_5d)
#define ROUND5_API_SET 7
#define CRYPTO_SECRETKEYBYTES 24
#define CRYPTO_PUBLICKEYBYTES 780
#define CRYPTO_BYTES 24
#define CRYPTO_CIPHERTEXTBYTES 859
#define CRYPTO_ALGNAME "R5ND_3CPA_5d"
#elif defined(R5ND_5CPA_5d)
#define ROUND5_API_SET 8
#define CRYPTO_SECRETKEYBYTES 32
#define CRYPTO_PUBLICKEYBYTES 972
#define CRYPTO_BYTES 32
#define CRYPTO_CIPHERTEXTBYTES 1063
#define CRYPTO_ALGNAME "R5ND_5CPA_5d"
#elif defined(R5ND_1CCA_5d)
#define ROUND5_API_SET 9
#define CRYPTO_SECRETKEYBYTES 493
#define CRYPTO_PUBLICKEYBYTES 461
#define CRYPTO_BYTES 636
#define CRYPTO_CIPHERTEXTBYTES 0
#define CRYPTO_ALGNAME "R5ND_1CCA_5d"
#elif defined(R5ND_3CCA_5d)
#define ROUND5_API_SET 10
#define CRYPTO_SECRETKEYBYTES 828
#define CRYPTO_PUBLICKEYBYTES 780
#define CRYPTO_BYTES 950
#define CRYPTO_CIPHERTEXTBYTES 0
#define CRYPTO_ALGNAME "R5ND_3CCA_5d"
#elif defined(R5ND_5CCA_5d)
#define ROUND5_API_SET 11
#define CRYPTO_SECRETKEYBYTES 1042
#define CRYPTO_PUBLICKEYBYTES 978
#define CRYPTO_BYTES 1301
#define CRYPTO_CIPHERTEXTBYTES 0
#define CRYPTO_ALGNAME "R5ND_5CCA_5d"
#elif defined(R5N1_1CPA_0d)
#define ROUND5_API_SET 12
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 5214
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 5236
#define CRYPTO_ALGNAME "R5N1_1CPA_0d"
#elif defined(R5N1_3CPA_0d)
#define ROUND5_API_SET 13
#define CRYPTO_SECRETKEYBYTES 24
#define CRYPTO_PUBLICKEYBYTES 8834
#define CRYPTO_BYTES 24
#define CRYPTO_CIPHERTEXTBYTES 8866
#define CRYPTO_ALGNAME "R5N1_3CPA_0d"
#elif defined(R5N1_5CPA_0d)
#define ROUND5_API_SET 14
#define CRYPTO_SECRETKEYBYTES 32
#define CRYPTO_PUBLICKEYBYTES 14264
#define CRYPTO_BYTES 32
#define CRYPTO_CIPHERTEXTBYTES 14288
#define CRYPTO_ALGNAME "R5N1_5CPA_0d"
#elif defined(R5N1_1CCA_0d)
#define ROUND5_API_SET 15
#define CRYPTO_SECRETKEYBYTES 5772
#define CRYPTO_PUBLICKEYBYTES 5740
#define CRYPTO_BYTES 5804
#define CRYPTO_CIPHERTEXTBYTES 0
#define CRYPTO_ALGNAME "R5N1_1CCA_0d"
#elif defined(R5N1_3CCA_0d)
#define ROUND5_API_SET 16
#define CRYPTO_SECRETKEYBYTES 9708
#define CRYPTO_PUBLICKEYBYTES 9660
#define CRYPTO_BYTES 9732
#define CRYPTO_CIPHERTEXTBYTES 0
#define CRYPTO_ALGNAME "R5N1_3CCA_0d"
#elif defined(R5N1_5CCA_0d)
#define ROUND5_API_SET 17
#define CRYPTO_SECRETKEYBYTES 14700
#define CRYPTO_PUBLICKEYBYTES 14636
#define CRYPTO_BYTES 14724
#define CRYPTO_CIPHERTEXTBYTES 0
#define CRYPTO_ALGNAME "R5N1_5CCA_0d"
#elif defined(R5ND_0CPA_2iot)
#define ROUND5_API_SET 18
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 342
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 394
#define CRYPTO_ALGNAME "R5ND_0CPA_2iot"
#elif defined(R5ND_1CPA_4longkey)
#define ROUND5_API_SET 19
#define CRYPTO_SECRETKEYBYTES 24
#define CRYPTO_PUBLICKEYBYTES 453
#define CRYPTO_BYTES 24
#define CRYPTO_CIPHERTEXTBYTES 563
#define CRYPTO_ALGNAME "R5ND_1CPA_4longkey"
#elif defined(R5N1_3CCA_0smallCT)
#define ROUND5_API_SET 20
#define CRYPTO_SECRETKEYBYTES 163584
#define CRYPTO_PUBLICKEYBYTES 163536
#define CRYPTO_BYTES 988
#define CRYPTO_CIPHERTEXTBYTES 0
#define CRYPTO_ALGNAME "R5N1_3CCA_0smallCT"
#elif defined(R5ND_0CPA_0fail_phi_0)
#define ROUND5_API_SET 21
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_0fail_phi_0"
#elif defined(R5ND_0CPA_0fail_phi_1)
#define ROUND5_API_SET 22
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_0fail_phi_1"
#elif defined(R5ND_0CPA_0fail_phi_2)
#define ROUND5_API_SET 23
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_0fail_phi_2"
#elif defined(R5ND_0CPA_0fail_phi_3)
#define ROUND5_API_SET 24
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_0fail_phi_3"
#elif defined(R5ND_0CPA_0fail_phi_4)
#define ROUND5_API_SET 25
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_0fail_phi_4"
#elif defined(R5ND_0CPA_0fail_phi_5)
#define ROUND5_API_SET 26
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_0fail_phi_5"
#elif defined(R5ND_0CPA_0fail_phi_6)
#define ROUND5_API_SET 27
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_0fail_phi_6"
#elif defined(R5ND_0CPA_0fail_phi_7)
#define ROUND5_API_SET 28
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_0fail_phi_7"
#elif defined(R5ND_0CPA_0fail_phi_8)
#define ROUND5_API_SET 29
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_0fail_phi_8"
#elif defined(R5ND_0CPA_0fail_phi_9)
#define ROUND5_API_SET 30
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_0fail_phi_9"
#elif defined(R5ND_0CPA_0fail_phi_10)
#define ROUND5_API_SET 31
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_0fail_phi_10"
#elif defined(R5ND_0CPA_0fail_phi_11)
#define ROUND5_API_SET 32
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_0fail_phi_11"
#elif defined(R5ND_0CPA_0fail_phi_12)
#define ROUND5_API_SET 33
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_0fail_phi_12"
#elif defined(R5ND_0CPA_0fail_phi_13)
#define ROUND5_API_SET 34
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_0fail_phi_13"
#elif defined(R5ND_0CPA_0fail_phi_14)
#define ROUND5_API_SET 35
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_0fail_phi_14"
#elif defined(R5ND_0CPA_0fail_phi_15)
#define ROUND5_API_SET 36
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_0fail_phi_15"
#elif defined(R5ND_0CPA_0fail_phi_16)
#define ROUND5_API_SET 37
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_0fail_phi_16"
#elif defined(R5ND_0CPA_0fail_phi_17)
#define ROUND5_API_SET 38
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_0fail_phi_17"
#elif defined(R5ND_0CPA_0fail_phi_18)
#define ROUND5_API_SET 39
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_0fail_phi_18"
#elif defined(R5ND_0CPA_0fail_phi_19)
#define ROUND5_API_SET 40
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_0fail_phi_19"
#elif defined(R5ND_0CPA_0fail_phi_20)
#define ROUND5_API_SET 41
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_0fail_phi_20"
#elif defined(R5ND_0CPA_0fail_phi_21)
#define ROUND5_API_SET 42
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_0fail_phi_21"
#elif defined(R5ND_0CPA_0fail_phi_22)
#define ROUND5_API_SET 43
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_0fail_phi_22"
#elif defined(R5ND_0CPA_0fail_phi_23)
#define ROUND5_API_SET 44
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_0fail_phi_23"
#elif defined(R5ND_0CPA_0fail_phi_24)
#define ROUND5_API_SET 45
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_0fail_phi_24"
#elif defined(R5ND_0CPA_0fail_phi_25)
#define ROUND5_API_SET 46
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_0fail_phi_25"
#elif defined(R5ND_0CPA_0fail_phi_26)
#define ROUND5_API_SET 47
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_0fail_phi_26"
#elif defined(R5ND_0CPA_0fail_phi_27)
#define ROUND5_API_SET 48
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_0fail_phi_27"
#elif defined(R5ND_0CPA_0fail_phi_28)
#define ROUND5_API_SET 49
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_0fail_phi_28"
#elif defined(R5ND_0CPA_0fail_phi_29)
#define ROUND5_API_SET 50
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_0fail_phi_29"
#elif defined(R5ND_0CPA_xfail_ntru_0)
#define ROUND5_API_SET 51
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_xfail_ntru_0"
#elif defined(R5ND_0CPA_xfail_ntru_1)
#define ROUND5_API_SET 52
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_xfail_ntru_1"
#elif defined(R5ND_0CPA_xfail_ntru_2)
#define ROUND5_API_SET 53
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_xfail_ntru_2"
#elif defined(R5ND_0CPA_xfail_ntru_3)
#define ROUND5_API_SET 54
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_xfail_ntru_3"
#elif defined(R5ND_0CPA_xfail_ntru_4)
#define ROUND5_API_SET 55
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_xfail_ntru_4"
#elif defined(R5ND_0CPA_xfail_ntru_5)
#define ROUND5_API_SET 56
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_xfail_ntru_5"
#elif defined(R5ND_0CPA_xfail_ntru_6)
#define ROUND5_API_SET 57
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_xfail_ntru_6"
#elif defined(R5ND_0CPA_xfail_ntru_7)
#define ROUND5_API_SET 58
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_xfail_ntru_7"
#elif defined(R5ND_0CPA_xfail_ntru_8)
#define ROUND5_API_SET 59
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_xfail_ntru_8"
#elif defined(R5ND_0CPA_xfail_ntru_9)
#define ROUND5_API_SET 60
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_xfail_ntru_9"
#elif defined(R5ND_0CPA_xfail_ntru_10)
#define ROUND5_API_SET 61
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_xfail_ntru_10"
#elif defined(R5ND_0CPA_xfail_ntru_11)
#define ROUND5_API_SET 62
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_xfail_ntru_11"
#elif defined(R5ND_0CPA_xfail_ntru_12)
#define ROUND5_API_SET 63
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_xfail_ntru_12"
#elif defined(R5ND_0CPA_xfail_ntru_13)
#define ROUND5_API_SET 64
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_xfail_ntru_13"
#elif defined(R5ND_0CPA_xfail_ntru_14)
#define ROUND5_API_SET 65
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_xfail_ntru_14"
#elif defined(R5ND_0CPA_xfail_ntru_15)
#define ROUND5_API_SET 66
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_xfail_ntru_15"
#elif defined(R5ND_0CPA_xfail_ntru_16)
#define ROUND5_API_SET 67
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_xfail_ntru_16"
#elif defined(R5ND_0CPA_xfail_ntru_17)
#define ROUND5_API_SET 68
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_xfail_ntru_17"
#elif defined(R5ND_0CPA_xfail_ntru_18)
#define ROUND5_API_SET 69
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_xfail_ntru_18"
#elif defined(R5ND_0CPA_xfail_ntru_19)
#define ROUND5_API_SET 70
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_xfail_ntru_19"
#elif defined(R5ND_0CPA_xfail_ntru_20)
#define ROUND5_API_SET 71
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_xfail_ntru_20"
#elif defined(R5ND_0CPA_xfail_ntru_21)
#define ROUND5_API_SET 72
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_xfail_ntru_21"
#elif defined(R5ND_0CPA_xfail_ntru_22)
#define ROUND5_API_SET 73
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_xfail_ntru_22"
#elif defined(R5ND_0CPA_xfail_ntru_23)
#define ROUND5_API_SET 74
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_xfail_ntru_23"
#elif defined(R5ND_0CPA_xfail_ntru_24)
#define ROUND5_API_SET 75
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_xfail_ntru_24"
#elif defined(R5ND_0CPA_xfail_ntru_25)
#define ROUND5_API_SET 76
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_xfail_ntru_25"
#elif defined(R5ND_0CPA_xfail_ntru_26)
#define ROUND5_API_SET 77
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_xfail_ntru_26"
#elif defined(R5ND_0CPA_xfail_ntru_27)
#define ROUND5_API_SET 78
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_xfail_ntru_27"
#elif defined(R5ND_0CPA_xfail_ntru_28)
#define ROUND5_API_SET 79
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_xfail_ntru_28"
#elif defined(R5ND_0CPA_xfail_ntru_29)
#define ROUND5_API_SET 80
#define CRYPTO_SECRETKEYBYTES 16
#define CRYPTO_PUBLICKEYBYTES 716
#define CRYPTO_BYTES 16
#define CRYPTO_CIPHERTEXTBYTES 764
#define CRYPTO_ALGNAME "R5ND_0CPA_xfail_ntru_29"
#else
#error You must define one of: R5ND_1CPA_0d, R5ND_3CPA_0d, R5ND_5CPA_0d, R5ND_1CCA_0d, R5ND_3CCA_0d, R5ND_5CCA_0d, R5ND_1CPA_5d, R5ND_3CPA_5d, R5ND_5CPA_5d, R5ND_1CCA_5d, R5ND_3CCA_5d, R5ND_5CCA_5d, R5N1_1CPA_0d, R5N1_3CPA_0d, R5N1_5CPA_0d, R5N1_1CCA_0d, R5N1_3CCA_0d, R5N1_5CCA_0d, R5ND_0CPA_2iot, R5ND_1CPA_4longkey, R5N1_3CCA_0smallCT, R5ND_0CPA_0fail_phi_0, R5ND_0CPA_0fail_phi_1, R5ND_0CPA_0fail_phi_2, R5ND_0CPA_0fail_phi_3, R5ND_0CPA_0fail_phi_4, R5ND_0CPA_0fail_phi_5, R5ND_0CPA_0fail_phi_6, R5ND_0CPA_0fail_phi_7, R5ND_0CPA_0fail_phi_8, R5ND_0CPA_0fail_phi_9, R5ND_0CPA_0fail_phi_10, R5ND_0CPA_0fail_phi_11, R5ND_0CPA_0fail_phi_12, R5ND_0CPA_0fail_phi_13, R5ND_0CPA_0fail_phi_14, R5ND_0CPA_0fail_phi_15, R5ND_0CPA_0fail_phi_16, R5ND_0CPA_0fail_phi_17, R5ND_0CPA_0fail_phi_18, R5ND_0CPA_0fail_phi_19, R5ND_0CPA_0fail_phi_20, R5ND_0CPA_0fail_phi_21, R5ND_0CPA_0fail_phi_22, R5ND_0CPA_0fail_phi_23, R5ND_0CPA_0fail_phi_24, R5ND_0CPA_0fail_phi_25, R5ND_0CPA_0fail_phi_26, R5ND_0CPA_0fail_phi_27, R5ND_0CPA_0fail_phi_28, R5ND_0CPA_0fail_phi_29, R5ND_0CPA_xfail_ntru_0, R5ND_0CPA_xfail_ntru_1, R5ND_0CPA_xfail_ntru_2, R5ND_0CPA_xfail_ntru_3, R5ND_0CPA_xfail_ntru_4, R5ND_0CPA_xfail_ntru_5, R5ND_0CPA_xfail_ntru_6, R5ND_0CPA_xfail_ntru_7, R5ND_0CPA_xfail_ntru_8, R5ND_0CPA_xfail_ntru_9, R5ND_0CPA_xfail_ntru_10, R5ND_0CPA_xfail_ntru_11, R5ND_0CPA_xfail_ntru_12, R5ND_0CPA_xfail_ntru_13, R5ND_0CPA_xfail_ntru_14, R5ND_0CPA_xfail_ntru_15, R5ND_0CPA_xfail_ntru_16, R5ND_0CPA_xfail_ntru_17, R5ND_0CPA_xfail_ntru_18, R5ND_0CPA_xfail_ntru_19, R5ND_0CPA_xfail_ntru_20, R5ND_0CPA_xfail_ntru_21, R5ND_0CPA_xfail_ntru_22, R5ND_0CPA_xfail_ntru_23, R5ND_0CPA_xfail_ntru_24, R5ND_0CPA_xfail_ntru_25, R5ND_0CPA_xfail_ntru_26, R5ND_0CPA_xfail_ntru_27, R5ND_0CPA_xfail_ntru_28, R5ND_0CPA_xfail_ntru_29.
/** The API set implemented with the NIST API. */
#define ROUND5_API_SET -1
/** The number of bytes of the secret key (NIST API). */
#define CRYPTO_SECRETKEYBYTES 0
/** The number of bytes of the public key (NIST API). */
#define CRYPTO_PUBLICKEYBYTES 0
/** The number of bytes of the shared secret in case of KEM, the encryption overhead in case of ENCRYPT (NIST API). */
#define CRYPTO_BYTES 0
/** The number of bytes of the cipher text in case of KEM, 0 in case of ENCRYPT (NIST API). */
#define CRYPTO_CIPHERTEXTBYTES 0
#endif

/** The Round5 parameter set parameter values. */
const uint32_t r5_parameter_sets[81][16];

/** The names of the Round5 parameter sets. */
const char *r5_parameter_set_names[81];

/* Default ROUND5_API_TAU to 0 if not yet defined */
#if !defined(ROUND5_API_TAU)
/** Defines the variant tau to use for the creation of A. */
#define ROUND5_API_TAU 0
#endif

/* Default ROUND5_API_TAU2_LEN to 2<<11 if not yet defined (or 0) */
#if !defined(ROUND5_API_TAU2_LEN) || ROUND5_API_TAU2_LEN == 0
#undef ROUND5_API_TAU2_LEN
/**
 * Defines the length of the random vector for the A matrix when A is created using TAU=2.
 * The value 0 (the default) means that the value of parameter _2^11_ will be used.
 *
 * <strong>Important: this must be a power of 2 and larger than parameter _d_!</strong>
 */
#define ROUND5_API_TAU2_LEN (1<<11)
#endif
#if ROUND5_API_TAU2_LEN > (1<<31)
#error ROUND5_API_TAU2_LEN must be less than or equal to 2^31
#endif
#if (ROUND5_API_TAU2_LEN & (ROUND5_API_TAU2_LEN - 1)) != 0
#error ROUND5_API_TAU2_LEN must be a power of two
#endif

#endif /* R5_PARAMETER_SETS_H */
