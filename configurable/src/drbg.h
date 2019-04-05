/*
 * Copyright (c) 2018, Koninklijke Philips N.V.
 */

/**
 * @file
 * Declaration of the deterministic random bits (bytes) functions.
 */

#ifndef DRBG_H
#define DRBG_H

#include "little_endian.h"

#include <stdint.h>
#include <stddef.h>

#ifdef DOXYGEN
/* Document DRBG implementation option */
/**
 * The default implementation of the DRBG uses (c)SHAKE for the generation of
 * the deterministic random bytes. To make use of the alternative AES (in CTR
 * mode on zero input blocks) implementation, define `USE_AES_DRBG`.
 * Especially on platforms with good hardware accelerated AES instructions, this
 * can be an advantage.
 */
#define USE_AES_DRBG
#undef USE_AES_DRBG
#endif

/**
 * Macro for the initialization code for generating uniformly distributed random numbers.
 * Use this macro before you use the macro `DRBG_SAMPLER16` itself.
 *
 * Important: the drbg itself needs to be initialized with `drbg_init()`.
 *
 * @param[in] range the upper limit of the range (exclusive)
 */
#define DRBG_SAMPLER16_INIT(range) \
    const uint32_t DRBG_SAMPLER16_range_divisor = (uint32_t) (0x10000 / range); \
    const uint32_t DRBG_SAMPLER16_range_limit = range * DRBG_SAMPLER16_range_divisor

/**
 * Macro to generates a uniformly distributed random number in the previously
 * set up range (see macro `DRBG_SAMPLER16_INIT`).
 *
 * Important: the drbg itself needs to be initialized with `drbg_init()`
 * (or `drbg_init_customization()`.
 *
 * @param[out] x     the variable to assign the random number to
 * @param[in]  range the range (ignored, must be set with `DRBG_SAMPLER16_INIT()`)
 */
#define DRBG_SAMPLER16(x, range) \
    do { \
        drbg(&x, sizeof (x)); \
        x = (uint16_t) LITTLE_ENDIAN16(x); \
    } while (x >= DRBG_SAMPLER16_range_limit); \
    x = (uint16_t) (x / DRBG_SAMPLER16_range_divisor)

#ifdef __cplusplus
extern "C" {
#endif

    /**
     * Initializes the deterministic random number generator.
     *
     * @param[in] seed      the seed to use for the deterministic number generator
     * @param[in] seed_size the size of the seed (must be 16, 24, or 32 bytes when USE_AES_DRBG is defined)
     */
    void drbg_init(const void *seed, const size_t seed_size);

    /**
     * Initializes the deterministic random number generator with the specified
     * customization string.
     *
     * @param[in] seed              the seed to use for the deterministic number generator
     * @param[in] seed_size         the size of the seed (must be 16, 24, or 32 bytes when USE_AES_DRBG is defined)
     * @param[in] customization     the customization string to use
     * @param[in] customization_len the length of the customization string
     */
    void drbg_init_customization(const void *seed, const size_t seed_size, const uint8_t *customization, const size_t customization_len);

    /**
     * Generates the next sequence of deterministic random bytes using the
     * (initial) seed as set with `drbg_init()`.
     *
     * @param[out] x    destination of the random bytes
     * @param[in]  xlen the number of deterministic random bytes to generate
     * @return __0__ in case of success
     */
    int drbg(void *x, const size_t xlen);

    /**
     * Generates the next uniformly distributed random number in the given
     * range using the (initial) seed as set with `drbg_init()`.
     *
     * Note: since this function re-calculates internal range factors, it is
     * better to use the `DRBG_SAMPLER16_INIT()` and `DRBG_SAMPLER16()` macros when
     * generating multiple random numbers.
     *
     * We use the "scaled" random number trick to quickly generate uniformly
     * distributed random numbers in a range.
     *
     * We scale the range so it is very close to a power of two (2^16 in this
     * case) and then scale back to get random number in the correct range.
     * This is much better than the normal approach since the number of rejects
     * is much smaller. For instance say we want to generate numbers in the
     * range 0-700, the normal approach would generate numbers in the range
     * 0-1023 and then retry if it was > 700. This is more than 30% rejects!
     * The scale trick on the other hand generates number in the range 0-65535
     * of which it only rejects if it was > 65.100, which happens in less than
     * 1% of the cases!
     *
     * @param range the maximum value (exclusive)
     * @return the next random number in the range _[0..range)_
     */
    uint16_t drbg_sampler16(const uint32_t range);

    /**
     * Generates the next sequence of deterministic random numbers using the
     * (initial) seed as set with `drbg_init()`.
     *
     * @return the next random number in the range _[0..2^16)_
     */
    uint16_t drbg_sampler16_2();
    /**
     * Macro override of `drbg_sampler16_2()` to ignore the range parameter at
     * compile time.
     *
     * @param[in]  range  the maximum value (exclusive) <strong>ignored</strong>
     * @return the next random number in the range _[0..2^16)_
     */
#define drbg_sampler16_2(range) drbg_sampler16_2()

    /**
     * Generates a sequence of deterministic random numbers using the given seed.
     * Can only be used to generate a single sequence of random numbers from the
     * given seed.
     *
     * Use this function to generate a fixed number of deterministic numbers
     * from a seed. It is faster than calling `drbg_init()` and
     * `drbg_sampler16_2()` separately.
     *
     * @param[out] x         destination of the random numbers
     * @param[in]  xlen      the number of deterministic random numbers to generate
     * @param[in]  seed      the seed to use for the deterministic number generator
     * @param[in]  seed_size the size of the seed (must be 16, 24, or 32 bytes when USE_AES_DRBG is defined)
     * @return __0__ in case of success
     */
    int drbg_sampler16_2_once(uint16_t *x, const size_t xlen, const void *seed, const size_t seed_size);
    /**
     * Macro override of `drbg_sampler16_2_once()` to ignore the range parameter
     * at compile time.
     *
     * @param[out] x         destination of the random numbers
     * @param[in]  xlen      the number of deterministic random numbers to generate
     * @param[in]  seed      the seed to use for the deterministic number generator
     * @param[in]  seed_size the size of the seed (must be 16, 24, or 32 bytes when USE_AES_DRBG is defined)
     * @param[in]  range     the maximum value (exclusive) <strong>ignored</strong>
     */
#define drbg_sampler16_2_once(x, xlen, seed, seed_size, range) drbg_sampler16_2_once(x, xlen, seed, seed_size)

    /**
     * Generates a sequence of deterministic random numbers using the given seed
     * and customization string.
     * Can only be used to generate a single sequence of random numbers from the
     * given seed.
     *
     * Use this function to generate a fixed number of deterministic numbers
     * from a seed. It is faster than calling `drbg_init()` and
     * `drbg_sampler16_2()` separately.
     *
     * @param[out] x                 destination of the random numbers
     * @param[in]  xlen              the number of deterministic random numbers to generate
     * @param[in]  seed              the seed to use for the deterministic number generator
     * @param[in]  seed_size         the size of the seed (must be 16, 24, or 32 bytes when USE_AES_DRBG is defined)
     * @param[in]  customization     the customization string to use
     * @param[in]  customization_len the length of the customization string
     * @return __0__ in case of success
     */
    int drbg_sampler16_2_once_customization(uint16_t *x, const size_t xlen, const void *seed, const size_t seed_size, const void *customization, const size_t customization_len);
    /**
     * Macro override of `drbg_sampler16_2_once_customization()` to ignore the range parameter
     * at compile time.
     *
     * @param[out] x                 destination of the random numbers
     * @param[in]  xlen              the number of deterministic random numbers to generate
     * @param[in]  seed              the seed to use for the deterministic number generator
     * @param[in]  seed_size         the size of the seed (must be 16, 24, or 32 bytes when USE_AES_DRBG is defined)
     * @param[in]  customization     the customization string to use
     * @param[in]  customization_len the length of the customization string
     * @param[in]  range             the maximum value (exclusive) <strong>ignored</strong>
     */
#define drbg_sampler16_2_once_customization(x, xlen, seed, seed_size, customization, customization_len, range) drbg_sampler16_2_once_customization(x, xlen, seed, seed_size, customization, customization_len)

#ifdef __cplusplus
}
#endif

#endif /* DRBG_H */
