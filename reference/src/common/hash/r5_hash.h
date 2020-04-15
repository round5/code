#ifndef _R5_HASH_H_
#define _R5_HASH_H_

/*
 * Copyright (c) 2020, Koninklijke Philips N.V.
 */

/**
 * @file
 * Definition of the hash function as used within Round5.
 */

#include "f202sp800185.h"

#ifdef __cplusplus
extern "C" {
#endif

extern void HCPAKEM
    ( uint8_t *output, uint32_t outputLength,
     const uint8_t *firstInput, uint16_t firstInputLength,
     const uint8_t *secondInput, uint32_t secondInputLength
     Parameters );

extern void HCCAKEM
    ( uint8_t *output, uint32_t outputLength,
     const uint8_t *firstInput, uint16_t firstInputLength,
     const uint8_t *secondInput, uint32_t secondInputLength
     Parameters );

extern void GCCAKEM
    ( uint8_t *output, uint32_t outputLength,
     const uint8_t *firstInput, uint16_t firstInputLength,
     const uint8_t *secondInput, uint32_t secondInputLength
     Parameters );

extern void HashR5DEM
    ( uint8_t *output, uint32_t outputLength,
     const uint8_t *firstInput, uint16_t firstInputLength
     Parameters );

#ifdef __cplusplus
}
#endif

#endif /* _R5_HASH_H_ */
