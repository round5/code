/*
 * Copyright (c) 2020, Koninklijke Philips N.V.
 */

/**
 * @file
 * Definition of the hash functions as used within Round5.
 */

#include "r5_hash.h"
#include "f202sp800185.h"

inline void HCPAKEM
(uint8_t *output, uint32_t outputLength,
 const uint8_t *firstInput, uint16_t firstInputLength,
 const uint8_t *secondInput, uint32_t secondInputLength
 Parameters )
    {   const uint8_t d[7] = "HCPAKEM";
        r5_tuple_hash(output, outputLength, d, 7, firstInput, firstInputLength, secondInput, secondInputLength, 3 Params);
    }

inline void HCCAKEM
( uint8_t *output, uint32_t outputLength,
 const uint8_t *firstInput, uint16_t firstInputLength,
 const uint8_t *secondInput, uint32_t secondInputLength
 Parameters )
    {
        const uint8_t d[7] = "HCCAKEM";
        r5_tuple_hash(output, outputLength, d, 7, firstInput, firstInputLength, secondInput, secondInputLength, 3 Params);
    }

inline void GCCAKEM
(uint8_t *output, uint32_t outputLength,
 const uint8_t *firstInput, uint16_t firstInputLength,
 const uint8_t *secondInput, uint32_t secondInputLength
 Parameters )
    {
        const uint8_t d[7] = "GCCAKEM";
        r5_tuple_hash(output, outputLength, d, 7, firstInput, firstInputLength, secondInput, secondInputLength, 3 Params);
    }

inline void HashR5DEM
(uint8_t *output, uint32_t outputLength,
 const uint8_t *firstInput, uint16_t firstInputLength
 Parameters )
{
    const uint8_t d[6] = "HR5DEM";
    r5_tuple_hash(output, outputLength, d, 6, firstInput, firstInputLength, NULL, 0, 2 Params);
}
