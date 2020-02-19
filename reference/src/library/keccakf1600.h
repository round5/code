#ifndef _KECCAKF1600_H_
#define _KECCAKF1600_H_

//	Importing, build upon:

#include <stddef.h> 
#include <stdint.h>

#include "chooseparameters.h"

//	Reduction of public domain sources.

void KeccakF1600_StateExtractBytes ( uint64_t *state, uint8_t *data Parameters );

void KeccakF1600_StateXORBytes ( uint64_t *state, const uint8_t *data Parameters );

void KeccakF1600_StatePermute( uint64_t * state );

#endif /* _KECCAKF1600_H_ */


