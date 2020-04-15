/*
 * Copyright (c) 2020, Koninklijke Philips N.V.
 */

#include "checkPublicParameter.h"

#ifdef CM_MALFORMED

#include "r5_parameter_sets.h"

#define MAXNBINS 64

int chi2_single_check(modp_t *public_param, uint16_t offset, uint8_t nbins, uint8_t nbinsbits){
    
    uint16_t i, idx;
    uint16_t hist[MAXNBINS] = {0};
    
    for (i=0; i< PARAMS_D; i++){
        idx = ((public_param[i] + offset) >> (PARAMS_P_BITS - nbinsbits)) & (nbins-1);
        hist[idx] += 1;
    }
    
    // chi2 test
    // values scaled-up nbinsbits to make more accurate operations (by Scott)
    uint64_t cv = 0;
    uint64_t aux = 0;
    
    for (i=0 ; i < nbins ; i++){
        aux = (hist[i] << nbinsbits) - PARAMS_D;
        cv += aux*aux;
    }
    cv /= (PARAMS_D << nbinsbits);
    
    if (cv > PARAMS_MAL_C2_TH) {
        return -1;
    }
    
    return 0;
}

int chi2_check(modp_t *public_param, uint16_t offset, uint8_t nbins, uint8_t nbinsbits){
    
    int ret=0;
    ret = chi2_single_check(public_param, 0, nbins, nbinsbits);
    if (ret < 0){
        return -1;
    }
    ret = chi2_single_check(public_param, PARAMS_P/(2*nbins), nbins, nbinsbits);
    if (ret < 0){
        return -1;
    }
    
    return 0;
}


int bin_check(modp_t *public_param){
    
    uint16_t i;
    uint16_t hist[PARAMS_P] = {0};
    
    for (i=0; i< PARAMS_D; i++){
        hist[public_param[i]] += 1;
    }
    
    // binomial test
    for (i=0; i< PARAMS_P; i++){
        if (hist[i] > PARAMS_MAL_BIN_TH) {
            return -1;
        }
    }
    
    return 0;
}


int checkPublicParameter(modp_t *public_param, uint16_t num_vectors){
    
    uint16_t j;
    
    int ret;
    
    uint8_t nbins = 64;
    uint8_t nbinsbits = 6;
    if (PARAMS_D < 640){nbins = 32; nbinsbits = 5;}
  
    // binomial test
    for (j=0; j < num_vectors; j++){
        ret = bin_check(&public_param[j*PARAMS_D]);
        if (ret < 0){
            return -1;
        }
    }
    
    //chi2 test
    for (j=0; j < num_vectors; j++){
        ret = chi2_check(&public_param[j*PARAMS_D], 0, nbins, nbinsbits);
        if (ret < 0){
            return -1;
        }
    }

    return 0;
}

#endif

