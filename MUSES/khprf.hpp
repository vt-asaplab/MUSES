#pragma once 
#include <types.hpp>
#include <config.hpp>
#include <openssl/sha.h>
#include <iostream>
#include <utils.hpp>
#include <emp-tool/emp-tool.h>

using namespace std; 

extern modp_t  ***hashed_states;
extern int     num_parties;

modp_t eval(poly_modq_t key, int wid, int i) {

    modq_t temp = 0;

    for(int j = 0; j < N; ++j) 
        temp = (temp + hashed_states[wid][i][j] * key[j]) & MASK_Q;
    
    modp_t output = (temp << P) >> Q;
    return output;
}

void share(poly_modq_t key, poly_modq_t *shared_keys) {
    PRG prg;
    for(int i = 0; i < N; ++i) {
        int s = 0;
        for(int j = 0; j < num_parties - 1; ++j) {
            prg.random_data(&shared_keys[j][i], sizeof(modq_t));
            shared_keys[j][i] &= MASK_Q;
            s = (s + shared_keys[j][i]) & MASK_Q;
        }
        shared_keys[num_parties-1][i]  = (key[i] - s + (1<<Q)) & MASK_Q;
    }
}
