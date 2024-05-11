#pragma once

#include <chrono>
#include <future>
#include <vector>

using std::vector;
using std::future;
using std::chrono::time_point;
using std::chrono::high_resolution_clock;

extern int bloom_filter_size;
extern int num_parties;

struct FSSKey {
    block s;
    block cw[16];
    uint8_t t_l[16];
    uint8_t t_r[16];
    uint16_t cw_leaf;
};

struct MPKey {
    block    **sigma;
    uint16_t **a;
    uint16_t **cw;
};

void g(block &seed, block &s_l, uint8_t &t_l, block &s_r, uint8_t &t_r) { 
    PRG prg(&seed);
    prg.random_block(&s_l, 1);
    prg.random_data(&t_l, 1);
    t_l &= 0x1; 
    prg.random_block(&s_r, 1);
    prg.random_data(&t_r, 1);
    t_r &= 0x1;
}

void generate_cw_from_seeds(uint16_t &alpha, uint16_t &beta, block &s_a, block &s_b, block cw[16], 
                            uint8_t t_l[16], uint8_t t_r[16], uint16_t &cw_leaf) {
    uint8_t t_a_i = 0;
    uint8_t t_b_i = 1;

    block s_a_i = s_a;
    block s_b_i = s_b;  

    block   s_a_l, s_a_r, s_b_l, s_b_r;
    uint8_t t_a_l, t_a_r, t_b_l, t_b_r;

    block *s_a_keep, *s_a_lose;
    block *s_b_keep, *s_b_lose;
    uint8_t t_a_keep, t_b_keep;

    for(int i = 0; i < 16; ++i) {
        int bit_i = (alpha >> i) & 0x1;
        
        g(s_a_i, s_a_l, t_a_l, s_a_r, t_a_r);
        g(s_b_i, s_b_l, t_b_l, s_b_r, t_b_r);

        if(bit_i) {
            s_a_keep = &s_a_r; s_a_lose = &s_a_l; t_a_keep = t_a_r;
        } else {
            s_a_keep = &s_a_l; s_a_lose = &s_a_r; t_a_keep = t_a_l;
        }

        if(bit_i) {
            s_b_keep = &s_b_r; s_b_lose = &s_b_l; t_b_keep = t_b_r;
        } else {
            s_b_keep = &s_b_l; s_b_lose = &s_b_r; t_b_keep = t_b_l;
        }

        uint8_t t_cw_l = t_a_l ^ t_b_l ^ bit_i ^ 1;
        uint8_t t_cw_r = t_a_r ^ t_b_r ^ bit_i;
        uint8_t t_cw_keep;
        if(bit_i) t_cw_keep = t_cw_r;
        else t_cw_keep = t_cw_l;

        cw[i]  = *s_a_lose ^ *s_b_lose;
        t_l[i] = t_cw_l;
        t_r[i] = t_cw_r;

        if(t_a_i == 0) {
            s_a_i = *s_a_keep;
            t_a_i = t_a_keep;
        } else {
            s_a_i = *s_a_keep ^ cw[i];
            t_a_i = t_a_keep ^ t_cw_keep;
        }

        if(t_b_i == 0) {
            s_b_i = *s_b_keep;
            t_b_i = t_b_keep;
        } else {
            s_b_i = *s_b_keep ^ cw[i];
            t_b_i = t_b_keep ^ t_cw_keep;
        }
    }
    uint16_t sbi = s_b_i[0] & MASK_P;
    uint16_t sai = s_a_i[0] & MASK_P;
    
    cw_leaf = ((1<<16) + sbi - sai + beta) & MASK_P;
    if(t_b_i) cw_leaf = ((1<<10) - cw_leaf) & MASK_P;
}

void generate_keypair(uint16_t alpha, uint16_t beta, FSSKey &key_a, FSSKey &key_b) {
    PRG prg;
    prg.random_block(&key_a.s, 1);
    prg.random_block(&key_b.s, 1);
    generate_cw_from_seeds(alpha, beta, key_a.s, key_b.s, key_a.cw, key_a.t_l, key_a.t_r, key_a.cw_leaf);
    memcpy(&key_b.cw, &key_a.cw, 16*sizeof(block));
    memcpy(&key_b.t_l, &key_a.t_l, 16*sizeof(uint8_t));
    memcpy(&key_b.t_r, &key_a.t_r, 16*sizeof(uint8_t));
    memcpy(&key_b.cw_leaf, &key_a.cw_leaf, sizeof(uint16_t));
}

uint16_t fss_eval(uint8_t party_id, FSSKey &key, uint16_t x) {
    uint8_t t_i = party_id;
    block   s_i = key.s;

    block   s_l, s_r;
    uint8_t t_l, t_r;
    
    for(int i = 0; i < 16; ++i) {
        int bit_i = (x >> i) & 0x1;
        g(s_i, s_l, t_l, s_r, t_r);
        block s_cw = key.cw[i];
        uint8_t t_cw_l = key.t_l[i];
        uint8_t t_cw_r = key.t_r[i];

        if(bit_i == 0) {
            if(t_i == 0) {
                s_i = s_l;
                t_i = t_l;
            } else {
                s_i = s_l ^ s_cw;
                t_i = t_l ^ t_cw_l;
            }
        } else {
            if(t_i == 0) {
                s_i = s_r;
                t_i = t_r;
            } else {
                s_i = s_r ^ s_cw;
                t_i = t_r ^ t_cw_r;
            }
        }
    }

    uint16_t r;
    if(t_i) {
        r = (key.cw_leaf + s_i[0]) & MASK_P;
    } else {
        r = s_i[0] & MASK_P;
    }
    if(party_id) r = ((1<<P) - r) & MASK_P;
    
    return r;
}

void generate_queries(int index, modp_t **queries) {    
    PRG prg;
    modp_t *sum_queries = new modp_t[bloom_filter_size];
    memset(sum_queries, 0, bloom_filter_size * sizeof(modp_t));

    for(int n = 0; n < nP; ++n) {
        for(int i = 0; i < bloom_filter_size; ++i)  {
            if(n < nP - 1) {
                prg.random_data((void*)&queries[n][i], sizeof(modp_t));
                queries[n][i] &= MASK_P;
                sum_queries[i] = (sum_queries[i] + queries[n][i]) & MASK_P;
            }
            else {
                if(i == index)
                    queries[n][i] = ((1<<P) + 1 - sum_queries[i]) & MASK_P;
                else 
                    queries[n][i] = ((1<<P) - sum_queries[i]) & MASK_P;
                }
        }
    }
    
    delete [] sum_queries;
}

void generate_fss_keys(uint16_t alpha, uint16_t beta, MPKey *keys) {
    PRG prg;
    uint64_t n = 16;
    uint32_t p2 = (uint32_t)(pow(2, num_parties-1));
    uint64_t mu = (uint64_t)ceil((pow(2, n/2.0) * pow(2,(num_parties-1)/2.0)));
    uint64_t v  = (uint64_t)ceil((pow(2, n))/mu);

    uint32_t delta = alpha & ((1 << (n/2)) - 1);
    uint32_t gamma = (alpha & (((1 << (n+1)/2) - 1) << n/2)) >> (n/2);
    uint16_t ***aArr = (uint16_t***)malloc(sizeof(uint16_t**)*v);
    for(int i = 0; i < v; ++i) {
        aArr[i] = (uint16_t**)malloc(sizeof(uint16_t*)*num_parties);
        for(int j = 0; j < num_parties; ++j) 
            aArr[i][j] = (uint16_t*)malloc(p2*sizeof(uint16_t));
    }

    uint16_t *sum = new uint16_t[p2];
    bool rd;
    for(int i = 0; i < v; ++i) {
        memset(sum, 0, p2*sizeof(uint16_t));
        for(int j = 0; j < num_parties; ++j) {
            if(j < num_parties-1) {
                prg.random_data(aArr[i][j], p2*sizeof(uint16_t));
                for(int k = 0; k < p2; ++k) {
                    if(aArr[i][j][k] & 0x1) aArr[i][j][k] &= MASK_P;
                    else aArr[i][j][k] = 0;
                }
            } else {
                for(int k = 0; k < p2; ++k) {
                    uint16_t sum = 0;
                    for(int l = 0; l < num_parties - 1; ++l) 
                        sum = (sum + aArr[i][l][k]) & MASK_P;
                    if(i != gamma) {
                        aArr[i][j][k] = ((1<<10) - sum) & MASK_P;
                    } else {
                        aArr[i][j][k] = ((1<<10) + 1 - sum) & MASK_P;
                    }
                }
            }
        }
    }
    delete [] sum;
    
    block **seeds = new block*[v];
    for(int i = 0; i < v; ++i) {
        seeds[i] = new block[p2];
        prg.random_block(seeds[i], p2);
    }

    uint16_t **cw = new uint16_t*[p2];
    uint16_t *cw_temp = new uint16_t[mu];
    memset(cw_temp, 0, sizeof(uint16_t)*mu);
    uint16_t *output_prg = new uint16_t[mu];
    PRG prg_once;

    for (int i = 0; i < p2 - 1; ++i) {
        cw[i] = new uint16_t[mu];
        prg_once.reseed(&seeds[gamma][i]);
        prg_once.random_data(output_prg, mu*sizeof(uint16_t));
        prg.random_data(cw[i], mu*sizeof(uint16_t));
        for(int j = 0; j < mu; ++j) {
            cw[i][j]      &= MASK_P;
            output_prg[j] &= MASK_P;
            cw_temp[j]     = (cw_temp[j] + cw[i][j] + output_prg[j]) & MASK_P;
        }
    }
    
    prg_once.reseed(&seeds[gamma][p2-1]);
    prg_once.random_data(output_prg, mu*sizeof(uint16_t));
    for(int i = 0; i < mu; ++i) {
        output_prg[i] &= MASK_P;
        cw_temp[i]     = (cw_temp[i] + output_prg[i]) & MASK_P;
    }

    cw[p2-1] = new uint16_t[mu];
    for(int i = 0; i < mu; ++i) {
        if (i == delta) 
            cw[p2-1][i] = ((1<<10) + beta - cw_temp[i]) & MASK_P;
        else 
            cw[p2-1][i] = ((1<<10) - cw_temp[i]) & MASK_P;
    }

    delete [] cw_temp;
    delete [] output_prg;

    block ***sigma = (block***) malloc(sizeof(block**)* num_parties);
    for (int i = 0; i < num_parties; i++) {
        sigma[i] = (block**) malloc(sizeof(block*)*v);
        for (int j = 0; j < v; j++) {
            sigma[i][j] = (block*) malloc(sizeof(block)*p2);
            for (int k = 0; k < p2; k++) {
                if (aArr[j][i][k] == 0) {
                    memset(&sigma[i][j][k], 0, sizeof(block));
                } else {
                    memcpy(&sigma[i][j][k], &seeds[j][k], sizeof(block));
                }
            }
        }
    }

    for(int n = 0; n < num_parties; ++n) {
        keys[n].sigma = sigma[n];
        keys[n].cw    = cw;
        keys[n].a     = new uint16_t*[v];
        for(int i = 0; i < v; ++i) {
            keys[n].a[i] = new uint16_t[p2];
            for(int j = 0; j < p2; ++j) {
                keys[n].a[i][j] = aArr[i][n][j];
            }
        }
    }
}

uint16_t eval_fss_keys(MPKey *key, uint16_t x) {
    uint64_t n = 16;
    uint32_t p2 = (uint32_t)(pow(2, num_parties-1));
    uint64_t mu = (uint64_t)ceil((pow(2, n/2.0) * pow(2,(num_parties-1)/2.0)));

    // sigma is last n/2 bits
    uint32_t delta = x & ((1 << (n/2)) - 1);
    uint32_t gamma = (x & (((1 << (n+1)/2) - 1) << n/2)) >> (n/2);

    block    **sigma = key->sigma;
    uint16_t **aArr  = key->a;
    uint16_t **cw    = key->cw;
    
    uint16_t *output_prg = new uint16_t[mu];
    PRG prg_once;
    uint16_t *y = new uint16_t[mu];
    memset(y, 0, mu*sizeof(uint16_t));

    for (int i = 0; i < p2; i++) {
        uint8_t *block_data = (uint8_t*)&sigma[gamma][i];
        bool is_empty = true;
        for(int j = 0; j < 16; ++j) {
            if(block_data[j]) {
                is_empty = false;
                break;
            } 
        }
        if(is_empty == false) {
            prg_once.reseed(&sigma[gamma][i]);
            prg_once.random_data(output_prg, mu*sizeof(uint16_t));
            for (int k = 0; k < mu; k++) {
                y[k] = (y[k] + aArr[gamma][i]*(output_prg[k] + cw[i][k])) & MASK_P;
            }
        }
    }
    
    uint16_t y_final = y[delta];
    delete [] y;
    delete [] output_prg;

    return y_final;
}
