#pragma once
#include <random>
#include <types.hpp>
#include <khprf.hpp>
#include <ThreadPool.h>
#include "pke/pke.hpp"

extern int       party;
extern int       port; 
extern int       num_writers;
extern int       bloom_filter_size;
extern int       num_documents;
extern int       num_parties; 

uint64_t         **states;
modp_t           ***hashed_states;
modp_t           ***search_index;
modp_t           ***encrypted_search_index;
private_token_t  **private_tokens;
secret_token_t   **secret_tokens;

// Secret keys
poly_modq_t     **column_keys;

std::random_device rd;
std::mt19937 gen(2023);
std::uniform_int_distribution<modp_t> dis(0, 1);

void init_search_index() {
    // This function is used for fast initialization
    states = new uint64_t*[num_writers];
    for(int wid = 0; wid < num_writers; ++wid) {
        states[wid] = (uint64_t*)malloc(num_documents*sizeof(uint64_t));
        for(int i = 0; i < num_documents; ++i)
            states[wid][i] = 0;
    }
    
    // Test simulated data
    int max_num_1_bits = num_documents * 9 / 25;
    search_index = new modp_t**[num_writers];
    for(int wid = 0; wid < num_writers; ++wid) {
        search_index[wid] = new modp_t*[bloom_filter_size];
        for(int i = 0; i < bloom_filter_size; ++i) {
            search_index[wid][i] = new modp_t[num_documents];
            int count_1_bits = 0;
            for(int j = 0; j < num_documents - N_S; ++j) {
                search_index[wid][i][j] = dis(gen);
                if(search_index[wid][i][j]) count_1_bits++;
            }
            while(count_1_bits > max_num_1_bits) {
                int p = gen() % (num_documents - N_S);
                if(search_index[wid][i][p]) {
                    search_index[wid][i][p] = 0;
                    count_1_bits--;
                }
            }
        }
    }
}

void compute_hashed_states() {
    hashed_states = new modp_t**[num_writers];
    for(int wid = 0; wid < num_writers; ++wid) {
        hashed_states[wid] = new modp_t*[num_documents];
        for(int i = 0; i < num_documents; ++i)
            hashed_states[wid][i] = new modp_t[N];
    }
    
    vector<future<void>> works;
    ThreadPool pool(MAX_THREADS);
    int size_per_thread = num_documents/MAX_THREADS;

    for(int wid = 0; wid < num_writers; ++wid) {
        for(int t = 0; t < MAX_THREADS; ++t) {
            works.push_back(pool.enqueue([wid, t, size_per_thread]() {
                SHA256_CTX sha256;  
                unsigned char hash[SHA256_DIGEST_LENGTH];

                int start = t * size_per_thread;
                int end   = start + size_per_thread;
                
                uint8_t seed[16];
                for(int i = start; i < end; ++i) {
                    memcpy(seed, &i, 4);
                    memcpy(seed + 4, &states[wid][i], sizeof(uint64_t));
                    
                    for(int j = 0; j < N; ++j) {
                        memcpy(seed + 12, &j, 4);
                        SHA256_Init(&sha256);
                        SHA256_Update(&sha256, seed, 16);
                        SHA256_Final(hash, &sha256);
                        hashed_states[wid][i][j] = hash[0] | ((hash[1] & 0x1F) << 8);
                    }
                }
            }));
        }
        joinNclean(works);    
    }
}

void deallocate_hashed_states() {
    for(int wid = 0; wid < num_writers; ++wid) {
        for(int i = 0; i < num_documents; ++i)
            delete [] hashed_states[wid][i];
        delete [] hashed_states[wid];
    }
    delete [] hashed_states;
}

void init_column_keys() {
    PRG prg;
    // The following seed is to let the servers generate the same column keys at the beginning 
    // instead of having the client upload data to initialize
    prg.reseed((block*)"FEDCBA9876543210");
    column_keys = (poly_modq_t**)malloc(bloom_filter_size*sizeof(poly_modq_t*));
    for(int wid = 0; wid < num_writers; ++wid) {
        column_keys[wid] = (poly_modq_t*)malloc(bloom_filter_size*sizeof(poly_modq_t));
        for(int i = 0; i < bloom_filter_size; ++i) {
            for(int j = 0; j < N; ++j) {
                prg.random_data(&column_keys[wid][i][j], sizeof(modq_t));
                column_keys[wid][i][j] &= MASK_Q;
            }
        }
    }
    
    unsigned char *iv = (unsigned char *)"0123456789012345";
    secret_tokens = new secret_token_t*[num_writers];
    for(int wid = 0; wid < num_writers; ++wid) {
        unsigned char secret_key[32];
        prg.reseed((block*)"generaterwritersecretkeys", wid);
        prg.random_block((block*)secret_key, 2);

        secret_tokens[wid] = new secret_token_t[bloom_filter_size];
        for(int i = 0; i < bloom_filter_size; ++i) {
            int ciphertext_len = encrypt((unsigned char*)&column_keys[wid][i], (int)sizeof(poly_modq_t), 
                                          secret_key, iv, (unsigned char*)&secret_tokens[wid][i]);
        }   
    }
    
    private_tokens = new private_token_t*[num_writers];
    for(int wid = 0; wid < num_writers; ++wid) {
        private_tokens[wid] = new private_token_t[bloom_filter_size];
        for(int i = 0; i < bloom_filter_size; ++i) {
            pk_encrypt((uint8_t*)&column_keys[wid][i], (uint8_t*)&private_tokens[wid][i]);
        }   
    }
}

void init_encrypted_search_index() {
    vector<future<void>> works;
    ThreadPool pool(MAX_THREADS);
    int size_per_thread = num_documents/MAX_THREADS;

    encrypted_search_index = (modp_t***)malloc(num_writers*sizeof(modp_t**));
    for(int wid = 0; wid < num_writers; ++wid) {
        encrypted_search_index[wid] = (modp_t**)malloc(bloom_filter_size*sizeof(modp_t*));
        for(int i = 0; i < bloom_filter_size; ++i) {
            encrypted_search_index[wid][i] = (modp_t*)malloc(num_documents*sizeof(modp_t));
            for(int t = 0; t < MAX_THREADS; ++t) {
                works.push_back(pool.enqueue([t, wid, size_per_thread, i]() 
                {
                    int start = t * size_per_thread;
                    int end   = start + size_per_thread;
                    for(int j = start; j < end; ++j) {
                        encrypted_search_index[wid][i][j]  = (search_index[wid][i][j]<<E) + eval(column_keys[wid][i], wid, j);
                        encrypted_search_index[wid][i][j] &= MASK_P;                
                    }
                }));
            }
            joinNclean(works); 
        }

        for(int i = 0; i < bloom_filter_size; ++i) 
            delete search_index[wid][i];
	
	delete [] search_index[wid];
    }
    
    delete [] search_index;
}

void generate_queries(int index, modp_t *q1, modp_t *q2) {    
    PRG prg;
    prg.reseed((block*)"generatesearchquery");
    for(int i = 0; i < bloom_filter_size; ++i)  {
        prg.random_data((void*)&q1[i], sizeof(modp_t));
        q1[i] &= MASK_P;
        if(i == index)
            q2[i] = ((1<<P) + 1 - q1[i]) & MASK_P;
        else 
            q2[i] = ((1<<P) - q1[i]) & MASK_P;
    }
}

void retrieve_BF_index(int wid, modp_t *query, poly_modq_t key, modp_t *data_out) {
    memset(data_out, 0, num_documents*sizeof(modp_t));

    vector<future<void>> works;
    ThreadPool pool(MAX_THREADS);
    
    int size_per_thread = num_documents/MAX_THREADS;
    for(int t = 0; t < MAX_THREADS; ++t) {
        works.push_back(pool.enqueue([t, wid, size_per_thread, query, key, data_out]() 
		{
            int start = t * size_per_thread;
            int end   = start + size_per_thread;

            for(int i = 0; i < bloom_filter_size; ++i) {
                for(int j = start; j < end; ++j) {
                    data_out[j] = (data_out[j] + (uint32_t)query[i] * encrypted_search_index[wid][i][j]) & MASK_P;
                }    
            }
        }));
    }

    joinNclean(works); 
    
    for(int t = 0; t < MAX_THREADS; ++t) {
        works.push_back(pool.enqueue([t, wid, size_per_thread, key, data_out]() 
		{
            int start = t * size_per_thread;
            int end   = start + size_per_thread;
            for(int i = start; i < end; ++i) 
                data_out[i] = (data_out[i] - eval(key, wid, i)) & MASK_P;
        }));
    }
    
    joinNclean(works); 
}

void update_BF_document(int wid, int file_id) {
    vector<future<void>> works;
    ThreadPool pool(MAX_THREADS);
    
    // Increment state counter value
    states[wid][file_id] += 1;

    SHA256_CTX sha256;  
    unsigned char hash[SHA256_DIGEST_LENGTH];

    uint8_t seed[16];
    memcpy(seed, &file_id, 4);
    memcpy(seed + 4, &states[wid][file_id], sizeof(uint64_t));
    
    for(int i = 0; i < N; ++i) {
        memcpy(seed + 12, &i, 4);
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, seed, 16);
        SHA256_Final(hash, &sha256);
        hashed_states[wid][file_id][i] = hash[0] | ((hash[1] & 0x1F) << 8);
    } 
}

void update_secret_key(int wid, uint8_t *secret_shared_key) {
    // Writer
    // auto start = clock_start();
    poly_modq_t *key = new poly_modq_t[bloom_filter_size];
    
    for(int i = 0; i < bloom_filter_size; ++i) {
        memcpy(&key[i], secret_shared_key, sizeof(poly_modq_t));
        secret_shared_key += sizeof(poly_modq_t);
    }
    
    poly_modq_t *new_key = new poly_modq_t[bloom_filter_size];
    for(int i = 0; i < bloom_filter_size; ++i) {
        memcpy(&new_key[i], secret_shared_key, sizeof(poly_modq_t));
        secret_shared_key += sizeof(poly_modq_t);
    }

    // cout << "[Permission Revocation] Writer time: " << time_from(start) << endl;

    // Server(s)
    // auto start = clock_start();

    modp_t ***masks         = new modp_t**[num_parties];
    modp_t ***removed_parts = new modp_t**[num_parties];
    modp_t ***added_parts   = new modp_t**[num_parties];
    
    for(int i = 0; i < num_parties; ++i) {
        masks[i]         = new modp_t*[bloom_filter_size];
        removed_parts[i] = new modp_t*[bloom_filter_size];
        added_parts[i]   = new modp_t*[bloom_filter_size];
        for(int j = 0; j < bloom_filter_size; ++j) {
            masks[i][j]         = new modp_t[num_documents];
            removed_parts[i][j] = new modp_t[num_documents];
            added_parts[i][j]   = new modp_t[num_documents];
        }
    }

    PRG prg;
    
    vector<future<void>> works;
    ThreadPool pool(MAX_THREADS);
    
    int size_per_thread = num_documents/MAX_THREADS;
    for(int i = 0; i < bloom_filter_size; ++i) {
        for(int t = 0; t < MAX_THREADS; ++t) {
            works.push_back(pool.enqueue([wid, i, t, size_per_thread, masks, removed_parts, added_parts, key, new_key]() {
                PRG prg;
                int start = t * size_per_thread;
                int end   = start + size_per_thread;

                for(int j = start; j < end; ++j) {
                    prg.random_data(&masks[party-1][i][j], sizeof(modp_t));
                    masks[party-1][i][j]       <<= E;
                    removed_parts[party-1][i][j] = ((1<<P) + masks[party-1][i][j] - eval(key[i], wid, j) + MAX_E) & MASK_P;
                    added_parts[party-1][i][j]   = ((1<<P) - masks[party-1][i][j] + eval(new_key[i], wid, j)) & MASK_P;
                }
            }));
        }
        joinNclean(works);
    }

    modp_t *send_buffer = new modp_t[num_documents*sizeof(modp_t)];
    modp_t *recv_buffer = new modp_t[num_documents*sizeof(modp_t)];
    NetIOMP<nP> *io     = new NetIOMP<nP>(party, port);

    for(int partyID = 1; partyID <= num_parties; ++partyID) {
        if(partyID != party) {
            // Thread for sending
            std::thread ts([io, partyID, removed_parts, added_parts, send_buffer](){
                for(int i = 0; i < bloom_filter_size; ++i) {
                    memcpy(send_buffer, removed_parts[party-1][i], num_documents * sizeof(modp_t));
                    io->send_data(partyID, send_buffer, num_documents*sizeof(modp_t));
                }

                for(int i = 0; i < bloom_filter_size; ++i) {
                    memcpy(send_buffer, added_parts[party-1][i], num_documents * sizeof(modp_t));
                    io->send_data(partyID, send_buffer, num_documents*sizeof(modp_t));
                }
            });

            // Thread for receiving
            std::thread rs([io, partyID, recv_buffer, removed_parts, added_parts](){
                modp_t *recv_ptr = recv_buffer;
                for(int i = 0; i < bloom_filter_size; ++i) {
                    io->recv_data(partyID, recv_buffer, num_documents*sizeof(modp_t));
                    memcpy(removed_parts[partyID-1][i], recv_buffer, num_documents * sizeof(modp_t));
                }
                
                for(int i = 0; i < bloom_filter_size; ++i) {
                    io->recv_data(partyID, recv_buffer, num_documents*sizeof(modp_t));
                    memcpy(added_parts[partyID-1][i], recv_buffer, num_documents * sizeof(modp_t));
                }

            });
            ts.join();
            rs.join();
        }
    }

    delete [] send_buffer; 
    delete [] recv_buffer; 
    delete    io;

    // Example for working of a server (P1)
    for(int i = 0; i < bloom_filter_size; ++i) {
        for(int t = 0; t < MAX_THREADS; ++t) {
            works.push_back(pool.enqueue([wid, i, t, size_per_thread, removed_parts, added_parts]() {
                int start = t * size_per_thread;
                int end   = start + size_per_thread;
                for(int j = start; j < end; ++j) {
                    for(int k = 0; k < num_parties; ++k) {
                        encrypted_search_index[wid][i][j] += removed_parts[k][i][j];
                        encrypted_search_index[wid][i][j] &= MASK_P;
                    }
                    
                    // Remove errors
                    encrypted_search_index[wid][i][j] >>= E;
                    encrypted_search_index[wid][i][j] <<= E;

                    for(int k = 0; k < num_parties; ++k) {
                        encrypted_search_index[wid][i][j] += added_parts[k][i][j];
                        encrypted_search_index[wid][i][j] &= MASK_P;
                    }
                    
                    encrypted_search_index[wid][i][j] = (encrypted_search_index[wid][i][j] + MAX_E) & MASK_P;
                }
            }));
        }
        joinNclean(works);
    }
    
    // cout << "[Permission Revocation] Server computing time: " << time_from(start) << endl;

    delete [] key;
    delete [] new_key;
    
    for(int i = 0; i < num_parties; ++i) {
        for(int j = 0; j < bloom_filter_size; ++j) {
            delete [] masks[i][j];
            delete [] removed_parts[i][j];
            delete [] added_parts[i][j];
        }
        delete [] masks[i];
        delete [] removed_parts[i];
        delete [] added_parts[i];
    }
    
    delete [] masks;
    delete [] removed_parts;
    delete [] added_parts;
}



