#include <iostream>
#include <zmq.hpp>
#include <emp-tool/emp-tool.h>
#include <emp-agmpc/emp-agmpc.h>
#include <openssl/sha.h>
#include "config.hpp"
#include "pke/pke.hpp"
#include "utils.hpp"

zmq::context_t  **context_client;  
zmq::socket_t   **socket_client;

int             num_parties;
int             num_writers;
int             bloom_filter_size;
int             num_documents;
uint8_t         **writer_secret_keys;
uint64_t        bandwidth;

std::random_device rd;
std::mt19937       gen(rd());
MPKey              mp_keys[K][nP];

std::uniform_int_distribution<modp_t> dis(0, 1);

void share(poly_modq_t key, poly_modq_t *shared_keys) {
    PRG prg;
    for(int i = 0; i < N; ++i) {
        int s = 0;
        for(int j = 0; j < num_parties - 1; ++j) {
            prg.random_data(&shared_keys[j][i], sizeof(modq_t));
            shared_keys[j][i] &= MASK_Q;
            s = (s + shared_keys[j][i]) & MASK_Q;
        }
        shared_keys[num_parties-1][i]  = ((1<<Q) + key[i] - s) & MASK_Q;
    }
}

modp_t eval(poly_modq_t key, const modp_t *hashed_state) {
    modq_t temp = 0;

    for(int j = 0; j < N; ++j) 
        temp = (temp + hashed_state[j] * key[j]) & MASK_Q;
    
    modp_t output = (temp << P) >> Q;
    return output;
}

void reader_setup() {
    cout << "Reader setup...";
    setup_public_private_keys();
    cout << "Done" << endl;
}

void writer_setup() {
    cout << "Writer setup...";
    writer_secret_keys = new uint8_t*[num_writers];
    PRG prg;
    for(int wid = 0; wid < num_writers; ++wid) {
        writer_secret_keys[wid] = new uint8_t[32];
        prg.reseed((block*)"generaterwritersecretkeys", wid);
        prg.random_block((block*)writer_secret_keys[wid], 2);
    }
    cout << "Done" << endl;
}

void test_secret_key_update() {
    PRG prg;
    vector<future<void>> works;
    ThreadPool pool(MAX_THREADS);
    int size_per_thread = bloom_filter_size/MAX_THREADS;
    int n_secret_key_update_times = 1;
    
    unsigned char *iv = (unsigned char *)"0123456789012345";

    poly_modq_t **key     = new poly_modq_t*[bloom_filter_size];
    poly_modq_t **new_key = new poly_modq_t*[bloom_filter_size];

    for(int i = 0; i < bloom_filter_size; ++i) {
        key[i]     = new poly_modq_t[num_parties];
        new_key[i] = new poly_modq_t[num_parties];
    }

    poly_modq_t     *column_keys    = new poly_modq_t[bloom_filter_size];
    secret_token_t  *secret_tokens  = new secret_token_t[bloom_filter_size];
    private_token_t *private_tokens = new private_token_t[bloom_filter_size];

    for(int t = 0; t < n_secret_key_update_times; ++t) {
        double writer_time = 0;
        auto   start       = clock_start();
        
        int selected_writer = 0;
        string request      = to_string(selected_writer);

        for(int i = 0; i < nP; ++i) {
            works.push_back(pool.enqueue([i, &request]() {
                zmq::message_t search_request(request.length());
                memcpy((void*)search_request.data(), request.c_str(), request.length());
                socket_client[i]->send(search_request);
            }));
        }
        joinNclean(works);

        zmq::message_t msg_secret_tokens[nP];
        for(int i = 0; i < nP; ++i) {
            works.push_back(pool.enqueue([i, &msg_secret_tokens]() {
                socket_client[i]->recv(&msg_secret_tokens[i]);
                // cout << "Received " << msg_secret_tokens.size() << " bytes from the server" << endl;
            }));
        }
        joinNclean(works);
        
        for(int t = 0; t < MAX_THREADS; ++t) {
            works.push_back(pool.enqueue([t, size_per_thread, selected_writer, iv, &msg_secret_tokens, column_keys, key]() {
                int start = t * size_per_thread;
                int end   = start + size_per_thread;
                uint8_t *msg_secret_tokens_ptr = (uint8_t*)msg_secret_tokens[0].data() + start * sizeof(secret_token_t);

                for(int i = start; i < end; ++i) {
                    secret_token_t stkn; 
                    memcpy(&stkn, msg_secret_tokens_ptr, sizeof(secret_token_t));
                    int ciphertext_len = decrypt(stkn, sizeof(stkn), (unsigned char*)writer_secret_keys[selected_writer], iv, (unsigned char*)&column_keys[i]);
                    share((uint16_t*)&column_keys[i], key[i]);
                    msg_secret_tokens_ptr += sizeof(secret_token_t);
                }
            }));
        }
        joinNclean(works);

        for(int t = 0; t < MAX_THREADS; ++t) {
            works.push_back(pool.enqueue([t, size_per_thread, column_keys]() {
                PRG prg;
                int start = t * size_per_thread;
                int end   = start + size_per_thread;
                for(int i = start; i < end; ++i) {
                    for(int j = 0; j < N; ++j) {
                        prg.random_data(&column_keys[i][j], sizeof(modq_t));
                        column_keys[i][j] &= MASK_Q;
                    }
                }
            }));
        }
        joinNclean(works);
        
        // Rotate both reader and writer's key
        /* Note: Rotating the reader's key requires to announce to all writers to encrypt private tokens */
        // rotate_public_private_keys(); 
        prg.random_block((block*)writer_secret_keys[selected_writer], 2);
        for(int t = 0; t < MAX_THREADS; ++t) {
            works.push_back(pool.enqueue([t, size_per_thread, column_keys, selected_writer, iv, secret_tokens]() {
                int start = t * size_per_thread;
                int end   = start + size_per_thread;
                for(int i = start; i < end; ++i) {
                    int ciphertext_len = encrypt((unsigned char*)&column_keys[i], (int)sizeof(poly_modq_t), 
                                                  writer_secret_keys[selected_writer], iv, (unsigned char*)&secret_tokens[i]);
                }   
            }));
        }
        joinNclean(works);

        writer_time += time_from(start);

        // This latency should be excluded. It is only here for correctness testing 
        // In permission revocation protocol, private keys are not updated
        for(int t = 0; t < MAX_THREADS; ++t) {
            works.push_back(pool.enqueue([t, size_per_thread, column_keys, private_tokens]() {
                NTL::ZZ_p::init(GROUP_ORDER);
                int start = t * size_per_thread;
                int end   = start + size_per_thread;
                for(int i = start; i < end; ++i) 
                    pk_encrypt((uint8_t*)&column_keys[i], (uint8_t*)&private_tokens[i]);
            }));
        }
        joinNclean(works);
        
        start = clock_start();

        for(int t = 0; t < MAX_THREADS; ++t) {
            works.push_back(pool.enqueue([t, size_per_thread, column_keys, new_key]() {
                int start = t * size_per_thread;
                int end   = start + size_per_thread;
                for(int i = start; i < end; ++i) 
                    share(column_keys[i], new_key[i]);
            }));
        }
        joinNclean(works);

        for(int i = 0; i < nP; ++i) {
            works.push_back(pool.enqueue([i, private_tokens, secret_tokens, key, new_key]() {
                zmq::message_t msg_secret_shares_key(bloom_filter_size * (sizeof(private_token_t) + sizeof(secret_token_t) + sizeof(poly_modq_t) * 2));
                uint8_t *msg_secret_shares_key_data = (uint8_t*)msg_secret_shares_key.data();

                for(int j = 0; j < bloom_filter_size; ++j) {
                    memcpy(msg_secret_shares_key_data, private_tokens[j], sizeof(private_token_t));
                    msg_secret_shares_key_data += sizeof(private_token_t);
                }

                for(int j = 0; j < bloom_filter_size; ++j) {
                    memcpy(msg_secret_shares_key_data, secret_tokens[j], sizeof(secret_token_t));
                    msg_secret_shares_key_data += sizeof(secret_token_t);
                }

                for(int j = 0; j < bloom_filter_size; ++j) {
                    memcpy(msg_secret_shares_key_data, key[j][i], sizeof(poly_modq_t));
                    msg_secret_shares_key_data += sizeof(poly_modq_t);
                }

                for(int j = 0; j < bloom_filter_size; ++j) {
                    memcpy(msg_secret_shares_key_data, new_key[j][i], sizeof(poly_modq_t));
                    msg_secret_shares_key_data += sizeof(poly_modq_t);
                }
                socket_client[i]->send(msg_secret_shares_key);
            }));
        }
        joinNclean(works);

        writer_time += time_from(start);
		
        cout << "[Permission revocation] Writer latency: " << writer_time << "us" << endl;
        cout << "[Permission revocation] Writer bandwidth: " << nP * bloom_filter_size * (sizeof(private_token_t) + sizeof(poly_modq_t))/(double)1048576.0 << "MB" << endl;
		
        start = clock_start();

        // if(t < n_secret_key_update_times - 1) {
            for(int i = 0; i < nP; ++i) {
                works.push_back(pool.enqueue([i]() {
                    zmq::message_t msg_ack;
                    socket_client[i]->recv(&msg_ack);
                    // cout << "Received \"" << msg_ack.to_string() << "\" from server " << i << endl;
                }));
            }
            joinNclean(works);
        // }
        
        writer_time += time_from(start);
        cout << "[Permission revocation] End-to-end latency: " << writer_time << "us" << endl;
    }

    for(int i = 0; i < bloom_filter_size; ++i) {
        delete [] key[i];
        delete [] new_key[i];
    }

    delete [] column_keys;
    delete [] key;
    delete [] new_key;
    delete [] private_tokens;
    delete [] secret_tokens;
}

void test_document_update() {
    int n_document_update_times = 1;
    srand(time(NULL));
    
    vector<future<void>> works;
    ThreadPool pool(MAX_THREADS);
    int size_per_thread = bloom_filter_size / MAX_THREADS;

    poly_modq_t *column_keys = new poly_modq_t[bloom_filter_size];
    modp_t *data_out = new modp_t[bloom_filter_size];
    modp_t *encrypted_data_out = new modp_t[bloom_filter_size];

    unsigned char *iv = (unsigned char *)"0123456789012345";
    uint8_t seed[16];
    unsigned char hash[SHA256_DIGEST_LENGTH];
    modp_t hashed_state[N];
    SHA256_CTX sha256;

    cout << "============ [Document update] =============" << endl;
    for (int n_execs = 0; n_execs < n_document_update_times; ++n_execs)
    {
        auto start = clock_start();

        int selected_writer = 0;
        int file_id = rand() % num_documents;

        for (int i = 0; i < nP; ++i)
        {
            works.push_back(pool.enqueue([i, selected_writer, file_id]() {
                zmq::message_t msg_writer_id_file_id(sizeof(int) * 2);
                memcpy((uint8_t*)msg_writer_id_file_id.data(), &selected_writer, sizeof(int));
                memcpy((uint8_t*)msg_writer_id_file_id.data() + sizeof(int), &file_id, sizeof(int));
                socket_client[i]->send(msg_writer_id_file_id); 
            }));
        }
        joinNclean(works);

        zmq::message_t msg_secret_tokens[nP];
        for (int i = 0; i < nP; ++i)
        {
            works.push_back(pool.enqueue([i, &msg_secret_tokens]() { 
                socket_client[i]->recv(&msg_secret_tokens[i]); 
            }));
        }
        joinNclean(works);
        
        // cout << "Received " << msg_secret_tokens[0].size() << " bytes from server 0" << endl;

        for (int t = 0; t < MAX_THREADS; ++t)
        {
            works.push_back(pool.enqueue([t, selected_writer, size_per_thread, &msg_secret_tokens, iv, column_keys]() {
                int start = t * size_per_thread;
                int end   = start + size_per_thread;
                uint8_t *decrypted_key = new uint8_t[sizeof(secret_token_t)];
                uint8_t *msg_secret_tokens_ptr = (uint8_t*)msg_secret_tokens[0].data() + start * sizeof(secret_token_t);
                
                for(int i = start; i < end; i++) {
                    int plaintext_len = decrypt(msg_secret_tokens_ptr, sizeof(secret_token_t), (unsigned char*)writer_secret_keys[selected_writer], iv, decrypted_key);
                    memcpy(column_keys[i], decrypted_key, sizeof(poly_modq_t));
                    msg_secret_tokens_ptr += sizeof(secret_token_t);
                } 

                delete [] decrypted_key;
            }));
        }
        joinNclean(works);

        uint64_t counter;   
        memcpy(&counter, (uint8_t*)msg_secret_tokens[0].data() + bloom_filter_size * sizeof(secret_token_t), sizeof(uint64_t));
        // Increment state update counter
        counter++;

        for (int i = 0; i < bloom_filter_size; ++i)
            data_out[i] = dis(gen);

        memcpy(seed, &file_id, 4);
        memcpy(seed + 4, &counter, sizeof(uint64_t));

        for (int j = 0; j < N; ++j)
        {
            memcpy(seed + 12, &j, 4);
            SHA256_Init(&sha256);
            SHA256_Update(&sha256, seed, 16);
            SHA256_Final(hash, &sha256);
            hashed_state[j] = hash[0] | ((hash[1] & 0x1F) << 8);
        }

        for (int t = 0; t < MAX_THREADS; ++t)
        {
            works.push_back(pool.enqueue([t, size_per_thread, data_out, encrypted_data_out, column_keys, hashed_state]() {
                int start = t * size_per_thread;
                int end = start + size_per_thread;
        
                for (int i = start; i < end; ++i)
                    encrypted_data_out[i] = ((data_out[i] << E) + eval(column_keys[i], hashed_state)) & 0x3FF;
            }));
        }
        joinNclean(works);

        for (int i = 0; i < nP; ++i)
        {
            works.push_back(pool.enqueue([i, data_out, encrypted_data_out]() { 
                zmq::message_t msg_updated_data(bloom_filter_size * sizeof(modp_t) * 2);
                // Send plaintext data just for debugging purpose
                memcpy((uint8_t*)msg_updated_data.data(), data_out, bloom_filter_size * sizeof(modp_t));
                memcpy((uint8_t*)msg_updated_data.data() + bloom_filter_size * sizeof(modp_t), encrypted_data_out, bloom_filter_size * sizeof(modp_t));
                socket_client[i]->send(msg_updated_data);
            }));
        }
        joinNclean(works);

        // if(n_execs < n_document_update_times - 1) {
        for (int i = 0; i < nP; ++i)
        {
            works.push_back(pool.enqueue([i]() {
                zmq::message_t msg_ack;
                socket_client[i]->recv(&msg_ack);
                // cout << "Received \"" << msg_ack.to_string() << "\" from server " << i << endl;
            }));
        }
        joinNclean(works);
        // }
        cout << "[Document update] End-to-end latency: " << time_from(start) << "us" << endl;
    }

    delete [] column_keys;
    delete [] data_out;
    delete [] encrypted_data_out;
}

void test_keyword_search() {
    // srand(2023);
    PRG prg[nP-1];
    bool **search_output     = new bool*[num_writers];
    bool **reshuffled_output = new bool*[num_writers];

    for(int wid = 0; wid < num_writers; ++wid) {
        search_output[wid]     = new bool[num_documents];
        reshuffled_output[wid] = new bool[num_documents];
    }

    uint32_t *random_indices = new uint32_t[num_documents];
    uint32_t *pi = new uint32_t[num_documents];    
    block permutation_seed[nP-1];

    int BF_index[K];
    FSSKey key[nP][K];
    private_token_t (*secret_shared_private_tokens)[nP][K];
    private_token_t private_token;
    poly_modq_t column_key;

    int n_keyword_search_times = 10;
    num_parties = nP;
    
    secret_shared_private_tokens = new private_token_t[num_writers][nP][K];
    poly_modq_t (*shared_keys)[K][nP] = new poly_modq_t[num_writers][K][nP];

    vector<future<void>> works;
    ThreadPool pool(MAX_THREADS);
    MPKey mp_keys[K][nP];
    
    uint16_t ***padding_values = new uint16_t**[num_writers];
    for(int i = 0; i < num_writers; ++i) {
        padding_values[i] = new uint16_t*[nP];
        for(int j = 0; j < nP; ++j)
            padding_values[i][j] = new uint16_t[N_S];
    }

    auto start = clock_start();
    
    for(int t = 0; t < n_keyword_search_times; ++t) {
        // modp_t *sum = new modp_t[bloom_filter_size];
        for(int i = 0; i < K; ++i) {
            BF_index[i] = rand() % bloom_filter_size;
            if(num_parties > 2) {
                generate_fss_keys(BF_index[i], 1, mp_keys[i]);
                // PRG prg;
                // memset(sum, 0, bloom_filter_size*sizeof(modp_t));
                // for(int j = 0; j < nP - 1; ++j) {
                //     prg.random_data(mp_keys[i][j], bloom_filter_size*sizeof(modp_t));
                //     for(int k = 0; k < bloom_filter_size; ++k) {
                //         mp_keys[i][j][k] &= MASK_P;
                //         sum[k] = (sum[k] + mp_keys[i][j][k]) & MASK_P;
                //     }
                // }
                // for(int k = 0; k < bloom_filter_size; ++k) {
                //     if(k == BF_index[i]) {
                //         mp_keys[i][nP-1][k] = ((1<<P) + 1 - sum[k]) & MASK_P;
                //     } else {
                //         mp_keys[i][nP-1][k] = ((1<<P) - sum[k]) & MASK_P;
                //     }
                // }
            }
            else generate_keypair(BF_index[i], 1, key[0][i], key[1][i]);
        }
        // delete [] sum;

		// For measuring bandwidth
        bandwidth = 0;

        for(int i = 0; i < num_parties; ++i) {
            works.push_back(pool.enqueue([i, key, BF_index, mp_keys]() {
                // Note: sending indices just for debugging purpose
                if(num_parties > 2) {           
                    uint64_t n = 16;
                    uint32_t p2 = (uint32_t)(pow(2, num_parties-1));
                    uint64_t mu = (uint64_t)ceil((pow(2, n/2.0) * pow(2,(num_parties-1)/2.0)));
                    uint64_t v  = (uint64_t)ceil((pow(2, n))/mu);

					// For measuring bandwidth
                    if(i == 0) {
                        bandwidth += K * (p2*mu*sizeof(modp_t) + v*p2*sizeof(block) + v*p2*sizeof(modp_t)) * num_parties;
                    }
					
                    zmq::message_t msg_fss_keys(K * (p2*mu*sizeof(modp_t) + v*p2*sizeof(block) + v*p2*sizeof(modp_t)) + K * sizeof(int));
                    uint8_t *msg_fss_keys_data = (uint8_t*)msg_fss_keys.data();
                    // for(int j = 0; j < K; ++j) {
                    //     memcpy(msg_fss_keys_data, mp_keys[j][i], bloom_filter_size * sizeof(modp_t));
                    //     msg_fss_keys_data += bloom_filter_size * sizeof(modp_t);
                    // }
                    // for(int j = 0; j < K; ++j) {
                    //     memcpy(msg_fss_keys_data, &BF_index[j], sizeof(int));
                    //     msg_fss_keys_data += sizeof(int);
                    // }
                    // socket_client[i]->send(msg_fss_keys);
                    for(int j = 0; j < K; ++j) {
                        for (int k = 0; k < p2; k++) {
                            memcpy(msg_fss_keys_data, mp_keys[j][i].cw[k], mu*sizeof(modp_t));
                            msg_fss_keys_data += mu*sizeof(modp_t);
                        }
                        for(int k = 0; k < v; ++k) {
                            memcpy(msg_fss_keys_data, mp_keys[j][i].sigma[k], p2*sizeof(block));
                            msg_fss_keys_data += sizeof(block)*p2;
                        }
                        for(int k = 0; k < v; ++k) {
                            memcpy(msg_fss_keys_data, mp_keys[j][i].a[k], p2*sizeof(uint16_t));
                            msg_fss_keys_data += sizeof(uint16_t)*p2;
                        }
                    }
                    for(int j = 0; j < K; ++j) {
                        memcpy(msg_fss_keys_data, &BF_index[j], sizeof(int));
                        msg_fss_keys_data += sizeof(int);
                    }
                    socket_client[i]->send(msg_fss_keys);
                } else { 
					// For measuring bandwidth
                    if(i == 0) {
                        bandwidth += K * sizeof(FSSKey) * num_parties;
                    }
					
                    zmq::message_t msg_fss_keys(K * sizeof(FSSKey) + K * sizeof(int));
                    uint8_t *msg_fss_keys_data = (uint8_t*)msg_fss_keys.data();
                    for(int j = 0; j < K; ++j) {
                        memcpy(msg_fss_keys_data, &key[i][j], sizeof(FSSKey));
                        msg_fss_keys_data += sizeof(FSSKey);
                    }
                    for(int j = 0; j < K; ++j) {
                        memcpy(msg_fss_keys_data, &BF_index[j], sizeof(int));
                        msg_fss_keys_data += sizeof(int);
                    }
                    socket_client[i]->send(msg_fss_keys);
                }
            }));
        }
        joinNclean(works);

        for(int i = 0; i < num_parties; ++i) {
            works.push_back(pool.enqueue([i, secret_shared_private_tokens]() {
                zmq::message_t msg_secret_shared_keys;
                socket_client[i]->recv(&msg_secret_shared_keys);

				// For measuring bandwidth
                if(i == 0) {
                    bandwidth += msg_secret_shared_keys.size() * num_parties;
                }
				
                uint8_t *msg_secret_shared_keys_data = (uint8_t*)msg_secret_shared_keys.data();
                for(int j = 0; j < num_writers; ++j) {
                    for(int k = 0; k < K; ++k) {
                        memcpy(&secret_shared_private_tokens[j][i][k], msg_secret_shared_keys_data, sizeof(private_token_t));
                        msg_secret_shared_keys_data += sizeof(private_token_t);
                    }
                }
            }));
        }
        joinNclean(works);

        for(int i = 0; i < num_writers; ++i) {
            for(int j = 0; j < K; ++j) {
                for(int k = 0; k < sizeof(private_token_t); ++k) {
                    private_token[k] = 0;
                    for(int l = 0; l < num_parties; ++l)
                        private_token[k] = (private_token[k] + secret_shared_private_tokens[i][l][j][k]) & MASK_P;
                }
                pk_decrypt(private_token, (uint8_t*)column_key);
                share((uint16_t*)column_key, shared_keys[i][j]);
            }
        }
        
        for(int i = 0; i < num_parties; ++i) {
            zmq::message_t msg_secret_shared_keys(num_writers * K * sizeof(poly_modq_t));
            uint8_t *msg_secret_shared_keys_data = (uint8_t*)msg_secret_shared_keys.data();
            for(int j = 0; j < num_writers; ++j) {
                for(int k = 0; k < K; ++k) {
                    memcpy(msg_secret_shared_keys_data, &shared_keys[j][k][i], sizeof(poly_modq_t));
                    msg_secret_shared_keys_data += sizeof(poly_modq_t);
                }
            }
            socket_client[i]->send(msg_secret_shared_keys);

			// For measuring bandwidth
            bandwidth += msg_secret_shared_keys.size();
        }

        // string test_msg = "test";
        // zmq::message_t msg_test(test_msg.length());
        // for(int i = 2; i < nP; ++i) {
        //     socket_client[i]->send(msg_test);
        // }
        uint16_t **s = new uint16_t*[nP];
        for(int i = 0; i < num_parties; ++i) 
            s[i] = new uint16_t[num_writers];

        for(int i = 0; i < num_parties; ++i) {
            works.push_back(pool.enqueue([i, s]() {
                zmq::message_t reply;
                socket_client[i]->recv(&reply);
                memcpy(s[i], reply.data(), num_writers*sizeof(uint16_t));

				// For measuring bandwidth  
                bandwidth += reply.size();
            }));
        }
        
        joinNclean(works);

        // start = clock_start();
        
        uint16_t current_sum[N_S];

        for(int i = 0; i < num_writers; ++i) {
            memset(current_sum, 0, N_S*sizeof(uint16_t));
            uint16_t sp = 0;
            for(int j = 0; j < num_parties; ++j) 
                sp = (sp + s[j][i]) & MASK_N_S;
            
            uint16_t padded = N_S - 1 - sp;
            for(int j = 0; j < num_parties - 1; ++j) {
                prg->random_data(padding_values[i][j], N_S*sizeof(uint16_t));
                for(int k = 0; k < N_S; ++k) {
                    padding_values[i][j][k] &= MASK_N_S;
                    current_sum[k] = (current_sum[k] + padding_values[i][j][k]) & MASK_N_S;
                }
            }
            for(int j = 0; j < padded; ++j) 
                padding_values[i][nP-1][j] = (N_S + 1 - current_sum[j]) & MASK_N_S;
            for(int j = padded; j < N_S; ++j) 
                padding_values[i][nP-1][j] = (N_S - current_sum[j]) & MASK_N_S;
        }

        for(int i = 0; i < num_parties; ++i) {
            works.push_back(pool.enqueue([i, padding_values]() {
                zmq::message_t padding_response(num_writers * N_S *sizeof(uint16_t));
                for(int j = 0; j < num_writers; ++j) 
                    memcpy(padding_response.data() + j * N_S * sizeof(uint16_t), padding_values[j][i], N_S*sizeof(uint16_t));
                socket_client[i]->send(padding_response);

				// For measuring bandwidth
                if(i == 0) {
                    bandwidth += padding_response.size() * num_parties;
                }
            }));
        }

        joinNclean(works);

        // cout << "Padding time: " << time_from(start) << endl;

        for(int i = 0; i < num_parties; ++i)
            delete [] s[i];
        delete [] s;

        for(int i = 0; i < num_parties; ++i) {
            works.push_back(pool.enqueue([i, &permutation_seed, search_output]() {
                zmq::message_t reply;
                socket_client[i]->recv(&reply);
                cout << "Received " << reply.size() << " bytes from server " << i << endl;

				// For measuring bandwidth
                if(i == num_parties - 1) {
                    bandwidth += reply.size();
                }
				
                uint8_t *reply_data = (uint8_t*)reply.data();
                if(i < num_parties-1) {
                    memcpy(&permutation_seed[i], reply_data, sizeof(block));
                }
                else {
                    int *reply_data_int = (int*)reply_data;
                    for(int wid = 0; wid < num_writers; ++wid) {
                        for(int j = 0; j < num_documents; ++j)
                            search_output[wid][j] = false;

                        int output_size = *reply_data_int;                        
                        for(int j = 0; j < output_size; ++j) {
                            reply_data_int++;
                            int appear = *reply_data_int;
                            search_output[wid][appear] = true;
                        }
                        if(wid < num_writers - 1) reply_data_int++;
                    }            
                }
            }));
        }
        joinNclean(works);

		bandwidth += (num_parties - 1) * num_writers * sizeof(block);
		
        int n = num_documents;
        
        // for(int m = 0; m <= num_parties-2; ++m) 
        //     prg[m].reseed(&permutation_seed[m]);

        for(int wid = 0; wid < num_writers; ++wid) {
            for(int m = num_parties-2; m >= 0; --m) {
				prg[m].reseed(&permutation_seed[m]);
                prg[m].random_data(random_indices, n * sizeof(uint32_t));
                for(uint32_t i = 0; i < n; ++i)
                    pi[i] = i;
                for(uint32_t i = n - 1; i > 0; --i) {
                    uint32_t j = random_indices[i] % (i + 1);
                    uint32_t tmp = pi[i]; pi[i] = pi[j]; pi[j] = tmp;
                }
                for(int i = 0; i < num_documents; ++i) {
                    reshuffled_output[wid][pi[i]] = search_output[wid][i]; 
                }
                memcpy(search_output[wid], reshuffled_output[wid], num_documents*sizeof(bool));
            }

            cout << "Search output: ";
            for(int i = 0; i < num_documents; ++i) {
                if(search_output[wid][i] && (i < num_documents - N_S))
                    cout << i << " ";
            }
            cout << endl;
        }
        if(t == n_keyword_search_times-1) {
        	for(int i = 0; i < num_parties; ++i) {
		    	works.push_back(pool.enqueue([i]() { 
		    		string ack = "ACK";
		    		zmq::message_t msg_ack(ack.length());
		    		memcpy(msg_ack.data(), ack.c_str(), ack.length());
		    		socket_client[i]->send(msg_ack);
		    	}));
		    }
		    joinNclean(works);
		}
    }
	
    cout << "[Keyword search] End-to-end latency (including preprocessing): " << time_from(start)/n_keyword_search_times << "us" << endl;
    cout << "[Keyword search] Bandwidth cost: " << (bandwidth/(double)1048576.0) << "MB" << endl;
	
    for(int i = 0; i < num_writers; ++i) {
        for(int j = 0; j < nP; ++j)
            delete [] padding_values[i][j];
        delete [] padding_values[i];
    }
    delete [] padding_values;

    for(int wid = 0; wid < num_writers; ++wid) {
        delete [] search_output[wid];
        delete [] reshuffled_output[wid];
    }

    delete [] shared_keys;
    delete [] secret_shared_private_tokens;
    delete [] search_output;
    delete [] reshuffled_output;
    delete [] random_indices;
    delete [] pi;
}

int main(int argc, char **argv) {
    num_parties       = nP;
    // Initialize default parameters
    num_writers       = 1;
    bloom_filter_size = 1120;
    num_documents     = 1024;
    
    int i = 1;
    while (i < argc) {
        if(strcmp(argv[i], "-w") == 0) 
            num_writers = atoi(argv[++i]);
        else if (strcmp(argv[i], "-b") == 0) 
            bloom_filter_size = atoi(argv[++i]);
        else if (strcmp(argv[i], "-d") == 0) 
            num_documents = atoi(argv[++i]);
        else {
            cout << "Option " << argv[i] << " does not exist!!!" << endl;
            exit(1);
        }
        i++;
    }
    
    reader_setup();
    writer_setup();
    
    cout << "Connecting to Servers..." << endl;
    context_client = new zmq::context_t*[nP];
    socket_client  = new zmq::socket_t*[nP];
    
    string ip_addresses[] = {"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"};
    
    for (int i = 0; i < nP; ++i)
    {
        context_client[i] = new zmq::context_t(1);
        socket_client[i]  = new zmq::socket_t(*context_client[i], ZMQ_REQ);
        string send_address = "tcp://" + ip_addresses[i] + ":" + to_string(SERVER_PORT+i*nP+i);
        cout << "Connecting to " << send_address << " for communication with Server " << (i+1) << " ..." << endl;
        socket_client[i]->connect(send_address);
    }

    test_secret_key_update();
    
    test_document_update();

    test_keyword_search();
    
    delete [] context_client;
    
    delete [] socket_client;

    return 0;
}

