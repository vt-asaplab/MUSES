#include <iostream>
#include <zmq.hpp>
#include <emp-tool/emp-tool.h>
#include <emp-agmpc/emp-agmpc.h>
#include "search_index.hpp"
#include "oblivious_shuffle.hpp"
#include "oblivious_count.hpp"
#include "config.hpp"
#include "pke/pke.hpp"

using namespace std;

int num_parties       = nP;

zmq::context_t        *context_server;
zmq::socket_t         *socket_server;
NetIOMP<nP>           *io;
int                   party;
int                   port;
int                   num_writers;
int                   bloom_filter_size;
int                   num_documents;

void test_secret_key_update() {
    cout << "Performing permission revocation..." << endl;
    // Measure average latency of secret-key update
    int n_secret_key_update_times = 1;
    for(int t = 0; t < n_secret_key_update_times; ++t) {
        auto start = clock_start();

        zmq::message_t msg_writer_id;
        socket_server->recv(&msg_writer_id);
        string received_id = msg_writer_id.to_string();
        
        int selected_writer = stoi(received_id);
        zmq::message_t msg_secret_tokens(bloom_filter_size * sizeof(secret_token_t));
        uint8_t *msg_secret_tokens_data = (uint8_t*)msg_secret_tokens.data();
        
        for(int i = 0; i < bloom_filter_size; ++i) {
            memcpy(msg_secret_tokens_data, &secret_tokens[selected_writer][i], sizeof(secret_token_t));
            msg_secret_tokens_data += sizeof(secret_token_t);
        }
        socket_server->send(msg_secret_tokens);
                
        zmq::message_t msg_secret_shares_key;
        socket_server->recv(&msg_secret_shares_key);
        uint8_t *msg_secret_shares_key_data = (uint8_t*)msg_secret_shares_key.data();

        // cout << "Received " << msg_secret_shares_key.size() << " bytes from the client" << endl;

        // This is just for verifying correctness
        for(int i = 0; i < bloom_filter_size; ++i) {
            memcpy(&private_tokens[selected_writer][i], msg_secret_shares_key_data, sizeof(private_token_t));
            msg_secret_shares_key_data += sizeof(private_token_t);
        }

        for(int i = 0; i < bloom_filter_size; ++i) {
            memcpy(&secret_tokens[selected_writer][i], msg_secret_shares_key_data, sizeof(secret_token_t));
            msg_secret_shares_key_data += sizeof(secret_token_t);
        }

        update_secret_key(selected_writer, msg_secret_shares_key_data); 

        string ack = "ACK";
        // if(t < n_secret_key_update_times-1) {
            zmq::message_t msg_ack(ack.length());
            memcpy(msg_ack.data(), ack.c_str(), ack.length());
            socket_server->send(msg_ack);
        // }

        cout << "[Permission revocation] Server latency: " << time_from(start) << "us" << endl;
    }
}

void test_document_update() {
    cout << "Updating document..." << endl;
    // Measure average latency of document update
    int n_document_update_times = 1;
    
    for(int i = 0; i < n_document_update_times; ++i) {
        zmq::message_t msg_writer_id_file_id;
        socket_server->recv(&msg_writer_id_file_id);
        int writer_id;
        int file_id;
        memcpy(&writer_id, msg_writer_id_file_id.data(), sizeof(int)); 
        memcpy(&file_id, (uint8_t*)msg_writer_id_file_id.data() + sizeof(int), sizeof(int)); 
        
        // cout << "Writer ID: " << writer_id << ", File ID: " << file_id << endl;

        zmq::message_t msg_secret_tokens(bloom_filter_size * sizeof(secret_token_t) + sizeof(uint64_t));
        uint8_t *msg_secret_tokens_data = (uint8_t*)msg_secret_tokens.data();
        
        for(int i = 0; i < bloom_filter_size; ++i) {
            memcpy(msg_secret_tokens_data, &secret_tokens[writer_id][i], sizeof(secret_token_t));
            msg_secret_tokens_data += sizeof(secret_token_t);
        }
        memcpy(msg_secret_tokens_data, &states[writer_id][file_id], sizeof(uint64_t));
        socket_server->send(msg_secret_tokens);

        zmq::message_t msg_updated_data;
        socket_server->recv(&msg_updated_data);

        uint8_t *updated_data_ptr = (uint8_t*)msg_updated_data.data();

        modp_t *data_out = (modp_t*)malloc(bloom_filter_size*sizeof(modp_t));
        memcpy(data_out, updated_data_ptr, bloom_filter_size * sizeof(modp_t));
        /*
        for(int i = 0; i < bloom_filter_size; ++i) {
            search_index[writer_id][i][file_id] = data_out[i];
        }
	    */
        updated_data_ptr += bloom_filter_size * sizeof(modp_t);
        memcpy(data_out, updated_data_ptr, bloom_filter_size * sizeof(modp_t));

        for(int i = 0; i < bloom_filter_size; ++i) {
            encrypted_search_index[writer_id][i][file_id] = data_out[i];
        }

        update_BF_document(writer_id, file_id);

        string ack = "ACK";
        // if(i < n_document_update_times-1) {
            zmq::message_t msg_ack(ack.length());
            memcpy(msg_ack.data(), ack.c_str(), ack.length());
            socket_server->send(msg_ack);
        // }
    }

    cout << "Finished document update!!!" << endl;
}

void test_keyword_search() {
    MPKey mp_keys[K];
    num_parties = nP;
    
    // modp_t *mp_keys[K];
    // for(int i = 0; i < K; ++i) {
    //     mp_keys[i] = new modp_t[bloom_filter_size];
    // }

    // if(nP > 2) {
    //     zmq::message_t msg_fss_prf_keys;
    //     socket_server->recv(&msg_fss_prf_keys);

    //     fServer.numKeys = initPRFLen;
    //     fServer.aes_keys = (AES_KEY*)malloc(244*128);
    //     memcpy(fServer.aes_keys, msg_fss_prf_keys.data(), 244*128);
    //     fServer.numBits = 16;
    //     fServer.numParties = nP;
    //     mpz_class p;
    //     mpz_ui_pow_ui(p.get_mpz_t(), 2, 32);
    //     mpz_nextprime(fServer.prime.get_mpz_t(), p.get_mpz_t());

    //     string ack = "ACK";
    //     zmq::message_t msg_ack(ack.length());
    //     memcpy(msg_ack.data(), ack.c_str(), ack.length());
    //     socket_server->send(msg_ack);
    // }
    
    auto start = clock_start();

    block permutation_seed;
    prg.random_block(&permutation_seed);
    preprocessing_shuffling(permutation_seed);
    preprocessing_counting();
    
    cout << "[Keyword search] Preprocessing latency: " << time_from(start) << "us" << endl;
    
    int n_keyword_search_times = 1; 
    FSSKey key[K];
    int BF_index[K];
    private_token_t secret_shared_private_tokens[K];

    modp_t **queries = new modp_t*[K];
    for(int i = 0; i < K; ++i)
        queries[i] = new modp_t[bloom_filter_size];

    modp_t *data_out[K];
    for(int i = 0; i < K; ++i)
        data_out[i] = (modp_t*)malloc(num_documents*sizeof(modp_t));
    modp_t *data_final = (modp_t*)malloc(num_documents*sizeof(modp_t));

    uint16_t **padded_data = new uint16_t*[num_writers];
    for(int i = 0; i < num_writers; ++i)
        padded_data[i] = new uint16_t[num_documents];
    
    modp_t *temp_data[nP];
    for(int i = 0; i < nP; ++i) 
        temp_data[i] = new modp_t[num_documents];

    int   *output_size    = new int[num_writers];
    int   **search_output = new int*[num_writers];
    block *seed_output    = new block[num_writers];
	
    // uint32_t n = 16;
    // uint32_t p = nP;
    // uint32_t m = 4; 
    // uint32_t p2 = (uint32_t)(pow(2, p-1));
    // uint32_t mu = (uint64_t)ceil((pow(2, n/2.0) * pow(2,(p-1)/2.0)));
    // uint32_t v  = (uint64_t)ceil((pow(2, n))/mu);
    // uint32_t m_bytes = m*mu;

    start = clock_start();

    for(int i = 0; i < n_keyword_search_times; ++i) {
        uint64_t n = 16;
        uint32_t p2 = (uint32_t)(pow(2, num_parties-1));
        uint64_t mu = (uint64_t)ceil((pow(2, n/2.0) * pow(2,(num_parties-1)/2.0)));
        uint64_t v  = (uint64_t)ceil((pow(2, n))/mu);

        if(num_parties > 2) {
            zmq::message_t msg_fss_keys;
            socket_server->recv(&msg_fss_keys);
            uint8_t *msg_fss_keys_data = (uint8_t*)msg_fss_keys.data();
            // for(int j = 0; j < K; ++j) {
            //     memcpy(queries[j], msg_fss_keys_data, bloom_filter_size*sizeof(modp_t));
            //     msg_fss_keys_data += bloom_filter_size*sizeof(modp_t);
            // }

            for(int j = 0; j < K; ++j) {
                mp_keys[j].cw = (modp_t**) malloc(sizeof(modp_t*)*p2);
                for (int k = 0; k < p2; k++) {
                    mp_keys[j].cw[k] = (modp_t*) malloc(mu*sizeof(modp_t));
                    memcpy(mp_keys[j].cw[k], msg_fss_keys_data, mu*sizeof(modp_t));
                    msg_fss_keys_data += mu*sizeof(modp_t);
                }
                mp_keys[j].sigma = (block**) malloc(sizeof(block*)*v);
                for(int k = 0; k < v; ++k) {
                    mp_keys[j].sigma[k] = (block*) malloc(sizeof(block)*p2);
                    memcpy(mp_keys[j].sigma[k], msg_fss_keys_data, sizeof(block)*p2);
                    msg_fss_keys_data += sizeof(block)*p2;
                }
                mp_keys[j].a = (modp_t**) malloc(sizeof(modp_t*)*v);
                for(int k = 0; k < v; ++k) {
                    mp_keys[j].a[k] = (modp_t*) malloc(sizeof(modp_t)*p2);
                    memcpy(mp_keys[j].a[k], msg_fss_keys_data, sizeof(modp_t)*p2);
                    msg_fss_keys_data += sizeof(modp_t)*p2;
                }
            }

            for(int j = 0; j < K; ++j) {
                memcpy(&BF_index[j], msg_fss_keys_data, sizeof(int));
                msg_fss_keys_data += sizeof(int);
            }   

            vector<future<void>> works;
            ThreadPool pool(MAX_THREADS);
            int size_per_thread = bloom_filter_size/MAX_THREADS;

            for(int j = 0; j < K; ++j) {
                for(int t = 0; t < MAX_THREADS; ++t) {
                    works.push_back(pool.enqueue([j, &mp_keys, queries, t, size_per_thread]() {
                        int start = t * size_per_thread;
                        int end   = start + size_per_thread;
                        for(int k = start; k < end; ++k) {
                            queries[j][k] = eval_fss_keys(&mp_keys[j], k);
                        }
                    }));
                }
                joinNclean(works);
                // cout << "Try: " << queries[j][BF_index[j]] << endl;
            }
        } else {
            zmq::message_t msg_fss_keys;
            socket_server->recv(&msg_fss_keys);

            uint8_t *msg_fss_keys_data = (uint8_t*)msg_fss_keys.data();
            for(int j = 0; j < K; ++j) {
                memcpy(&key[j], msg_fss_keys_data, sizeof(FSSKey));
                msg_fss_keys_data += sizeof(FSSKey);
            }

            for(int j = 0; j < K; ++j) {
                memcpy(&BF_index[j], msg_fss_keys_data, sizeof(int));
                msg_fss_keys_data += sizeof(int);
            }   

            vector<future<void>> works;
            ThreadPool pool(MAX_THREADS);
            int size_per_thread = bloom_filter_size/MAX_THREADS;

            for(int i = 0; i < K; ++i) {
                for(int t = 0; t < MAX_THREADS; ++t) {
                    works.push_back(pool.enqueue([i, &key, queries, t, size_per_thread]() {
                        int start = t * size_per_thread;
                        int end   = start + size_per_thread;
                        for(int j = start; j < end; ++j) {
                            queries[i][j] = fss_eval(party-1, key[i], j);
                        }
                    }));
                }
                joinNclean(works);
            }
        }

        zmq::message_t msg_secret_shared_private_tokens(num_writers * K * sizeof(private_token_t));
        uint8_t *msg_secret_shared_private_tokens_data = (uint8_t*)msg_secret_shared_private_tokens.data();

        for(int wid = 0; wid < num_writers; ++wid) {
            vector<future<void>> works;
            ThreadPool pool(K);
            
            for(int i = 0; i < K; ++i) {
                works.push_back(pool.enqueue([i, &secret_shared_private_tokens, queries, wid]() {
                    for(int j = 0; j < sizeof(private_token_t); ++j) {
                        secret_shared_private_tokens[i][j] = 0;
                        for(int k = 0; k < bloom_filter_size; ++k) {
                            secret_shared_private_tokens[i][j] = (secret_shared_private_tokens[i][j] + (uint32_t)queries[i][k] * private_tokens[wid][k][j]) & MASK_P;
                        }
                    }
                }));
            }   
            joinNclean(works);

            for(int i = 0; i < K; ++i) {
                memcpy(msg_secret_shared_private_tokens_data, secret_shared_private_tokens[i], sizeof(private_token_t));
                msg_secret_shared_private_tokens_data += sizeof(private_token_t);
            }
        }
        
        socket_server->send(msg_secret_shared_private_tokens);

        zmq::message_t msg_secret_shared_column_keys;
        socket_server->recv(&msg_secret_shared_column_keys);
        uint8_t *msg_secret_shared_column_keys_data = (uint8_t*)msg_secret_shared_column_keys.data();
        poly_modq_t column_key;

        zmq::message_t counting_result(num_writers*sizeof(uint16_t));

        for(int wid = 0; wid < num_writers; ++wid) {
            for(int i = 0; i < K; ++i) {
                memcpy(&column_key, msg_secret_shared_column_keys_data, sizeof(poly_modq_t));
                msg_secret_shared_column_keys_data += sizeof(poly_modq_t);
                poly_modq_t shared_keys[2];
                retrieve_BF_index(wid, queries[i], column_key, data_out[i]);
            }

            for(int i = 0; i < num_documents; ++i) {
                for(int j = 1; j < K; ++j) {
                    data_out[0][i] = (data_out[0][i] + data_out[j][i]) & MASK_P; 
                }
            }

            // For debugging
            /* cout << "Actual Output: ";
            for(int i = 0; i < num_documents; ++i) {
                int valid = true;
                for(int j = 0; j < K; ++j) {
                    if(search_index[wid][BF_index[j]][i] == 0) {
                        valid = false;
                        break;
                    }
                }   
                if(valid) cout << i << " ";
            }
            cout << endl; 
            */

            // cout << "data_out[0][0]: " << data_out[0][0] << endl;

            // start = clock_start();

            // Oblivious counting: reuse preprocessing materials to reduce preprocessing couting time in testing
            for(int i = 0; i < num_documents; ++i) 
                data_out[0][i] = (((K+1-r[0][i])<<E) + data_out[0][i]) & MASK_P;
                // data_out[0][i] = (((K+1)<<E) + data_out[0][i] - (r[wid][i]<<E)) & MASK_P;
            
            std::thread ts([data_out](){
                for(int i = 1; i <= nP; ++i) {
                    if(i != party) {
                        io->send_data(i, data_out[0], num_documents*sizeof(modp_t));
                        io->flush();
                    }
                }
            });
            
            std::thread rs([temp_data](){
                for(int i = 1; i <= nP; ++i) {
                    if(i != party) {
                        io->recv_data(i, temp_data[i-1], num_documents*sizeof(modp_t));
                        io->flush();
                    }
                }
            });

            ts.join();
            rs.join();

            for(int i = 1; i <= nP; ++i) {
                if(i != party) {
                    for(int j = 0; j < num_documents; ++j)
                        data_out[0][j] = (data_out[0][j] + temp_data[i-1][j]) & MASK_P;
                }
            }
            
            for(int i = 0; i < num_documents; ++i) 
                data_out[0][i] = (data_out[0][i] >> E) % (K+1);
            
            // cout << "data_out[0][0]: " << data_out[0][0] << endl;
            
            uint16_t s = 0;
            for(int i = 0; i < num_documents; ++i) {
                data_out[0][i] = e[0][i][K - data_out[0][i]];
                // data_out[0][i] = e[wid][i][K - data_out[0][i]];
                s = (s + data_out[0][i]) & MASK_N_S;
            }

            // cout << "s = " << s << endl;

            // Padding
            memcpy((uint8_t*)counting_result.data() + wid*sizeof(uint16_t), &s, sizeof(uint16_t));
            memcpy(padded_data[wid], data_out[0], num_documents*sizeof(uint16_t));

            // cout << "Padding time: " << time_from(start) << endl;
        }
        
        socket_server->send(counting_result);
        zmq::message_t padding_response;
		socket_server->recv(&padding_response);
	
		int total_output = 0;
        for(int wid = 0; wid < num_writers; ++wid)
        {   
            memcpy(padded_data[wid] + num_documents - N_S, padding_response.data() + wid * N_S * sizeof(uint16_t), N_S*sizeof(uint16_t));
            // Oblivious shuffle
            if(party != 1) {
                mask(padded_data[wid], wid);
                io->send_data(1, padded_data[wid], num_documents * sizeof(modp_t));
                io->flush();
                cout << "Done sending masked data..." << endl;
            }
            else if(party == 1) {
                modp_t *tmp = (modp_t*)malloc(num_documents*sizeof(modp_t));
                modp_t *sum = (modp_t*)malloc(num_documents*sizeof(modp_t));
                memset(sum, 0, num_documents*sizeof(modp_t));
                for(int i = 2; i <= num_parties; ++i) {
                    io->recv_data(i, tmp, num_documents * sizeof(modp_t));
                    for(int j = 0; j < num_documents; ++j)
                        sum[j] = (sum[j] + tmp[j]) & MASK_N_S;
                }
                shuffle(data_final, padded_data[wid], sum, wid);
                io->send_data(2, data_final, num_documents * sizeof(modp_t));
                io->flush();
                delete [] tmp;
                delete [] sum;
                cout << "Done sending shuffled data to P2..." << endl;
            } 
            
            if(party > 1 && party < num_parties) {
                modp_t *tmp = (modp_t*)malloc(num_documents*sizeof(modp_t));
                cout << "Waiting for receiving data from " << (party-1) << endl;
                io->recv_data(party-1, tmp, num_documents*sizeof(modp_t));
                memset(padded_data[wid], 0, num_documents*sizeof(modp_t));
                shuffle(data_final, padded_data[wid], tmp, wid);
                io->send_data(party+1, data_final, num_documents*sizeof(modp_t));
                io->flush();
                cout << "Done sending shuffled data to " << (party+1) << endl;
                delete [] tmp;
            }
            else if(party == num_parties) {
                cout << "Waiting for receiving data from " << (party-1) << endl;
                io->recv_data(party-1, data_final, num_documents * sizeof(modp_t));
                unmask(data_final, wid);
                
                output_size[wid] = 0;

                for(int i = 0; i < num_documents; ++i)
                    if(data_final[i] == 1) output_size[wid]++;

                search_output[wid] = new int[output_size[wid]];
                int cnt = 0;
                for(int i = 0; i < num_documents; ++i) 
                    if(data_final[i] == 1) search_output[wid][cnt++] = i;
                
                total_output += output_size[wid];
                // cout << "Output size: " << output_size[wid] << endl;
            }
        }   

        if(party == num_parties) {
            zmq::message_t reply((num_writers + total_output)*4);
            uint8_t *reply_data = (uint8_t*)reply.data();

            for(int wid = 0; wid < num_writers; ++wid) {
                memcpy(reply_data, &output_size[wid], sizeof(int));
                reply_data += sizeof(int);
                memcpy(reply_data, search_output[wid], output_size[wid]*sizeof(int));
                reply_data += output_size[wid] * sizeof(int);
            }
        
            socket_server->send(reply);

            for(int wid = 0; wid < num_writers; ++wid) 
                if(output_size[wid] > 0) delete [] search_output[wid];
        }
        else {
            zmq::message_t reply(sizeof(block));
            memcpy(reply.data(), &permutation_seed, sizeof(block));
            socket_server->send(reply);
        }
        
        if(i == n_keyword_search_times - 1) {
        	zmq::message_t ack;
        	socket_server->recv(&ack);
        }
    }

    cout << "[Keyword search] Server latency: " << time_from(start)/n_keyword_search_times << "us" << endl;

    for(int i = 0; i < K; ++i)
        delete [] data_out[i];
    
    for(int i = 0; i < num_writers; ++i)
        delete [] padded_data[i];
    delete [] padded_data;

    delete [] data_final;
    delete [] output_size;
    delete [] search_output;
    delete [] seed_output;

    for(int i = 0; i < K; ++i)
        delete [] queries[i];
    delete [] queries;

    for(int i = 0; i < nP; ++i) 
        delete [] temp_data[i];
}

int main(int argc, char **argv) {
    // Initialize default parameters
    num_writers       = 1;
    bloom_filter_size = 2000;
    num_documents     = 1024;
    
    int i = 3;
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
    
    // Following code is for fast initialization
    // srand(2023);
    setup_public_private_keys();
    
    party          = atoi(argv[1]);
    port           = atoi(argv[2]);
    io             = new NetIOMP<nP>(party, port);
    context_server = new zmq::context_t(1);
    socket_server  = new zmq::socket_t(*context_server, ZMQ_REP);    
    socket_server->bind("tcp://*:" + to_string(SERVER_PORT+(party-1)*num_parties+(party-1)));
    cout << "Port: " << to_string(SERVER_PORT+(party-1)*num_parties+(party-1)) << endl;
    
    // Init search indices for num_writers
    cout << "Initialize search indices..." << endl;
    init_search_index();

    // Precomputing hashed states to accelerate search operations
    compute_hashed_states();
    
    // Initialize column keys of search indices
    init_column_keys();

    // Encrypt search indices
    cout << "Initialize encrypted search indices..." << endl;
    init_encrypted_search_index();
    
    test_secret_key_update();
    
    test_document_update();

    test_keyword_search();
    
    return 0;
}





