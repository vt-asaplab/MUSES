#pragma once
#include <types.hpp>
#include <config.hpp>
#include <emp-tool/emp-tool.h>
#include <emp-ot/emp-ot.h>
#include <vector>
#include <ThreadPool.h>

using namespace std;

extern int           num_parties;
extern int           party;
extern int           port; 
extern int           n_s;
extern int           mask_n_s;
uint16_t             **r;
uint16_t             ***e;

void shr_trns(IKNP<NetIO> *ot, NetIO *io, int party_i, int party_j, uint8_t *punctured_positions, 
              uint16_t **ac, uint16_t **bc, uint16_t **deltac) {
    int n = K + 1;
    int n_levels = (int)log2(n);
    // cout << "n_levels: " << n_levels << endl;
    
    if(party == party_j) {    
        uint16_t **full_matrix = new uint16_t*[n];
        for(int i = 0; i < n; ++i) 
            full_matrix[i] = new uint16_t[n];
        
        block *b0 = new block[n_levels * n];
        block *b1 = new block[n_levels * n];

        PRG   prg;
        block *seeds = new block[2*n - 2];
        block *b0_ptr = b0;
        block *b1_ptr = b1;

        for(int t = 0; t < n; ++t) {
            prg.random_block(seeds, 2);
            for(int i = 0; i < n - 2; ++i) {
                PRG prg(&seeds[i]);
                prg.random_block(&seeds[2*i + 2], 2);
                // cout << "Seed at position " << i << " is used to generate " << (2*i + 2) << ": " << seeds[2*i+2][0] << " and " << (2*i + 3) << ": " << seeds[2*i+3][0] << endl;
            }
            
            for(int i = n - 2; i < 2*n - 2; ++i) {
                // cout << "seeds[" << i << "] = " << (seeds[i]) << endl;
                full_matrix[t][i - n + 2] = seeds[i][0] & mask_n_s;
            } 

            memcpy(b0_ptr, &seeds[0], sizeof(block));
            memcpy(b1_ptr, &seeds[1], sizeof(block));

            for(int i = 1; i < n_levels; ++i) {
                block sum_left = makeBlock(0, 0);
                block sum_right = makeBlock(0, 0);
                int start_left = (1<<(i+1)) - 2;
                int start_right = (1<<(i+1)) - 1;

                // cout << "start_left: " << start_left << ", start_right: " << start_right << endl;
                // cout << "j runs: " << (1 << i) << " times" << endl;

                for(int j = 0; j < (1 << i); ++j) {
                    sum_left  ^= seeds[start_left];
                    sum_right ^= seeds[start_right];
                    start_left  += 2;
                    start_right += 2;
                }

                memcpy(b0_ptr + i, &sum_left, sizeof(block));
                memcpy(b1_ptr + i, &sum_right, sizeof(block));
            }
            b0_ptr += n_levels;
            b1_ptr += n_levels;
        }
        delete [] seeds; 
        
        ot->send(b0, b1, n_levels * n);
        io->flush();

        delete [] b0;
        delete [] b1;

        // cout << "Full Matrix: " << endl;
        // for(int i = 0; i < n; ++i) {
        //     for(int j = 0; j < n; ++j)
        //         cout << setw(5) << (int)full_matrix[i][j] << " ";
        //     cout << endl;
        // }
        
        memset(ac[party_i-1], 0, n * sizeof(uint16_t));
        for(int i = 0; i < n; ++i) {
            bc[party_i-1][i] = 0;
            for(int j = 0; j < n; ++j) {
                ac[party_i-1][j] = (ac[party_i-1][j] + full_matrix[i][j]) & mask_n_s;
                bc[party_i-1][i] = (bc[party_i-1][i] + full_matrix[i][j]) & mask_n_s;
            }
        }

        // for(int i = 0; i < n; ++i) 
        //     cout << "ac[" << i << "] = " << (int)ac[party_i-1][i] << ", bc[" << i << "] = " << (int)bc[party_i-1][i] << endl;

        for(int i = 0; i < n; ++i)
            delete [] full_matrix[i];
        delete [] full_matrix;

    } else if(party == party_i) {
        uint16_t **punctured_matrix = new uint16_t*[n];
        for(int i = 0; i < n; ++i)
            punctured_matrix[i] = new uint16_t[n];

        bool *sel = new bool[n_levels * n];
        bool *sel_ptr = sel;

        int punctured_position, cpunctured_position;

        for(int t = 0; t < n; ++t) {
            punctured_position = punctured_positions[t];
            // cout << "punctured_position: " << cpunctured_position << endl;
            cpunctured_position = punctured_position ^ ((1<<n_levels)-1);
            // cout << "cpunctured_position: " << cpunctured_position << endl;

            for(int i = 1; i <= n_levels; ++i) {
                if (cpunctured_position >> (n_levels - i) & 0x1) 
                    sel_ptr[i-1] = true;
                else 
                    sel_ptr[i-1] = false;
            }
            sel_ptr += n_levels;
        }

        auto start = clock_start();

        block *r = new block[n_levels * n];
        ot->recv(r, sel, n_levels * n);        
        io->flush();
        
        block *rseeds  = new block[2*n - 2];
        block *r_ptr   = r;

        for(int t = 0; t < n; ++t) {
            int punctured_position  = punctured_positions[t];
            int cpunctured_position = punctured_position ^ ((1<<n_levels)-1);

            memset(rseeds, 0, (2*n-2)*sizeof(block));

            for(int i = 1; i <= n_levels; ++i) {

                block seed_value = r_ptr[i-1];
                int computed_seed = (1<<i) - 2 + ((punctured_position>>(n_levels-i)) ^ 0b1);
                // cout << "computed_seed: " << computed_seed << endl;
                int k = (1<<i) - 2 + ((cpunctured_position>>(n_levels-i)) & 0x1);
                for(int j = 0; j < (1<<(i-1)); ++j) {
                    if(k != computed_seed) {
                        seed_value ^= rseeds[k];
                        // cout << "seed_value is XORed with: " << k << endl;
                    }
                    k += 2;
                }
                memcpy(&rseeds[computed_seed], &seed_value, sizeof(block));

                if(i < n_levels) {
                    k = (1<<i) - 2;
                    for(int j = 0; j < (1<<i); ++j) {
                        if(rseeds[k][0] != 0) {
                            PRG prg(&rseeds[k]);
                            prg.random_block(&rseeds[2*k+2], 2);
                            // cout << "Generate from seed " << k << endl;
                        }
                        k++;
                    }
                }        
            }

            // cout << endl;
            for(int i = n - 2; i < 2*n - 2; ++i) {
                // cout << "rseeds[" << i << "] = " << (rseeds[i]) << endl;
                punctured_matrix[t][i-n+2] = rseeds[i][0] & mask_n_s;
            } 
            r_ptr += n_levels;
        }
        delete [] rseeds; 
        delete [] sel;
        delete [] r;

        // cout << "Punctured Matrix: " << endl;
        // for(int i = 0; i < n; ++i) {
        //     for(int j = 0; j < n; ++j)
        //         cout << setw(5) << (int)punctured_matrix[i][j];
        //     cout << endl;
        // }

        memset(ac[party_j-1], 0, n * sizeof(uint16_t));
        for(int i = 0; i < n; ++i) {
            bc[party_j-1][i] = 0;
            for(int j = 0; j < n; ++j) {
                ac[party_j-1][j] = (ac[party_j-1][j] + punctured_matrix[i][j]) & mask_n_s;
                bc[party_j-1][i] = (bc[party_j-1][i] + punctured_matrix[i][j]) & mask_n_s;
            }
        }

        for(int i = 0; i < n; ++i) 
            deltac[party_j-1][i] = (n_s + bc[party_j-1][i] - ac[party_j-1][punctured_positions[i]]) & mask_n_s;

        for(int i = 0; i < n; ++i)
            delete [] punctured_matrix[i];
        delete [] punctured_matrix;
    }
}

void preprocessing_counting() {

    cout << "Preprocessing counting..." << endl;

    r   = new uint16_t*[num_writers];
    e   = new uint16_t**[num_writers];
    
    for(int i = 0; i < num_writers; ++i) {
        r[i]     = new uint16_t[num_documents];
        e[i]     = new uint16_t*[num_documents];
        for(int j = 0; j < num_documents; ++j) {
            e[i][j] = new uint16_t[K+1];
        }
    }
    
    vector<future<void>> works;
    ThreadPool pool(MAX_THREADS);
    int execs_per_thread = num_documents/MAX_THREADS;
    
    // Reuse preprocessing materials to reduce preprocessing counting time in testing
    // for(int wid = 0; wid < num_writers; ++wid) {
    for(int wid = 0; wid < 1; ++wid) {
        for(int k = 0; k < MAX_THREADS; ++k) {
            works.push_back(pool.enqueue([execs_per_thread, wid, k]() {
                
                NetIOMP<nP> *io = new NetIOMP<nP>(party, port + (k+1)*1024);
                uint16_t **ac, **bc, **deltac;
                uint8_t  *pic;

                pic    = new uint8_t[K+1];
                ac     = new uint16_t*[nP];
                bc     = new uint16_t*[nP];
                deltac = new uint16_t*[nP];
                
                for(int i = 0; i < nP; ++i) {
                    ac[i]     = new uint16_t[K+1];
                    bc[i]     = new uint16_t[K+1];
                    deltac[i] = new uint16_t[K+1];
                }

                int start_exec = k * execs_per_thread;
                int end_exec   = start_exec + execs_per_thread;

                int port_parties[nP][nP];
                
                for(int i = 0; i < nP; ++i) {
                    int start_port = 16384 + k * 2048 - i * 100;
                    for(int j = 0; j < nP; ++j) {
                        port_parties[i][j] = start_port--;
                    }
                }
                
                for(int n = start_exec; n < end_exec; ++n) {
                    // Roulette protocol
                    uint16_t x;
                    prg.random_data(&x, sizeof(uint16_t));
                    r[wid][n] = x % (K+1);
                    // cout << "x = " << (int)r[wid][n] << endl;
                    for(uint8_t i = 0; i < K + 1; ++i) 
                        pic[i] = (i + K + 1 - r[wid][n]) % (K+1);

                    std::thread ts([port_parties, pic, ac, bc, deltac](){
                        for(int i = party + 1; i <= num_parties; ++i) {
                            // cout << "Preprocessing counting with party " << i << endl;
                            NetIO *io         = new NetIO(IP[i], port_parties[i-1][party-1], true);
                            IKNP<NetIO> *iknp = new IKNP<NetIO>(io, true);
                            shr_trns(iknp, io, i, party, pic, ac, bc, deltac);
                            delete io;
                            delete iknp;
                        }
                    }); 
                    
                    std::thread rs([port_parties, pic, ac, bc, deltac](){
                        for(int i = 1; i < party; ++i) {
                            // cout << "Preprocessing counting with party " << i << endl;
                            NetIO *io         = new NetIO(nullptr, port_parties[party-1][i-1], true);
                            IKNP<NetIO> *iknp = new IKNP<NetIO>(io, true);
                            shr_trns(iknp, io, party, i, pic, ac, bc, deltac);
                            delete io;
                            delete iknp;
                        }
                    });
                    
                    ts.join();
                    rs.join();

                    memset(deltac[party-1], 0, (K+1)*sizeof(uint16_t));
                    
                    if(party > 1) {
                        for(int i = 1; i < party; ++i)
                            for(int j = 0; j < K+1; ++j) 
                                deltac[party-1][j] = (deltac[party-1][j] + deltac[i-1][j]) & mask_n_s;
                    }

                    std::thread tsp([io, ac, bc](){
                        if(num_parties > 2 && party < num_parties) {
                            uint16_t *delta_prime = new uint16_t[K+1];
                            for(int i = party + 1; i < num_parties; ++i) {
                                for(int j = 0; j < K+1; ++j) 
                                    delta_prime[j] = (n_s + bc[i-1][j] - ac[i][j]) & mask_n_s;
                                io->send_data(i, delta_prime, (K+1)*sizeof(uint16_t));
                                io->flush();    
                            }
                            delete [] delta_prime;
                        }
                    });
                    
                    std::thread rsp([io, deltac](){
                        if(num_parties > 2 && party > 1 && party < num_parties) {        
                            uint16_t *delta_prime = new uint16_t[K+1];
                            for(int i = 1; i < party; ++i) {
                                io->recv_data(i, delta_prime, (K+1)*sizeof(uint16_t));
                                io->flush();    
                                for(int j = 0; j < K+1; ++j) 
                                    deltac[party-1][j] = (n_s + deltac[party-1][j] - delta_prime[j]) & mask_n_s;
                            }
                            delete [] delta_prime;
                        }
                    });
                    
                    tsp.join();
                    rsp.join();
                    
                    if(party < num_parties) {
                        for(int j = 0; j < K+1; ++j) 
                            deltac[party-1][j] = (deltac[party-1][j] + ac[party][j]) & mask_n_s;
                    }

                    uint16_t e1[K+1]; 
                    uint16_t e1c[K+1]; 
                    
                    if(party == 1) {
                        e1c[0] = 1; 
                        for(int i = 1; i < K + 1; ++i) 
                            e1c[i] = 0;
                        for(int i = 0; i < K + 1; ++i) 
                            e1[i] = (e1c[pic[i]] + deltac[party-1][i]) & mask_n_s;
                        io->send_data(party + 1, e1, (K+1)*sizeof(uint16_t));
                        io->flush();   
                        for(int i = 0; i < K + 1; ++i) 
                            e[wid][n][i] = (n_s - bc[num_parties-1][i]) & mask_n_s;
                        // cout << "e = ";
                        // for(int i = 0; i < K + 1; ++i) cout << (int)e[wid][n][i] << " ";
                        // cout << endl; 
                    }   
                    else if (party < num_parties) {
                        io->recv_data(party - 1, e1c, (K+1)*sizeof(uint16_t));
                        io->flush();    
                        for(int i = 0; i < K + 1; ++i) 
                            e1[i] = (e1c[pic[i]] + deltac[party-1][i]) & mask_n_s;
                        io->send_data(party + 1, e1, (K+1)*sizeof(uint16_t));
                        io->flush();   
                        for(int i = 0; i < K + 1; ++i) 
                            e[wid][n][i] = (n_s - bc[num_parties-1][i]) & mask_n_s;
                        // cout << "e = ";
                        // for(int i = 0; i < K + 1; ++i) cout << (int)e[wid][n][i] << " ";
                        // cout << endl;
                    } 
                    else {
                        io->recv_data(party - 1, e1, (K+1)*sizeof(uint16_t));
                        io->flush();    
                        for(int i = 0; i < K + 1; ++i) 
                            e[wid][n][i] = (e1[pic[i]] + deltac[party-1][i]) & mask_n_s;
                        // cout << "e = ";
                        // for(int i = 0; i < K + 1; ++i) cout << (int)e[wid][n][i] << " ";
                        // cout << endl;
                    }
                }

                for(int i = 0; i < nP; ++i) {
                    delete [] ac[i];
                    delete [] bc[i];
                    delete [] deltac[i];
                }
                delete [] ac;
                delete [] bc;
                delete [] deltac;
                delete [] pic;
            }));
        }
        joinNclean(works);
    }

    cout << "Finished preprocessing counting!" << endl;
}





