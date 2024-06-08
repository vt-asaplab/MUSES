#pragma once
#include <types.hpp>
#include <config.hpp>
#include <emp-tool/emp-tool.h>
#include <emp-ot/emp-ot.h>
#include <vector>
#include <ThreadPool.h>

using namespace std;

modp_t               ***a, ***b, ***delta;
uint32_t             **pi;
PRG                  prg;

extern int           num_parties;
extern int           party;
extern int           port; 
extern NetIOMP<nP>   *io;

void share_translation(IKNP<NetIO> *ot, NetIO *io, int party_i, int party_j, 
                       int n, uint32_t *punctured_positions, int wid) {
    
    int n_levels = (int)log2(n);
    // cout << "n_levels: " << n_levels << endl;
    
    if(party == party_j) {    
        a[wid][party_i-1] = new modp_t[n];
        b[wid][party_i-1] = new modp_t[n];

        uint16_t **full_matrix = new uint16_t*[n];
        for(int i = 0; i < n; ++i) 
            full_matrix[i] = new uint16_t[n];
        
        block *b0 = new block[n_levels * n];
        block *b1 = new block[n_levels * n];

        vector<future<void>> works;
        ThreadPool pool(MAX_THREADS);
        int execs_per_thread = n/MAX_THREADS;

        auto start = clock_start();

        for(int k = 0; k < MAX_THREADS; ++k) {
            works.push_back(pool.enqueue([k, execs_per_thread, b0, b1, full_matrix, n, n_levels]() {
                PRG prg;
                block *seeds = new block[2*n - 2];
                int start_exec = k * execs_per_thread;
                int end_exec   = start_exec + execs_per_thread;
                
                block *b0_ptr = b0 + start_exec * n_levels;
                block *b1_ptr = b1 + start_exec * n_levels;

                for(int t = start_exec; t < end_exec; ++t) {
                    prg.random_block(seeds, 2);
                    for(int i = 0; i < n - 2; ++i) {
                        PRG prg(&seeds[i]);
                        prg.random_block(&seeds[2*i + 2], 2);
                        // cout << "Seed at position " << i << " is used to generate " << (2*i + 2) << ": " << seeds[2*i+2][0] << " and " << (2*i + 3) << ": " << seeds[2*i+3][0] << endl;
                    }
                    
                    for(int i = n - 2; i < 2*n - 2; ++i) {
                        // cout << "seeds[" << i << "] = " << (seeds[i]) << endl;
                        full_matrix[t][i - n + 2] = seeds[i][0] & MASK_N_S;
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
            }));
        }

        joinNclean(works);    

        cout << "Precomputing time: " << time_from(start) << endl;

        start = clock_start();
        
        ot->send(b0, b1, n_levels * n);
        io->flush();

        cout << "IKNP OT delay: " << time_from(start) << endl;

        delete [] b0;
        delete [] b1;

        // cout << "Full Matrix: " << endl;
        // for(int i = 0; i < n; ++i) {
        //     for(int j = 0; j < n; ++j)
        //         cout << setw(5) << full_matrix[i][j] << " ";
        //     cout << endl;
        // }
        
        memset(a[wid][party_i-1], 0, n * sizeof(modp_t));
        for(int i = 0; i < n; ++i) {
            b[wid][party_i-1][i] = 0;
            for(int j = 0; j < n; ++j) {
                a[wid][party_i-1][j] = (a[wid][party_i-1][j] + full_matrix[i][j]) & MASK_N_S;
                b[wid][party_i-1][i] = (b[wid][party_i-1][i] + full_matrix[i][j]) & MASK_N_S;
            }
        }

        // for(int i = 0; i < n; ++i) 
        //     cout << "a[" << i << "] = " << a[i] << ", b[" << i << "] = " << b[i] << endl;

        for(int i = 0; i < n; ++i)
            delete [] full_matrix[i];
        delete [] full_matrix;

    } else if(party == party_i) {
        a[wid][party_j-1] = new modp_t[n];
        b[wid][party_j-1] = new modp_t[n];

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

        cout << "Precomputing + IKNP OT delay: " << time_from(start) << endl;
        
        // for(int i = 1; i <= n_levels; ++i) {
        //     if (cpunctured_position >> (n_levels - i) & 0x1) 
        //         memcpy(&r[i-1], &b1[i-1], sizeof(block));
        //     else 
        //         memcpy(&r[i-1], &b0[i-1], sizeof(block));
        // }

        // for(int i = 0; i < n_levels; ++i) {
        //     cout << "r: " << r[i] << endl;
        // }

        // Regenerate to check data
        vector<future<void>> works;
        ThreadPool pool(MAX_THREADS);
        int execs_per_thread = n/MAX_THREADS;

        for(int k = 0; k < MAX_THREADS; ++k) {
            works.push_back(pool.enqueue([k, execs_per_thread, n, n_levels, punctured_positions, r, punctured_matrix]() {
                block *rseeds  = new block[2*n - 2];

                int start_exec = k * execs_per_thread;
                int end_exec   = start_exec + execs_per_thread;

                block *r_ptr   = r + start_exec * n_levels;

                for(int t = start_exec; t < end_exec; ++t) {
                    int punctured_position = punctured_positions[t];
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
                        punctured_matrix[t][i-n+2] = rseeds[i][0] & MASK_N_S;
                    } 
                    r_ptr += n_levels;
                }
                delete [] rseeds; 
            }));
        }

        joinNclean(works);

        delete [] sel;
        delete [] r;

        // cout << "Punctured Matrix: " << endl;
        // for(int i = 0; i < n; ++i) {
        //     for(int j = 0; j < n; ++j)
        //         cout << setw(5) << punctured_matrix[i][j];
        //     cout << endl;
        // }
        
        memset(a[wid][party_j-1], 0, n * sizeof(modp_t));
        for(int i = 0; i < n; ++i) {
            b[wid][party_j-1][i] = 0;
            for(int j = 0; j < n; ++j) {
                a[wid][party_j-1][j] = (a[wid][party_j-1][j] + punctured_matrix[i][j]) & MASK_N_S;
                b[wid][party_j-1][i] = (b[wid][party_j-1][i] + punctured_matrix[i][j]) & MASK_N_S;
            }
        }

        delta[wid][party_j-1] = new modp_t[n];
        for(int i = 0; i < n; ++i) 
            delta[wid][party_j-1][i] = (N_S + b[wid][party_j-1][i] - a[wid][party_j-1][pi[wid][i]]) & MASK_N_S;
        
        delete [] a[wid][party_j-1];
        delete [] b[wid][party_j-1];

        // for(int i = 0; i < n; ++i) 
        //     cout << "a[" << i << "] = " << a[i] << ", b[" << i << "] = " << b[i] << endl;
        
        for(int i = 0; i < n; ++i)
            delete [] punctured_matrix[i];
        delete [] punctured_matrix;
    }
}

void preprocessing_shuffling(block &permutation_seed) {

    cout << "Preprocessing shuffling ..." << endl;

    int n = num_documents;
    uint32_t *random_indices = new uint32_t[n];
    
    prg.reseed(&permutation_seed);

    a     = new modp_t**[num_writers];
    b     = new modp_t**[num_writers];
    delta = new modp_t**[num_writers];
    pi    = new uint32_t*[num_writers];

    // for(int i = 0; i < num_writers; ++i) {
    for(int i = 0; i < 1; ++i) {
        a[i]     = new modp_t*[nP];
        b[i]     = new modp_t*[nP];
        delta[i] = new modp_t*[nP];
    }
    
    // for(int wid = 0; wid < num_writers; ++wid) {
    for(int wid = 0; wid < 1; ++wid) {
        if(party < nP) {
            prg.random_data(random_indices, n * sizeof(uint32_t));
            pi[wid] = new uint32_t[n];
            for(uint32_t i = 0; i < n; ++i)
                pi[wid][i] = i;

            for(uint32_t i = n - 1; i > 0; --i) {
                uint32_t j = random_indices[i] % (i + 1);
                uint32_t tmp = pi[wid][i]; pi[wid][i] = pi[wid][j]; pi[wid][j] = tmp;
            }
        }
    }
    
    delete [] random_indices; 

    int port_parties[nP][nP];
    for(int i = 0; i < nP; ++i) {
        int start_port = 32768 - i * 100;
        for(int j = 0; j < nP; ++j) {
            port_parties[i][j] = start_port--;
        }
    }
    
    std::thread ts([n, port_parties](){
        for(int i = 1; i < party; ++i) {
            cout << "Preprocessing shuffling with party " << i << endl;
            NetIO *io         = new NetIO(IP[i-1], port_parties[i-1][party-1]);
            IKNP<NetIO> *iknp = new IKNP<NetIO>(io, true);
            // for(int wid = 0; wid < num_writers; ++wid) 
            for(int wid = 0; wid < 1; ++wid) 
                share_translation(iknp, io, i, party, n, pi[wid], wid);
            delete io;
            delete iknp;
        }
    });

    std::thread rs([n, port_parties](){
        for(int i = party + 1; i <= num_parties; ++i) {
            cout << "Preprocessing shuffling with party " << i << endl;
            NetIO *io         = new NetIO(nullptr, port_parties[party-1][i-1]);
            IKNP<NetIO> *iknp = new IKNP<NetIO>(io, true);
            // for(int wid = 0; wid < num_writers; ++wid) 
            for(int wid = 0; wid < 1; ++wid) 
                share_translation(iknp, io, party, i, n, pi[wid], wid);
            delete io;
            delete iknp;
        }
    });

    ts.join();
    rs.join();

    // cout << "Permutation: ";
    // for(int i = 0; i < n; ++i) 
    //     cout << pi[i] << " ";
    // cout << endl;

    // cout << "Delta: ";
    // for(int i = 0; i < n; ++i)
    //     cout << delta[i] << " ";
    // cout << endl;

    if(party < num_parties) {
        // for(int wid = 0; wid < num_writers; ++wid) {
        for(int wid = 0; wid < 1; ++wid) {
            delta[wid][party-1] = new modp_t[num_documents];
            memset(delta[wid][party-1], 0, num_documents*sizeof(modp_t));
            for(int i = party; i < num_parties; ++i) {
                for(int j = 0; j < num_documents; ++j) 
                    delta[wid][party-1][j] = (delta[wid][party-1][j] + delta[wid][i][j]) & MASK_N_S;
                // cout  << "Delta[" << (party-1) << "] += " << "Delta[" << (i) << "]" << endl;
            }
        }
    }
    
    std::thread tsp([](){
        if(party > 2) {
            modp_t *delta_prime = new modp_t[num_documents];
            for(int i = 2; i < party; ++i) {
                // for(int wid = 0; wid < num_writers; ++wid) {
                for(int wid = 0; wid < 1; ++wid) {
                    for(int j = 0; j < num_documents; ++j) 
                        delta_prime[j] = (N_S + b[wid][i-2][j] - a[wid][i-1][j]) & MASK_N_S;
                    io->send_data(i, delta_prime, num_documents*sizeof(modp_t));
                    io->flush(i);    
                }
                // cout  << "Delta_Prime[" << (i) << "] = " << "b[" << (i-2) << "] - a[" << (i-1) << "]" << endl;
            }
            delete [] delta_prime;
        }
    });

    std::thread rsp([](){
        if(party > 1 && party < num_parties) {        
            modp_t *delta_prime = new modp_t[num_documents];
            for(int i = party + 1; i <= num_parties; ++i) {
                // for(int wid = 0; wid < num_writers; ++wid) {
                for(int wid = 0; wid < 1; ++wid) {
                    io->recv_data(i, delta_prime, num_documents*sizeof(modp_t));
                    io->flush(i);    
                    for(int j = 0; j < num_documents; ++j) 
                        delta[wid][party-1][j] = (N_S + delta[wid][party-1][j] - delta_prime[pi[wid][j]]) & MASK_N_S;
                }
                // cout  << "Delta[" << (party-1) << "] -= " << "Delta_Prime[" << (i-1) << "]" << endl;
            }
            delete [] delta_prime;
            // for(int wid = 0; wid < num_writers; ++wid)
            for(int wid = 0; wid < 1; ++wid)  
                for(int j = 0; j < num_documents; ++j) 
                    delta[wid][party-1][j] = (N_S + delta[wid][party-1][j] - b[wid][party-2][pi[wid][j]]) & MASK_N_S;

            // cout  << "Delta[" << (party-1) << "] -= " << "Pi(b[" << (party-2) << "])" << endl;
        }
    });

    tsp.join();
    rsp.join();

    cout << "Finished preprocessing shuffling!" << endl;
}

void mask(modp_t *data, int wid) {    
    for(int i = 0; i < num_documents; ++i) {
        // data[i] = (data[i] + a[wid][0][i]) & MASK_N_S;
	   data[i] = (data[i] + a[0][0][i]) & MASK_N_S;
    }
}

void shuffle(modp_t *data, modp_t *data_p1, modp_t *data_p2, int wid) {
    for(int i = 0; i < num_documents; ++i) {
        // data[i] = (delta[wid][party-1][i] + data_p1[pi[wid][i]] + data_p2[pi[wid][i]]) & MASK_N_S;
    	data[i] = (delta[0][party-1][i] + data_p1[pi[0][i]] + data_p2[pi[0][i]]) & MASK_N_S;
    }
}

void unmask(modp_t *data, int wid) {
    for(int i = 0; i < num_documents; ++i) {
        // data[i]    = (N_S + data[i] - b[wid][party-2][i]) & MASK_N_S;
        data[i]    = (N_S + data[i] - b[0][party-2][i]) & MASK_N_S;
        // data[i]  >>= E;
    }
}

