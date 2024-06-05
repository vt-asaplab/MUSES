#pragma once
#include <iostream>
#include "libsecp256k1-config.h"
#include "secp256k1.c"
#include "secp256k1.h"
#include "secp256k1_preallocated.h"
#include "testrand_impl.h"
#include <chrono>
#include <stdlib.h>
#include <NTL/vec_ZZ_p.h>
#include <NTL/vec_ZZ.h>
#include <config.hpp>
#include <emp-tool/emp-tool.h>
#include <types.hpp>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

using namespace std;

std::string              GROUP_ORDER_STR("115792089237316195423570985008687907852837564279074904382605163141518161494337"); // Order of secp256k1
NTL::ZZ                  GROUP_ORDER(NTL::INIT_VAL, GROUP_ORDER_STR.c_str());
static secp256k1_context *CTX = NULL;
secp256k1_scalar         sk;
secp256k1_ge             pk;

void convert_ZZ_to_scalar(secp256k1_scalar &scalar, NTL::ZZ_p &ZZp_value)
{
    NTL::ZZ  temp;
    conv(temp, ZZp_value);
    long val;
    uint32_t *d = (uint32_t*)scalar.d;
    for(int i = 0; i < 8; ++i)
    {
        conv(val, temp & 0xFFFFFFFF);
        d[i]   = val;
        temp >>= 32;
    }
}

void ge_equals_ge(const secp256k1_ge *a, const secp256k1_ge *b) {
    CHECK(a->infinity == b->infinity);
    if (a->infinity) {
        return;
    }
    CHECK(secp256k1_fe_equal_var(&a->x, &b->x));
    CHECK(secp256k1_fe_equal_var(&a->y, &b->y));
}

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

void setup_public_private_keys() {
    CTX = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    
    // This seed is for synchronization with the servers in initialization 
    // rather than interaction between the reader and the servers 
    NTL::ZZ_p::init(GROUP_ORDER);
    NTL::SetSeed(NTL::conv<NTL::ZZ>((long) 2023));
    NTL::ZZ_p x = NTL::to_ZZ_p(NTL::RandomBits_ZZ(256));
    convert_ZZ_to_scalar(sk, x);
        
    secp256k1_gej tmp;
    secp256k1_ecmult_gen(&CTX->ecmult_gen_ctx, &tmp, &sk);
    secp256k1_ge_set_gej(&pk, &tmp);
}

void rotate_public_private_keys() {
    NTL::ZZ_p x = NTL::to_ZZ_p(NTL::RandomBits_ZZ(256));
    convert_ZZ_to_scalar(sk, x);
    
    secp256k1_gej tmp;
    secp256k1_ecmult_gen(&CTX->ecmult_gen_ctx, &tmp, &sk);
    secp256k1_ge_set_gej(&pk, &tmp);
}

void pk_encrypt(uint8_t *plaintext, uint8_t *ciphertext) {
    int num_trials = 1;
    secp256k1_gej tmp;
    secp256k1_ge R;
    size_t size;

    secp256k1_scalar r;
    NTL::ZZ_p x = NTL::to_ZZ_p(NTL::RandomBits_ZZ(256));
    convert_ZZ_to_scalar(r, x);

    // R = r * G
    secp256k1_ecmult_gen(&CTX->ecmult_gen_ctx, &tmp, &r);
    secp256k1_ge_set_gej(&R, &tmp);    
    secp256k1_eckey_pubkey_serialize(&R, ciphertext, &size, 1);

    // S = r * public_key
    secp256k1_ge S;
    secp256k1_ecmult_const(&tmp, &pk, &r, 256);
    secp256k1_ge_set_gej(&S, &tmp);

    // Shared key = KDF(S)
    unsigned char shared_key[32];
    secp256k1_sha256 sha256;
    secp256k1_sha256_initialize(&sha256);
    unsigned char out[65];
    secp256k1_eckey_pubkey_serialize(&S, out, &size, 0);
    secp256k1_sha256_write(&sha256, out, size);
    secp256k1_sha256_finalize(&sha256, shared_key);
    
    unsigned char *iv = (unsigned char *)"0123456789012345";
    int ciphertext_len = encrypt(plaintext, sizeof(poly_modq_t), shared_key, iv, ciphertext + 33);
}

void pk_decrypt(uint8_t *ciphertext, uint8_t *plaintext) {
    secp256k1_gej tmp;
    secp256k1_ge  R, S;

    secp256k1_eckey_pubkey_parse(&R, ciphertext, 33);
    secp256k1_ecmult_const(&tmp, &R, &sk, 256);
    secp256k1_ge_set_gej(&S, &tmp);
    
    // Shared key = KDF(S)
    unsigned char shared_key[32];
    secp256k1_sha256 sha256;
    secp256k1_sha256_initialize(&sha256);
    unsigned char out[65];
    size_t size;
    secp256k1_eckey_pubkey_serialize(&S, out, &size, 0);
    secp256k1_sha256_write(&sha256, out, size);
    secp256k1_sha256_finalize(&sha256, shared_key);

    unsigned char *iv = (unsigned char *)"0123456789012345";
    int plaintext_len = decrypt(ciphertext + 33, sizeof(poly_modq_t) + 16, shared_key, iv, plaintext);
}



