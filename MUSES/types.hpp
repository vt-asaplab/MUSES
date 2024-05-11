#pragma once
#include <config.hpp>

typedef uint16_t    modp_t;
typedef uint16_t    modq_t;
typedef uint32_t    mod2q_t;
typedef uint16_t    poly_modq_t[N];
typedef uint8_t     secret_token_t[N*sizeof(modp_t) + 16];
typedef uint8_t     private_token_t[N*sizeof(modp_t) + 16 + 33];
