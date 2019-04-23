/**********************************************************************
 * Copyright (c) 2016 Llamasoft                                       *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

// After building secp256k1_fast_unsafe, compile benchmarks with:
//   gcc -Wall -Wno-unused-function -O2 --std=c99 -march=native -I src/ -I ./ bench_privkey.c timer.c -lgmp -o bench_privkey


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "timer.h"

#define HAVE_CONFIG_H
#include "libsecp256k1-config.h"
#include "secp256k1.c"
#include "ecmult_big_impl.h"
#include "secp256k1_batch_impl.h"


void rand_privkey(unsigned char *privkey) {
    // Not cryptographically secure, but good enough for quick verification tests
    for ( size_t pos = 0; pos < 32; pos++ ) {
        privkey[pos] = rand() & 0xFF;
    }
}

void hex_dump(void *data, size_t len) {
    unsigned char *chr = data;
    for ( size_t pos = 0; pos < len; pos++, chr++ ) { printf("%02x ", *chr & 0xFF); }
}


void *safe_calloc(size_t num, size_t size) {
    void *rtn = calloc(num, size);
    if ( !rtn ) {
        printf("calloc failed to allocate %zu items of size %zu\n", num, size);
        exit(EXIT_FAILURE);
    }
    return rtn;
}


// Hackishly converts an uncompressed public key to a compressed public key
// The input is considered 65 bytes, the output should be considered 33 bytes
void secp256k1_pubkey_uncomp_to_comp(unsigned char *pubkey) {
    pubkey[0] = 0x02 | (pubkey[64] & 0x01);
}


const unsigned char baseline_privkey[32] = {
    // generated using srand(31415926), first 256 calls of rand() & 0xFF
    0xb9, 0x43, 0x14, 0xa3, 0x7d, 0x33, 0x46, 0x16, 0xd8, 0x0d, 0x62, 0x1b, 0x11, 0xa5, 0x9f, 0xdd,
    0x13, 0x56, 0xf6, 0xec, 0xbb, 0x9e, 0xb1, 0x9e, 0xfd, 0xe6, 0xe0, 0x55, 0x43, 0xb4, 0x1f, 0x30
};

const unsigned char baseline_expected[65] = {
    0x04, 0xfa, 0xf4, 0x5a, 0x13, 0x1f, 0xe3, 0x16, 0xe7, 0x59, 0x78, 0x17, 0xf5, 0x32, 0x14, 0x0d,
    0x75, 0xbb, 0xc2, 0xb7, 0xdc, 0xd6, 0x18, 0x35, 0xea, 0xbc, 0x29, 0xfa, 0x5d, 0x7f, 0x80, 0x25,
    0x51, 0xe5, 0xae, 0x5b, 0x10, 0xcf, 0xc9, 0x97, 0x0c, 0x0d, 0xca, 0xa1, 0xab, 0x7d, 0xc1, 0xb3,
    0x40, 0xbc, 0x5b, 0x3d, 0xf6, 0x87, 0xa5, 0xbc, 0xe7, 0x26, 0x67, 0xfd, 0x6c, 0xe6, 0xc3, 0x66, 0x29
};



int main(int argc, char **argv) {
    unsigned int iter_exp   = ( argc > 1 ? atoi(argv[1]) : 16 );    // Number of iterations as 2^N
    unsigned int bmul_size  = ( argc > 2 ? atoi(argv[2]) : 18 );    // ecmult_big window size in bits
    unsigned int batch_size = ( argc > 3 ? atoi(argv[3]) : 16 );    // ecmult_batch size in keys

    unsigned int iterations = (1 << iter_exp);
    unsigned int total_keys = iterations * batch_size;

    struct timespec clock_start;
    double clock_diff;

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);

    secp256k1_ecmult_big_context* bmul = secp256k1_ecmult_big_create(ctx, bmul_size);

    // Initializing secp256k1_scratch for batched key calculations
    secp256k1_scratch *scr = secp256k1_scratch_create(ctx, batch_size);
    ////////////////////////////////////////////////////////////////////////////////
    //                                 Benchmark                                  //
    ////////////////////////////////////////////////////////////////////////////////

    unsigned char *privkeys = (unsigned char*)safe_calloc(batch_size, 32 * sizeof(unsigned char));
    unsigned char *pubkeys  = (unsigned char*)safe_calloc(batch_size, 65 * sizeof(unsigned char));
secp256k1_pubkey point;


secp256k1_sha256_t sha;
        unsigned char s_b32[32];
        unsigned char output_ecdh[65];
        unsigned char output_ser[32];
        unsigned char point_ser[65];
        size_t point_ser_len = sizeof(point_ser);
        secp256k1_scalar s;
    // Get a rough estimate of how long privkey randomization takes
   // for ( size_t iter = 0; iter < iterations; iter++ ) {
   //     rand_privkey(&privkeys[32 * (iter % batch_size)]);
   // }


    // Actual benchmark loop
   // for ( size_t iter = 0; iter < iterations; iter++ ) {
   //     for ( size_t b = 0; b < batch_size; b++ ) {
            rand_privkey(&privkeys[0]);
   //     }

        // Wrapped in if to prevent "ignoring return value" warning
        secp256k1_ec_pubkey_create(ctx, &point, s_b32);
secp256k1_ec_pubkey_serialize(ctx, point_ser, &point_ser_len, &point, SECP256K1_EC_COMPRESSED);
        secp256k1_sha256_initialize(&sha);
        secp256k1_sha256_write(&sha, point_ser, point_ser_len);
        secp256k1_sha256_finalize(&sha, output_ser);

  //  }

for (int i = 0; i<33 ; i++) printf("%c", output_ser); 
//printf("key: %d \n",pubkeys);
    return 0;
}
