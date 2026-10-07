/*
 * chacha20_sw.c  -  ChaCha20 in software (project-1 C code)
 *
 * quarterround() and chacha20_block() are copied unchanged from the
 * project-1 benchmark (ChaCha20.c.bak). They match RFC 8439 (checked
 * against its test vectors). chacha20_sw_encrypt() adds the XOR with the
 * plaintext, exactly like the project-1 main() did.
 */
#include <stdint.h>
#include "chacha20_sw.h"

#define ROTL(a,b) (((a) << (b)) | ((a) >> (32 - (b))))

// 1. The Core ChaCha20 "Quarter Round"
void quarterround(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    *a += *b; *d ^= *a; *d = ROTL(*d,16);
    *c += *d; *b ^= *c; *b = ROTL(*b,12);
    *a += *b; *d ^= *a; *d = ROTL(*d,8);
    *c += *d; *b ^= *c; *b = ROTL(*b,7);
}

// 2. The Main Block Function
void chacha20_block(uint8_t key[32], uint8_t nonce[12], uint32_t counter, uint8_t out[64]) {
    uint32_t state[16] = {
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
    };

    int i;
    for (i = 0; i < 8; i++) {
        state[4 + i] = ((uint32_t)key[i*4]) | ((uint32_t)key[i*4+1] << 8) |
                       ((uint32_t)key[i*4+2] << 16) | ((uint32_t)key[i*4+3] << 24);
    }
    state[12] = counter;
    for (i = 0; i < 3; i++) {
        state[13 + i] = ((uint32_t)nonce[i*4]) | ((uint32_t)nonce[i*4+1] << 8) |
                         ((uint32_t)nonce[i*4+2] << 16) | ((uint32_t)nonce[i*4+3] << 24);
    }

    uint32_t working[16];
    for (i = 0; i < 16; i++) working[i] = state[i];

    for (i = 0; i < 10; i++) {
        quarterround(&working[0], &working[4], &working[8], &working[12]);
        quarterround(&working[1], &working[5], &working[9], &working[13]);
        quarterround(&working[2], &working[6], &working[10], &working[14]);
        quarterround(&working[3], &working[7], &working[11], &working[15]);
        quarterround(&working[0], &working[5], &working[10], &working[15]);
        quarterround(&working[1], &working[6], &working[11], &working[12]);
        quarterround(&working[2], &working[7], &working[8], &working[13]);
        quarterround(&working[3], &working[4], &working[9], &working[14]);
    }

    for (i = 0; i < 16; i++) working[i] += state[i];

    for (i = 0; i < 16; i++) {
        out[i*4]   = (working[i]) & 0xFF;
        out[i*4+1] = (working[i] >> 8) & 0xFF;
        out[i*4+2] = (working[i] >> 16) & 0xFF;
        out[i*4+3] = (working[i] >> 24) & 0xFF;
    }
}

// 3. Encrypt one 64-byte block: keystream XOR plaintext (as in project 1)
void chacha20_sw_encrypt(uint8_t key[32], uint8_t nonce[12], uint32_t counter,
                         const uint8_t in[64], uint8_t out[64]) {
    uint8_t keystream[64];
    chacha20_block(key, nonce, counter, keystream);
    for (int i = 0; i < 64; i++) {
        out[i] = in[i] ^ keystream[i];
    }
}
