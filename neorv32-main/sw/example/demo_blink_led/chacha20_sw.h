/*
 * chacha20_sw.h  -  ChaCha20 in software (project-1 C code)
 */
#ifndef CHACHA20_SW_H
#define CHACHA20_SW_H

#include <stdint.h>

void quarterround(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d);
void chacha20_block(uint8_t key[32], uint8_t nonce[12], uint32_t counter, uint8_t out[64]);

/* encrypt one 64-byte block: out = in XOR keystream(key, nonce, counter) */
void chacha20_sw_encrypt(uint8_t key[32], uint8_t nonce[12], uint32_t counter,
                         const uint8_t in[64], uint8_t out[64]);

#endif /* CHACHA20_SW_H */
