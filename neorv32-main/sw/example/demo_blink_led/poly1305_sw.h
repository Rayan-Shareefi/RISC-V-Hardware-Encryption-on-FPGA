/*
 * poly1305_sw.h  -  Poly1305 MAC in software (pk/poly1305 (1).c, unchanged
 * copy in poly1305_sw.c). 130-bit accumulator in 5 limbs of 26 bits.
 */
#ifndef POLY1305_SW_H
#define POLY1305_SW_H

#include <stdint.h>

/* tag = Poly1305(key, msg[0..len-1]); key = r (16 bytes) || s (16 bytes) */
void poly1305_mac(uint8_t key[32], const uint8_t *msg, uint32_t len, uint8_t tag[16]);

#endif /* POLY1305_SW_H */
