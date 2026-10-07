/*
 * keccak_sw.h  -  Keccak-f[1600] and SHA3-256 in software
 * (pk/keccak.c copied to keccak_sw.c, only change: PRINT_ROUNDS 1 -> 0)
 */
#ifndef KECCAK_SW_H
#define KECCAK_SW_H

#include <stdint.h>

void keccak_f1600(uint64_t A[25]);
void sha3_256(const uint8_t *msg, uint32_t len, uint8_t digest[32]);

#endif /* KECCAK_SW_H */
