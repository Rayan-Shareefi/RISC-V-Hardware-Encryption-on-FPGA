/*
 * keccak_sw.h  -  Keccak-f[1600] and Keccak-256 (original Keccak, padding 0x01) in software
 * (pk/keccak.c copied to keccak_sw.c; changes: PRINT_ROUNDS 0, padding 0x01, name keccak256)
 */
#ifndef KECCAK_SW_H
#define KECCAK_SW_H

#include <stdint.h>

void keccak_f1600(uint64_t A[25]);
void keccak256(const uint8_t *msg, uint32_t len, uint8_t digest[32]);

#endif /* KECCAK_SW_H */
