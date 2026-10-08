/*
 * keccak.c  -  Keccak-f[1600] permutation and Keccak-256 hash (original Keccak)
 * (project copy of pk/keccak.c; changes: PRINT_ROUNDS 0, padding 0x01 = Keccak-256
 *  instead of 0x06 = SHA3-256, function name keccak256)
 * Same structure as poly1305.c: this file holds the algorithm only,
 * the testbench (main) is in keccak_test.c.
 *
 * Fast version (2026-10-08): the rho + pi step is written out lane by lane with
 * fixed rotation amounts, and theta/chi use fixed lane numbers. The first
 * version used "% 5" and rotations by a variable amount, which this small CPU
 * does very slowly, so the SW-vs-HW comparison was unfair to the software.
 * Same results; the old version is kept in "old c files/OLD_keccak_sw.c.txt".
 *
 * State: 25 lanes of 64 bits, lane index = x + 5*y
 * (in the VHDL circuit the same lane is state(y)(x)).
 *
 * PRINT_ROUNDS = 1 prints the first plane (lanes x = 0..4, y = 0) after
 * every round, to compare step by step with the Vivado waveform.
 */
#include <stdint.h>
#include <string.h>
#ifndef __SYNTHESIS__
#include <stdio.h>
#endif

#define PRINT_ROUNDS 0

#define ROTL64(a, n) (((a) << (n)) | ((a) >> (64 - (n))))

static const uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808AULL, 0x8000000080008000ULL,
    0x000000000000808BULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008AULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000AULL,
    0x000000008000808BULL, 0x800000000000008BULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800AULL, 0x800000008000000AULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

void keccak_f1600(uint64_t A[25]) {
    uint64_t C0, C1, C2, C3, C4, D0, D1, D2, D3, D4, B[25];
    int round, y;

    for (round = 0; round < 24; round++) {
        /* theta: C[x] = column parity, D[x] = C[x-1] ^ rot(C[x+1], 1) */
        C0 = A[0] ^ A[5] ^ A[10] ^ A[15] ^ A[20];
        C1 = A[1] ^ A[6] ^ A[11] ^ A[16] ^ A[21];
        C2 = A[2] ^ A[7] ^ A[12] ^ A[17] ^ A[22];
        C3 = A[3] ^ A[8] ^ A[13] ^ A[18] ^ A[23];
        C4 = A[4] ^ A[9] ^ A[14] ^ A[19] ^ A[24];
        D0 = C4 ^ ROTL64(C1, 1);
        D1 = C0 ^ ROTL64(C2, 1);
        D2 = C1 ^ ROTL64(C3, 1);
        D3 = C2 ^ ROTL64(C4, 1);
        D4 = C3 ^ ROTL64(C0, 1);
        for (y = 0; y < 25; y += 5) {
            A[y + 0] ^= D0;
            A[y + 1] ^= D1;
            A[y + 2] ^= D2;
            A[y + 3] ^= D3;
            A[y + 4] ^= D4;
        }

        /* rho + pi:  B[y, 2x+3y] = rot(A[x,y], r[x,y]), every lane written out */
        B[ 0] = A[ 0];
        B[ 1] = ROTL64(A[ 6], 44);
        B[ 2] = ROTL64(A[12], 43);
        B[ 3] = ROTL64(A[18], 21);
        B[ 4] = ROTL64(A[24], 14);
        B[ 5] = ROTL64(A[ 3], 28);
        B[ 6] = ROTL64(A[ 9], 20);
        B[ 7] = ROTL64(A[10],  3);
        B[ 8] = ROTL64(A[16], 45);
        B[ 9] = ROTL64(A[22], 61);
        B[10] = ROTL64(A[ 1],  1);
        B[11] = ROTL64(A[ 7],  6);
        B[12] = ROTL64(A[13], 25);
        B[13] = ROTL64(A[19],  8);
        B[14] = ROTL64(A[20], 18);
        B[15] = ROTL64(A[ 4], 27);
        B[16] = ROTL64(A[ 5], 36);
        B[17] = ROTL64(A[11], 10);
        B[18] = ROTL64(A[17], 15);
        B[19] = ROTL64(A[23], 56);
        B[20] = ROTL64(A[ 2], 62);
        B[21] = ROTL64(A[ 8], 55);
        B[22] = ROTL64(A[14], 39);
        B[23] = ROTL64(A[15], 41);
        B[24] = ROTL64(A[21],  2);

        /* chi: A[x,y] = B[x,y] ^ (~B[x+1,y] & B[x+2,y]) */
        for (y = 0; y < 25; y += 5) {
            A[y + 0] = B[y + 0] ^ (~B[y + 1] & B[y + 2]);
            A[y + 1] = B[y + 1] ^ (~B[y + 2] & B[y + 3]);
            A[y + 2] = B[y + 2] ^ (~B[y + 3] & B[y + 4]);
            A[y + 3] = B[y + 3] ^ (~B[y + 4] & B[y + 0]);
            A[y + 4] = B[y + 4] ^ (~B[y + 0] & B[y + 1]);
        }

        /* iota */
        A[0] ^= RC[round];

#if PRINT_ROUNDS && !defined(__SYNTHESIS__)
        printf("Round %2d: %016llx %016llx %016llx %016llx %016llx\n", round + 1,
               (unsigned long long)A[0], (unsigned long long)A[1], (unsigned long long)A[2],
               (unsigned long long)A[3], (unsigned long long)A[4]);
#endif
    }
}

/* Padding byte after the message - the ONLY difference between
     0x01 = Keccak-256 (original Keccak, e.g. Ethereum, "Keccak-256" online tools)
     0x06 = SHA3-256   (NIST FIPS 202 standard)                                    */
#define KECCAK_PAD 0x01

/* Keccak-256: rate = 136 bytes, capacity = 512 bits, padding KECCAK_PAD ... 0x80 */
void keccak256(const uint8_t *msg, uint32_t len, uint8_t digest[32]) {
    uint64_t A[25];
    uint8_t block[136];
    uint32_t i, n;

    memset(A, 0, sizeof A);

    for (;;) {
        n = (len < 136) ? len : 136;
        memset(block, 0, sizeof block);
        memcpy(block, msg, n);
        if (n < 136) {                  /* last block: add padding */
            block[n]   ^= KECCAK_PAD;
            block[135] ^= 0x80;
        }
        for (i = 0; i < 17; i++) {      /* absorb: XOR 17 lanes (little-endian) */
            uint64_t w = 0;
            int b;
            for (b = 7; b >= 0; b--) w = (w << 8) | block[8 * i + b];
            A[i] ^= w;
        }
        keccak_f1600(A);
        if (n < 136) break;
        msg += 136;
        len -= 136;
    }

    for (i = 0; i < 32; i++)            /* squeeze: first 32 bytes of the state */
        digest[i] = (uint8_t)(A[i / 8] >> (8 * (i % 8)));
}
