/*
 * keccak.c  -  Keccak-f[1600] permutation and Keccak-256 hash (original Keccak)
 * (project copy of pk/keccak.c; changes: PRINT_ROUNDS 0, padding 0x01 = Keccak-256
 *  instead of 0x06 = SHA3-256, function name keccak256)
 * Same structure as poly1305.c: this file holds the algorithm only,
 * the testbench (main) is in keccak_test.c.
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

/* rotation offsets r[x][y] for the rho step */
static const int RHO[5][5] = {
    { 0, 36,  3, 41, 18},
    { 1, 44, 10, 45,  2},
    {62,  6, 43, 15, 61},
    {28, 55, 25, 21, 56},
    {27, 20, 39,  8, 14}
};

void keccak_f1600(uint64_t A[25]) {
    uint64_t C[5], D[5], B[25];
    int round, x, y;

    for (round = 0; round < 24; round++) {
        /* theta */
        for (x = 0; x < 5; x++)
            C[x] = A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20];
        for (x = 0; x < 5; x++)
            D[x] = C[(x + 4) % 5] ^ ROTL64(C[(x + 1) % 5], 1);
        for (x = 0; x < 5; x++)
            for (y = 0; y < 5; y++)
                A[x + 5 * y] ^= D[x];

        /* rho + pi:  B[y, 2x+3y] = rot(A[x,y], r[x,y]) */
        for (x = 0; x < 5; x++)
            for (y = 0; y < 5; y++) {
                int r = RHO[x][y];
                uint64_t v = A[x + 5 * y];
                B[y + 5 * ((2 * x + 3 * y) % 5)] = (r == 0) ? v : ROTL64(v, r);
            }

        /* chi */
        for (x = 0; x < 5; x++)
            for (y = 0; y < 5; y++)
                A[x + 5 * y] = B[x + 5 * y] ^ ((~B[(x + 1) % 5 + 5 * y]) & B[(x + 2) % 5 + 5 * y]);

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
