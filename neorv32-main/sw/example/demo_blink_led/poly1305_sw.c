/*
 * poly1305.c  -  Poly1305 MAC function (RFC 8439, Section 2.5)
 * Same structure as cha20-test.c: this file holds the algorithm only,
 * the testbench (main) is in poly1305_test.c.
 *
 * 130-bit accumulator split into 5 limbs of 26 bits (h0..h4).
 */
#include <stdint.h>
#include <string.h>

#define MASK26 0x3ffffff

static uint32_t load32_le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void store32_le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

void poly1305_mac(uint8_t key[32], const uint8_t *msg, uint32_t len, uint8_t tag[16]) {
    /* 1) r = key[0..15] clamped, split into 26-bit limbs */
    uint32_t r0 = (load32_le(key + 0))      & 0x3ffffff;
    uint32_t r1 = (load32_le(key + 3) >> 2) & 0x3ffff03;
    uint32_t r2 = (load32_le(key + 6) >> 4) & 0x3ffc0ff;
    uint32_t r3 = (load32_le(key + 9) >> 6) & 0x3f03fff;
    uint32_t r4 = (load32_le(key + 12) >> 8) & 0x00fffff;

    /* precomputed r*5 (because 2^130 = 5 mod p) */
    uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;

    uint32_t h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;  /* accumulator */

    /* 2) process 16-byte blocks: acc = (acc + block) * r  mod (2^130 - 5) */
    while (len > 0) {
        uint8_t block[16] = {0};
        uint32_t n = (len < 16) ? len : 16;
        uint32_t hibit;
        memcpy(block, msg, n);
        if (n < 16) { block[n] = 1; hibit = 0; }   /* partial block: append 0x01 */
        else        { hibit = 1u << 24; }          /* full block: bit 128 set   */

        h0 += (load32_le(block + 0))       & MASK26;
        h1 += (load32_le(block + 3) >> 2)  & MASK26;
        h2 += (load32_le(block + 6) >> 4)  & MASK26;
        h3 += (load32_le(block + 9) >> 6)  & MASK26;
        h4 += (load32_le(block + 12) >> 8) | hibit;

        uint64_t d0 = (uint64_t)h0*r0 + (uint64_t)h1*s4 + (uint64_t)h2*s3 + (uint64_t)h3*s2 + (uint64_t)h4*s1;
        uint64_t d1 = (uint64_t)h0*r1 + (uint64_t)h1*r0 + (uint64_t)h2*s4 + (uint64_t)h3*s3 + (uint64_t)h4*s2;
        uint64_t d2 = (uint64_t)h0*r2 + (uint64_t)h1*r1 + (uint64_t)h2*r0 + (uint64_t)h3*s4 + (uint64_t)h4*s3;
        uint64_t d3 = (uint64_t)h0*r3 + (uint64_t)h1*r2 + (uint64_t)h2*r1 + (uint64_t)h3*r0 + (uint64_t)h4*s4;
        uint64_t d4 = (uint64_t)h0*r4 + (uint64_t)h1*r3 + (uint64_t)h2*r2 + (uint64_t)h3*r1 + (uint64_t)h4*r0;

        /* carry propagation (partial reduction) */
        uint64_t c;
        c = d0 >> 26; h0 = (uint32_t)d0 & MASK26; d1 += c;
        c = d1 >> 26; h1 = (uint32_t)d1 & MASK26; d2 += c;
        c = d2 >> 26; h2 = (uint32_t)d2 & MASK26; d3 += c;
        c = d3 >> 26; h3 = (uint32_t)d3 & MASK26; d4 += c;
        c = d4 >> 26; h4 = (uint32_t)d4 & MASK26;
        h0 += (uint32_t)c * 5; c = h0 >> 26; h0 &= MASK26; h1 += (uint32_t)c;

        msg += n; len -= n;
    }

    /* 3) full carry */
    uint32_t c;
    c = h1 >> 26; h1 &= MASK26; h2 += c;
    c = h2 >> 26; h2 &= MASK26; h3 += c;
    c = h3 >> 26; h3 &= MASK26; h4 += c;
    c = h4 >> 26; h4 &= MASK26; h0 += c * 5;
    c = h0 >> 26; h0 &= MASK26; h1 += c;

    /* 4) final reduction: if h >= p then h = h - p  (constant time) */
    uint32_t g0 = h0 + 5;   c = g0 >> 26; g0 &= MASK26;
    uint32_t g1 = h1 + c;   c = g1 >> 26; g1 &= MASK26;
    uint32_t g2 = h2 + c;   c = g2 >> 26; g2 &= MASK26;
    uint32_t g3 = h3 + c;   c = g3 >> 26; g3 &= MASK26;
    uint32_t g4 = h4 + c - (1u << 26);

    uint32_t sel = (g4 >> 31) - 1;   /* all 1s if h >= p, else 0 */
    h0 = (h0 & ~sel) | (g0 & sel);
    h1 = (h1 & ~sel) | (g1 & sel);
    h2 = (h2 & ~sel) | (g2 & sel);
    h3 = (h3 & ~sel) | (g3 & sel);
    h4 = (h4 & ~sel) | (g4 & sel);

    /* 5) pack back to 4 x 32-bit words, then tag = (h + s) mod 2^128 */
    uint32_t w0 = h0 | (h1 << 26);
    uint32_t w1 = (h1 >> 6)  | (h2 << 20);
    uint32_t w2 = (h2 >> 12) | (h3 << 14);
    uint32_t w3 = (h3 >> 18) | (h4 << 8);

    uint64_t f;
    f = (uint64_t)w0 + load32_le(key + 16);             store32_le(tag + 0,  (uint32_t)f);
    f = (uint64_t)w1 + load32_le(key + 20) + (f >> 32); store32_le(tag + 4,  (uint32_t)f);
    f = (uint64_t)w2 + load32_le(key + 24) + (f >> 32); store32_le(tag + 8,  (uint32_t)f);
    f = (uint64_t)w3 + load32_le(key + 28) + (f >> 32); store32_le(tag + 12, (uint32_t)f);
}
