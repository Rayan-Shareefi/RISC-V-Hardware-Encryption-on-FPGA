/*
 * chacha20_poly1305.h  -  ChaCha20-Poly1305 authenticated encryption (AEAD),
 *                         RFC 8439 section 2.8, in software and in hardware
 *
 * Encrypt (sender):
 *   1) Poly1305 one-time key = first 32 bytes of ChaCha20 block 0 (key, nonce)
 *   2) ciphertext = message XOR ChaCha20 keystream, blocks 1, 2, 3, ...
 *   3) tag = Poly1305(one-time key, MAC input), where the MAC input is
 *        AAD | zeros to 16 | ciphertext | zeros to 16 | len(AAD) | len(ciphertext)
 *      (the two lengths are 8-byte little-endian numbers)
 * Decrypt (receiver): compute the tag again from the received ciphertext;
 * only if it is equal, decrypt. A changed bit anywhere -> tag differs -> reject.
 *
 * AAD ("additional authenticated data") is sent in clear text but protected by
 * the tag, e.g. a packet header. It may be empty.
 *
 * Software version: chacha20_block / chacha20_sw_encrypt (chacha20_sw.c, project 1)
 *                   and poly1305_mac (poly1305_sw.c).
 * Hardware version: crypto_accel.h drivers (custom instructions).
 * Both build the MAC input the same way, so the comparison is fair.
 *
 * Checked with the official RFC 8439 2.8.2 example (demo_chacha20_poly1305.c,
 * crypto_hw_test.c) and a Python reference (scripts/gen_poly1305_vectors.py).
 */
#ifndef CHACHA20_POLY1305_H
#define CHACHA20_POLY1305_H

#include <stdint.h>
#include <string.h>
#include "chacha20_sw.h"
#include "poly1305_sw.h"
#include "crypto_accel.h"

/* not every program uses every function */
#define AEAD_API static __attribute__((unused))

#ifndef AEAD_MAX_AAD
#define AEAD_MAX_AAD   64      /* largest AAD in bytes      */
#endif
#ifndef AEAD_MAX_MSG
#define AEAD_MAX_MSG   256     /* largest message in bytes  */
#endif

/* MAC input buffer (word array, so the hardware driver can send it directly) */
static uint32_t aead_mac_buf[(AEAD_MAX_AAD + 16 + AEAD_MAX_MSG + 16 + 16) / 4];

/* build the MAC input in aead_mac_buf, return its length in bytes */
AEAD_API uint32_t aead_mac_input(const uint8_t *aad, uint32_t aad_len, const uint8_t *ct, uint32_t len) {
  uint8_t *b = (uint8_t *)aead_mac_buf;
  uint32_t n = 0;
  memcpy(b, aad, aad_len);  n += aad_len;
  while (n % 16) b[n++] = 0;                       /* zeros to a multiple of 16 */
  memcpy(b + n, ct, len);   n += len;
  while (n % 16) b[n++] = 0;
  /* the two 8-byte little-endian lengths (n is a multiple of 16 here, so these are
     whole words; the upper 4 bytes are 0 because the lengths are small) */
  aead_mac_buf[n / 4]     = aad_len;
  aead_mac_buf[n / 4 + 1] = 0;
  aead_mac_buf[n / 4 + 2] = len;
  aead_mac_buf[n / 4 + 3] = 0;
  return n + 16;
}

/* ---- software -------------------------------------------------------------- */

/* ChaCha20 over len bytes, blocks counter, counter+1, ... (software) */
AEAD_API void chacha20_sw_crypt(uint8_t key[32], uint8_t nonce[12], uint32_t counter,
                              const uint8_t *in, uint8_t *out, uint32_t len) {
  uint8_t ks[64];
  while (len >= 64) {
    chacha20_sw_encrypt(key, nonce, counter++, in, out);
    in += 64; out += 64; len -= 64;
  }
  if (len > 0) {                                   /* last, partial block: keystream XOR */
    chacha20_block(key, nonce, counter, ks);       /* only the message bytes             */
    for (uint32_t i = 0; i < len; i++) out[i] = in[i] ^ ks[i];
  }
}

/* encrypt: ct = len bytes, tag = 16 bytes; also returns the one-time Poly1305 key */
AEAD_API void aead_encrypt_sw(uint8_t key[32], uint8_t nonce[12], const uint8_t *aad, uint32_t aad_len,
                            const uint8_t *pt, uint32_t len, uint8_t *ct, uint8_t tag[16], uint8_t otk[32]) {
  uint8_t blk0[64];
  chacha20_block(key, nonce, 0, blk0);             /* 1) one-time key = block 0 */
  memcpy(otk, blk0, 32);
  chacha20_sw_crypt(key, nonce, 1, pt, ct, len);   /* 2) encrypt with blocks 1, 2, ... */
  uint32_t n = aead_mac_input(aad, aad_len, ct, len);
  poly1305_mac(otk, (const uint8_t *)aead_mac_buf, n, tag);   /* 3) tag */
}

/* decrypt: returns 1 and pt if the tag is right, 0 (and no pt) if not */
AEAD_API int aead_decrypt_sw(uint8_t key[32], uint8_t nonce[12], const uint8_t *aad, uint32_t aad_len,
                           const uint8_t *ct, uint32_t len, const uint8_t tag[16], uint8_t *pt) {
  uint8_t blk0[64], chk[16], diff = 0;
  chacha20_block(key, nonce, 0, blk0);
  uint32_t n = aead_mac_input(aad, aad_len, ct, len);
  poly1305_mac(blk0, (const uint8_t *)aead_mac_buf, n, chk);
  for (int i = 0; i < 16; i++) diff |= chk[i] ^ tag[i];
  if (diff) return 0;                              /* wrong tag: reject */
  chacha20_sw_crypt(key, nonce, 1, ct, pt, len);
  return 1;
}

/* ---- hardware -------------------------------------------------------------- */
/* All buffers are word arrays (byte i of the message = byte i of the array). */

AEAD_API void aead_encrypt_hw(const uint32_t key[8], const uint32_t nonce[3], const uint8_t *aad, uint32_t aad_len,
                            const uint32_t *pt, uint32_t len, uint32_t *ct, uint32_t tag[4], uint32_t otk[8]) {
  static uint32_t zero[16];                        /* all 0: block 0 gives the keystream */
  uint32_t blk0[16];
  chacha20_hw_set_key(key, nonce);
  chacha20_hw_block_fast(0, zero, blk0);           /* 1) one-time key = block 0 */
  for (int i = 0; i < 8; i++) otk[i] = blk0[i];
  chacha20_hw_crypt(1, pt, ct, len);               /* 2) encrypt with blocks 1, 2, ... (same key) */
  uint32_t n = aead_mac_input(aad, aad_len, (const uint8_t *)ct, len);
  poly1305_hw_mac(otk, aead_mac_buf, n, tag);      /* 3) tag (long input: sent in pieces) */
}

AEAD_API int aead_decrypt_hw(const uint32_t key[8], const uint32_t nonce[3], const uint8_t *aad, uint32_t aad_len,
                           const uint32_t *ct, uint32_t len, const uint32_t tag[4], uint32_t *pt) {
  static uint32_t zero[16];
  uint32_t blk0[16], chk[4], diff = 0;
  chacha20_hw_set_key(key, nonce);
  chacha20_hw_block_fast(0, zero, blk0);
  uint32_t n = aead_mac_input(aad, aad_len, (const uint8_t *)ct, len);
  poly1305_hw_mac(blk0, aead_mac_buf, n, chk);
  for (int i = 0; i < 4; i++) diff |= chk[i] ^ tag[i];
  if (diff) return 0;                              /* wrong tag: reject */
  chacha20_hw_crypt(1, ct, pt, len);
  return 1;
}

#endif /* CHACHA20_POLY1305_H */
