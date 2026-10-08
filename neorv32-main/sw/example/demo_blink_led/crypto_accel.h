/*
 * crypto_accel.h  -  C interface for the crypto hardware
 *
 *   Custom crypto instructions (CFU)  -> hw/crypto_accel.vhd
 *   1 microsecond counter (CFS)       -> neorv32_cfs.vhd
 *
 * All custom instructions use the RISC-V CUSTOM-0 opcode (R-type, funct7 = 0):
 *   funct3 = 000  chacha.start           start ChaCha20 on the loaded block
 *   funct3 = 001  crypto.write rs1, rs2  register[rs1] = rs2
 *   funct3 = 010  crypto.read  rd, rs1   rd = register[rs1] (waits until ready)
 *   funct3 = 011  poly.start             start Poly1305 on the loaded message
 *   funct3 = 100  keccak.start           start Keccak-256 on the loaded message
 */
#ifndef CRYPTO_ACCEL_H
#define CRYPTO_ACCEL_H

#include <neorv32.h>
#include <stdint.h>

/* ---- custom instructions ---- */
#define CHACHA_START()          RISCV_INSTR_R_TYPE(RISCV_OPCODE_CUSTOM0, 0b000, 0b0000000, 0, 0)
#define CRYPTO_WRITE(idx, val)  RISCV_INSTR_R_TYPE(RISCV_OPCODE_CUSTOM0, 0b001, 0b0000000, (idx), (val))
#define CRYPTO_READ(idx)        RISCV_INSTR_R_TYPE(RISCV_OPCODE_CUSTOM0, 0b010, 0b0000000, (idx), 0)
#define POLY_START()            RISCV_INSTR_R_TYPE(RISCV_OPCODE_CUSTOM0, 0b011, 0b0000000, 0, 0)
#define KECCAK_START()          RISCV_INSTR_R_TYPE(RISCV_OPCODE_CUSTOM0, 0b100, 0b0000000, 0, 0)

/* ---- register map (see crypto_accel in hw/crypto_accel.vhd) ---- */
#define CH_KEY      0x00  /* 8 words, write-only            */
#define CH_NONCE    0x08  /* 3 words                        */
#define CH_COUNTER  0x0B  /* block counter                  */
#define CH_STATUS   0x0C  /* bit 0 = done, bit 1 = busy     */
#define CH_DATA     0x10  /* 16 words: write plaintext, read ciphertext */
#define PO_KEY      0x20  /* 8 words: r (0x20-0x23) || s (0x24-0x27), write-only */
#define PO_LEN      0x28  /* piece length in bytes (0..64)  */
#define PO_STATUS   0x29  /* bit 0 = done, bit 1 = busy     */
#define PO_CTRL     0x2A  /* control: CTRL_INIT | CTRL_FINAL */
#define PO_TAG      0x2C  /* 4 words (16-byte tag), read    */
#define PO_MSG      0x30  /* 16 words: message piece        */
#define KE_MSG      0x40  /* 34 words: one 136-byte Keccak block */
#define KE_LEN      0x62  /* block length (last block 0..135, others 136) */
#define KE_STATUS   0x63  /* bit 0 = done, bit 1 = busy     */
#define KE_CTRL     0x64  /* control: CTRL_INIT | CTRL_FINAL */
#define KE_DIGEST   0x68  /* 8 words (32-byte digest), read */

/* control bits (Poly1305 and Keccak): long messages are sent in pieces;
 * the unit keeps its state between pieces when CTRL_INIT is 0 */
#define CTRL_INIT   1     /* first piece: start a new message */
#define CTRL_FINAL  2     /* last piece: finish, make the tag / digest */

/* ---- 1 microsecond counter (CFS) ---- */
#define US_COUNTER  (NEORV32_CFS->REG[0])  /* read: microseconds, write: set value */
#define US_PER_TICK (NEORV32_CFS->REG[1])  /* clock cycles per microsecond (12)    */

/*
 * Encrypt one 64-byte block with the ChaCha20 hardware.
 * All data is in 32-bit little-endian words (RISC-V is little-endian, so
 * word i holds bytes 4i..4i+3): key = 8 words, nonce = 3 words, in/out = 16 words.
 */
static inline void chacha20_hw_block(const uint32_t key[8], const uint32_t nonce[3],
                                     uint32_t counter, const uint32_t in[16], uint32_t out[16]) {
  int i;
  for (i = 0; i < 8; i++)  CRYPTO_WRITE(CH_KEY + i, key[i]);
  for (i = 0; i < 3; i++)  CRYPTO_WRITE(CH_NONCE + i, nonce[i]);
  CRYPTO_WRITE(CH_COUNTER, counter);
  for (i = 0; i < 16; i++) CRYPTO_WRITE(CH_DATA + i, in[i]);
  CHACHA_START();
  for (i = 0; i < 16; i++) out[i] = CRYPTO_READ(CH_DATA + i);  /* first read waits for done */
}

/*
 * Faster driver for many blocks with the same key and nonce (this is how a
 * long message is encrypted: only the block counter changes per block).
 *   1) chacha20_hw_set_key() once   2) chacha20_hw_block_fast() per block
 * The key/nonce stay in the accelerator's registers between blocks, and the
 * loops are unrolled so no loop/branch instructions run between transfers.
 */
static inline void chacha20_hw_set_key(const uint32_t key[8], const uint32_t nonce[3]) {
  #pragma GCC unroll 8
  for (int i = 0; i < 8; i++) CRYPTO_WRITE(CH_KEY + i, key[i]);
  #pragma GCC unroll 3
  for (int i = 0; i < 3; i++) CRYPTO_WRITE(CH_NONCE + i, nonce[i]);
}

static inline void chacha20_hw_block_fast(uint32_t counter, const uint32_t in[16], uint32_t out[16]) {
  CRYPTO_WRITE(CH_COUNTER, counter);
  #pragma GCC unroll 16
  for (int i = 0; i < 16; i++) CRYPTO_WRITE(CH_DATA + i, in[i]);
  CHACHA_START();
  #pragma GCC unroll 16
  for (int i = 0; i < 16; i++) out[i] = CRYPTO_READ(CH_DATA + i);  /* first read waits for done */
}

/*
 * Encrypt (or decrypt - it is the same) a message of any length with ChaCha20:
 * block counter, counter+1, ... One 64-byte block per hardware run.
 * in/out are word arrays; out must hold (len + 3) / 4 words.
 * chacha20_hw_crypt: the same, when key + nonce are already loaded.
 */
static inline void chacha20_hw_crypt(uint32_t counter, const uint32_t *in, uint32_t *out, uint32_t len) {
  while (len >= 64) {                              /* key + nonce must be loaded already */
    chacha20_hw_block_fast(counter++, in, out);
    in += 16; out += 16; len -= 64;
  }
  if (len > 0) {                                   /* last, partial block: only the words */
    uint32_t n = (len + 3) / 4;                    /* of the message are sent and read    */
    CRYPTO_WRITE(CH_COUNTER, counter);             /* (the other data words are not used) */
    #pragma GCC unroll 16
    for (uint32_t i = 0; i < n; i++) CRYPTO_WRITE(CH_DATA + i, in[i]);
    CHACHA_START();
    #pragma GCC unroll 16
    for (uint32_t i = 0; i < n; i++) out[i] = CRYPTO_READ(CH_DATA + i);
  }
}

static inline void chacha20_hw_encrypt(const uint32_t key[8], const uint32_t nonce[3], uint32_t counter,
                                       const uint32_t *in, uint32_t *out, uint32_t len) {
  chacha20_hw_set_key(key, nonce);
  chacha20_hw_crypt(counter, in, out, len);
}

/*
 * Poly1305 tag of a message of any length with the hardware.
 * The message is sent in 64-byte pieces (control register: CTRL_INIT on the
 * first piece, CTRL_FINAL on the last); the hardware keeps its running value
 * in between. The next piece is written while the previous one is computed.
 * key = 8 words (r || s); msg must hold (len + 3) / 4 words; tag = 4 words.
 */
static inline void poly1305_hw_mac(const uint32_t key[8], const uint32_t *msg, uint32_t len, uint32_t tag[4]) {
  uint32_t ctrl = CTRL_INIT;
  #pragma GCC unroll 8
  for (int i = 0; i < 8; i++) CRYPTO_WRITE(PO_KEY + i, key[i]);
  while (len > 64) {                               /* full 64-byte pieces */
    #pragma GCC unroll 16
    for (int i = 0; i < 16; i++) CRYPTO_WRITE(PO_MSG + i, msg[i]);
    CRYPTO_WRITE(PO_LEN, 64);
    CRYPTO_WRITE(PO_CTRL, ctrl);
    (void)CRYPTO_READ(PO_TAG);                     /* waits until the previous piece is done */
    POLY_START();
    msg += 16; len -= 64; ctrl = 0;
  }
  #pragma GCC unroll 16
  for (uint32_t i = 0; i < (len + 3) / 4; i++) CRYPTO_WRITE(PO_MSG + i, msg[i]);
  CRYPTO_WRITE(PO_LEN, len);
  CRYPTO_WRITE(PO_CTRL, ctrl | CTRL_FINAL);
  (void)CRYPTO_READ(PO_TAG);                       /* waits until the previous piece is done */
  POLY_START();
  #pragma GCC unroll 4
  for (int i = 0; i < 4; i++) tag[i] = CRYPTO_READ(PO_TAG + i);  /* first read waits for done */
}

/* the same for exactly 64 bytes in one piece, fully unrolled (fastest) */
static inline void poly1305_hw_mac64(const uint32_t key[8], const uint32_t msg[16], uint32_t tag[4]) {
  #pragma GCC unroll 8
  for (int i = 0; i < 8; i++) CRYPTO_WRITE(PO_KEY + i, key[i]);
  CRYPTO_WRITE(PO_LEN, 64);
  CRYPTO_WRITE(PO_CTRL, CTRL_INIT | CTRL_FINAL);
  #pragma GCC unroll 16
  for (int i = 0; i < 16; i++) CRYPTO_WRITE(PO_MSG + i, msg[i]);
  POLY_START();
  #pragma GCC unroll 4
  for (int i = 0; i < 4; i++) tag[i] = CRYPTO_READ(PO_TAG + i);
}

/*
 * Keccak-256 digest of a message of any length with the hardware.
 * The message is sent in 136-byte blocks (the Keccak-256 rate) and a last
 * block of 0..135 bytes that the hardware pads (CTRL_FINAL). The hardware
 * keeps its 1600-bit state between blocks; the next block is written while
 * the previous one is computed.
 * msg must hold (len + 3) / 4 words; digest = 8 words.
 */
static inline void keccak256_hw(const uint32_t *msg, uint32_t len, uint32_t digest[8]) {
  uint32_t ctrl = CTRL_INIT;
  while (len >= 136) {                             /* full 136-byte blocks */
    #pragma GCC unroll 34
    for (int i = 0; i < 34; i++) CRYPTO_WRITE(KE_MSG + i, msg[i]);
    CRYPTO_WRITE(KE_LEN, 136);
    CRYPTO_WRITE(KE_CTRL, ctrl);
    (void)CRYPTO_READ(KE_DIGEST);                  /* waits until the previous block is done */
    KECCAK_START();
    msg += 34; len -= 136; ctrl = 0;
  }
  #pragma GCC unroll 34
  for (uint32_t i = 0; i < (len + 3) / 4; i++) CRYPTO_WRITE(KE_MSG + i, msg[i]);
  CRYPTO_WRITE(KE_LEN, len);
  CRYPTO_WRITE(KE_CTRL, ctrl | CTRL_FINAL);
  (void)CRYPTO_READ(KE_DIGEST);                    /* waits until the previous block is done */
  KECCAK_START();
  #pragma GCC unroll 8
  for (int i = 0; i < 8; i++) digest[i] = CRYPTO_READ(KE_DIGEST + i);  /* first read waits for done */
}

/* the same for exactly 64 bytes in one block, fully unrolled (fastest) */
static inline void keccak256_hw64(const uint32_t msg[16], uint32_t digest[8]) {
  #pragma GCC unroll 16
  for (int i = 0; i < 16; i++) CRYPTO_WRITE(KE_MSG + i, msg[i]);
  CRYPTO_WRITE(KE_LEN, 64);
  CRYPTO_WRITE(KE_CTRL, CTRL_INIT | CTRL_FINAL);
  KECCAK_START();
  #pragma GCC unroll 8
  for (int i = 0; i < 8; i++) digest[i] = CRYPTO_READ(KE_DIGEST + i);
}

#endif /* CRYPTO_ACCEL_H */
