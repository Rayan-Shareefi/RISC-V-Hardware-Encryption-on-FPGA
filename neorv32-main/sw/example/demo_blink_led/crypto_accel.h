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
 *   funct3 = 100  keccak.start           start SHA3-256 on the loaded message
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
#define PO_LEN      0x28  /* message length in bytes (0..64) */
#define PO_STATUS   0x29  /* bit 0 = done, bit 1 = busy     */
#define PO_TAG      0x2C  /* 4 words (16-byte tag), read    */
#define PO_MSG      0x30  /* 16 words: message              */
#define KE_MSG      0x40  /* 16 words: message              */
#define KE_LEN      0x50  /* message length in bytes (0..64) */
#define KE_STATUS   0x51  /* bit 0 = done, bit 1 = busy     */
#define KE_DIGEST   0x58  /* 8 words (32-byte digest), read */

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
 * Poly1305 tag of a message of len bytes (0..64) with the hardware.
 * key = 8 words (r || s); msg must hold (len + 3) / 4 words (only these are sent);
 * tag = 4 words (16 bytes).
 */
static inline void poly1305_hw_mac(const uint32_t key[8], const uint32_t *msg, uint32_t len, uint32_t tag[4]) {
  #pragma GCC unroll 8
  for (int i = 0; i < 8; i++) CRYPTO_WRITE(PO_KEY + i, key[i]);
  CRYPTO_WRITE(PO_LEN, len);
  for (uint32_t i = 0; i < (len + 3) / 4; i++) CRYPTO_WRITE(PO_MSG + i, msg[i]);
  POLY_START();
  #pragma GCC unroll 4
  for (int i = 0; i < 4; i++) tag[i] = CRYPTO_READ(PO_TAG + i);  /* first read waits for done */
}

/* the same for exactly 64 bytes, fully unrolled (fastest) */
static inline void poly1305_hw_mac64(const uint32_t key[8], const uint32_t msg[16], uint32_t tag[4]) {
  #pragma GCC unroll 8
  for (int i = 0; i < 8; i++) CRYPTO_WRITE(PO_KEY + i, key[i]);
  CRYPTO_WRITE(PO_LEN, 64);
  #pragma GCC unroll 16
  for (int i = 0; i < 16; i++) CRYPTO_WRITE(PO_MSG + i, msg[i]);
  POLY_START();
  #pragma GCC unroll 4
  for (int i = 0; i < 4; i++) tag[i] = CRYPTO_READ(PO_TAG + i);
}

/*
 * SHA3-256 digest of a message of len bytes (0..64) with the hardware.
 * msg must hold (len + 3) / 4 words (only these are sent); digest = 8 words.
 */
static inline void sha3_256_hw(const uint32_t *msg, uint32_t len, uint32_t digest[8]) {
  for (uint32_t i = 0; i < (len + 3) / 4; i++) CRYPTO_WRITE(KE_MSG + i, msg[i]);
  CRYPTO_WRITE(KE_LEN, len);
  KECCAK_START();
  #pragma GCC unroll 8
  for (int i = 0; i < 8; i++) digest[i] = CRYPTO_READ(KE_DIGEST + i);  /* first read waits for done */
}

/* the same for exactly 64 bytes, fully unrolled (fastest) */
static inline void sha3_256_hw64(const uint32_t msg[16], uint32_t digest[8]) {
  #pragma GCC unroll 16
  for (int i = 0; i < 16; i++) CRYPTO_WRITE(KE_MSG + i, msg[i]);
  CRYPTO_WRITE(KE_LEN, 64);
  KECCAK_START();
  #pragma GCC unroll 8
  for (int i = 0; i < 8; i++) digest[i] = CRYPTO_READ(KE_DIGEST + i);
}

#endif /* CRYPTO_ACCEL_H */
