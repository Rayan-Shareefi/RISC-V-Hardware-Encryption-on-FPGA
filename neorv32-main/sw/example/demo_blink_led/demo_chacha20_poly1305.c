/*
 * demo_chacha20_poly1305.c  -  DEMO 2: ChaCha20-Poly1305 (RFC 8439 AEAD),
 *                              software vs hardware
 *
 *  [1] Official tests  Poly1305 RFC 8439 2.5.2, and the complete ChaCha20-Poly1305
 *                      example RFC 8439 2.8.2 (114-byte message, 12-byte AAD)
 *  [2] Your message    encrypt + tag in SW and HW; the receiver checks the tag and
 *                      decrypts; then 1 bit of the ciphertext is changed and the
 *                      receiver must REJECT it
 *  [3] Benchmark       1000 x Poly1305 (64 bytes) and 1000 x ChaCha20-Poly1305
 *                      encryption (64-byte message + 12-byte AAD, a new nonce every
 *                      run) in SW and HW, live progress, then all 1000 checked: SW == HW
 *  [4] Results         time (1 us counter), cycles, speedup
 *
 * One ChaCha20-Poly1305 run (chacha20_poly1305.h) = ChaCha20 block 0 (gives the
 * one-time Poly1305 key) + ChaCha20 block 1 (encrypts the 64-byte message) +
 * Poly1305 over AAD | ciphertext | lengths (16 + 64 + 16 = 96 bytes).
 */
#include <neorv32.h>
#include <string.h>
#include "demo_util.h"
#include "crypto_accel.h"
#include "chacha20_sw.h"
#include "poly1305_sw.h"
#include "chacha20_poly1305.h"

#define RUNS    1000
#define CHUNK   100

/* ChaCha20-Poly1305 example: RFC 8439 2.8.2 */
static uint8_t key8[32] = {
  0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
  0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f
};
static uint8_t nonce8[12] = {0x07,0x00,0x00,0x00,0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47};
static const uint8_t AAD[12] = {0x50,0x51,0x52,0x53,0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7};
#define RFC_LEN 114
static const uint8_t RFC_PT[RFC_LEN + 1] =
  "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
static const uint8_t RFC_CT[RFC_LEN] = {
  0xd3,0x1a,0x8d,0x34,0x64,0x8e,0x60,0xdb,0x7b,0x86,0xaf,0xbc,0x53,0xef,0x7e,0xc2,
  0xa4,0xad,0xed,0x51,0x29,0x6e,0x08,0xfe,0xa9,0xe2,0xb5,0xa7,0x36,0xee,0x62,0xd6,
  0x3d,0xbe,0xa4,0x5e,0x8c,0xa9,0x67,0x12,0x82,0xfa,0xfb,0x69,0xda,0x92,0x72,0x8b,
  0x1a,0x71,0xde,0x0a,0x9e,0x06,0x0b,0x29,0x05,0xd6,0xa5,0xb6,0x7e,0xcd,0x3b,0x36,
  0x92,0xdd,0xbd,0x7f,0x2d,0x77,0x8b,0x8c,0x98,0x03,0xae,0xe3,0x28,0x09,0x1b,0x58,
  0xfa,0xb3,0x24,0xe4,0xfa,0xd6,0x75,0x94,0x55,0x85,0x80,0x8b,0x48,0x31,0xd7,0xbc,
  0x3f,0xf4,0xde,0xf0,0x8e,0x4b,0x7a,0x9d,0xe5,0x76,0xd2,0x65,0x86,0xce,0xc6,0x4b,
  0x61,0x16
};
static const uint8_t RFC_TAG[16] = {
  0x1a,0xe1,0x0b,0x59,0x4f,0x09,0xe2,0x6a,0x7e,0x90,0x2e,0xcb,0xd0,0x60,0x06,0x91
};

/* Poly1305 alone: key, message and tag of RFC 8439 2.5.2 */
static uint8_t pkey8[32] = {
  0x85,0xd6,0xbe,0x78,0x57,0x55,0x6d,0x33,0x7f,0x44,0x52,0xfe,0x42,0xd5,0x06,0xa8,
  0x01,0x03,0x80,0x8a,0xfb,0x0d,0xb2,0xfd,0x4a,0xbf,0xf6,0xaf,0x41,0x49,0xf5,0x1b
};
static const uint8_t POLY_MSG[34] = "Cryptographic Forum Research Group";
static const uint8_t POLY_TAG[16] = {
  0xa8,0x06,0x1d,0xc1,0x30,0x51,0x36,0xc6,0xc2,0x2b,0x8b,0xaf,0x0c,0x01,0x27,0xa9
};

static const char DEFAULT_MSG[] = "Transfer 100 SAR to account 1234";
static const char USER_AAD[]    = "From: board 1";    /* sent in clear, protected by the tag */

static uint32_t key_w[8], nonce_w[3], pkey_w[8];

/* ---------------------------------------------------------------------------
 * [1] official tests
 * ------------------------------------------------------------------------- */
static int official_tests(void) {
  static uint8_t  ct_sw[RFC_LEN];
  static uint32_t pt_w[(RFC_LEN + 3) / 4], ct_hw[(RFC_LEN + 3) / 4];
  uint8_t  sw[16], tag_sw[16], otk_sw[32];
  uint32_t msg_w[16] = {0}, hw[4], tag_hw[4], otk_hw[8];

  /* Poly1305 alone */
  memcpy(msg_w, POLY_MSG, 34);
  uint32_t c0 = neorv32_cpu_csr_read(CSR_MCYCLE);
  poly1305_mac(pkey8, POLY_MSG, 34, sw);
  uint32_t c1 = neorv32_cpu_csr_read(CSR_MCYCLE);
  poly1305_hw_mac(pkey_w, msg_w, 34, hw);
  uint32_t c2 = neorv32_cpu_csr_read(CSR_MCYCLE);
  int p_sw = (memcmp(sw, POLY_TAG, 16) == 0);
  int p_hw = (memcmp(hw, POLY_TAG, 16) == 0);

  demo_step("1] Official tests (RFC 8439)");
  neorv32_uart0_printf("  a) Poly1305, section 2.5.2: message ");
  print_text(POLY_MSG, 34);
  neorv32_uart0_printf("\n     Expected tag:  "); print_hex(POLY_TAG, 16);
  neorv32_uart0_printf("\n     Software:      "); print_hex(sw, 16);
  neorv32_uart0_printf("  %s  (%u cycles)\n     Hardware:      ", pass_fail(p_sw), c1 - c0);
  print_hex((const uint8_t *)hw, 16);
  neorv32_uart0_printf("  %s  (%u cycles)\n", pass_fail(p_hw), c2 - c1);

  /* complete ChaCha20-Poly1305 */
  memcpy(pt_w, RFC_PT, RFC_LEN);
  c0 = neorv32_cpu_csr_read(CSR_MCYCLE);
  aead_encrypt_sw(key8, nonce8, AAD, 12, RFC_PT, RFC_LEN, ct_sw, tag_sw, otk_sw);
  c1 = neorv32_cpu_csr_read(CSR_MCYCLE);
  aead_encrypt_hw(key_w, nonce_w, AAD, 12, pt_w, RFC_LEN, ct_hw, tag_hw, otk_hw);
  c2 = neorv32_cpu_csr_read(CSR_MCYCLE);
  int a_sw = (memcmp(ct_sw, RFC_CT, RFC_LEN) == 0) && (memcmp(tag_sw, RFC_TAG, 16) == 0);
  int a_hw = (memcmp(ct_hw, RFC_CT, RFC_LEN) == 0) && (memcmp(tag_hw, RFC_TAG, 16) == 0);

  neorv32_uart0_printf("\n  b) ChaCha20-Poly1305, section 2.8.2 (%u-byte message, 12-byte AAD)\n", (uint32_t)RFC_LEN);
  neorv32_uart0_printf("     Key:    "); print_hex(key8, 32);
  neorv32_uart0_printf("\n     Nonce:  "); print_hex(nonce8, 12);
  neorv32_uart0_printf("   AAD: "); print_hex(AAD, 12);
  neorv32_uart0_printf("\n     Message: "); print_text(RFC_PT, RFC_LEN);
  neorv32_uart0_printf("\n     Ciphertext (hardware):\n");
  hex_lines((const uint8_t *)ct_hw, RFC_LEN);
  neorv32_uart0_printf("     Expected tag:  "); print_hex(RFC_TAG, 16);
  neorv32_uart0_printf("\n     Software:      "); print_hex(tag_sw, 16);
  neorv32_uart0_printf("  %s  (ciphertext + tag, %u cycles)\n     Hardware:      ", pass_fail(a_sw), c1 - c0);
  print_hex((const uint8_t *)tag_hw, 16);
  neorv32_uart0_printf("  %s  (ciphertext + tag, %u cycles)\n", pass_fail(a_hw), c2 - c1);
  return !(p_sw && p_hw && a_sw && a_hw);
}

/* ---------------------------------------------------------------------------
 * [2] your message: encrypt + tag, the receiver checks, then a tamper test
 * ------------------------------------------------------------------------- */
static int your_message(void) {
  char     text[65];
  uint8_t  pt[64] = {0}, ct_sw[64], tag_sw[16], otk_sw[32];
  uint32_t pt_w[16], ct_hw[16], back_w[16], tag_hw[4], otk_hw[8];
  uint32_t aad_len = strlen(USER_AAD);

  demo_step("2] Your message: encrypt + authenticate");
  neorv32_uart0_printf("  Type a message (up to 64 characters) and press Enter,\n");
  neorv32_uart0_printf("  or wait %u s for the default message:\n", (uint32_t)INPUT_TIMEOUT);
  uint32_t n = read_line(text, 64);
  if (n == 0) {
    n = strlen(DEFAULT_MSG);
    memcpy(text, DEFAULT_MSG, n + 1);
  }
  memcpy(pt, text, n);
  memcpy(pt_w, pt, 64);

  /* sender (software and hardware) */
  aead_encrypt_sw(key8, nonce8, (const uint8_t *)USER_AAD, aad_len, pt, n, ct_sw, tag_sw, otk_sw);
  uint32_t c0 = neorv32_cpu_csr_read(CSR_MCYCLE);
  aead_encrypt_hw(key_w, nonce_w, (const uint8_t *)USER_AAD, aad_len, pt_w, n, ct_hw, tag_hw, otk_hw);
  uint32_t c1 = neorv32_cpu_csr_read(CSR_MCYCLE);
  int same = (memcmp(ct_sw, ct_hw, n) == 0) && (memcmp(tag_sw, tag_hw, 16) == 0);

  neorv32_uart0_printf("  Message:          "); print_text(pt, n);
  neorv32_uart0_printf("  (%u bytes)\n  AAD (in clear):   ", n); print_text((const uint8_t *)USER_AAD, aad_len);
  neorv32_uart0_printf("\n  Ciphertext (HW):\n");
  hex_lines((const uint8_t *)ct_hw, n);
  neorv32_uart0_printf("  Tag (SW):         "); print_hex(tag_sw, 16);
  neorv32_uart0_printf("\n  Tag (HW):         "); print_hex((const uint8_t *)tag_hw, 16);
  neorv32_uart0_printf("\n  Software == hardware: %s   (hardware encrypt + tag: %u cycles)\n", same ? "YES" : "NO", c1 - c0);

  /* receiver: check the tag, then decrypt */
  int accept_ok = aead_decrypt_hw(key_w, nonce_w, (const uint8_t *)USER_AAD, aad_len, ct_hw, n, tag_hw, back_w)
                  && (memcmp(back_w, pt, n) == 0);
  neorv32_uart0_printf("  Receiver, message unchanged:  tag matches -> %s, decrypted: ", accept_ok ? "ACCEPTED" : "REJECTED");
  print_text((const uint8_t *)back_w, n);
  neorv32_uart0_printf("\n");

  ((uint8_t *)ct_hw)[0] ^= 0x01;                         /* attacker flips 1 bit */
  int reject_ok = !aead_decrypt_hw(key_w, nonce_w, (const uint8_t *)USER_AAD, aad_len, ct_hw, n, tag_hw, back_w);
  neorv32_uart0_printf("  Receiver, 1 bit changed:      tag differs -> %s\n",
                       reject_ok ? "REJECTED, nothing decrypted (tampering detected)" : "ACCEPTED (BAD)");
  return !(same && accept_ok && reject_ok);
}

/* ---------------------------------------------------------------------------
 * [3] benchmark (progress printed between chunks, outside the timed part)
 * ------------------------------------------------------------------------- */
static meas_t run_poly_sw(void) {
  static uint8_t tag[16];
  meas_t total = {0, 0};
  bench_timer_t t;
  leds(LED_SW);
  progress("Poly1305 SW          ", 0, RUNS, 0);
  for (uint32_t c = 0; c < RUNS; c += CHUNK) {
    bench_start(&t);
    for (uint32_t i = c; i < c + CHUNK; i++) {
      poly1305_mac(pkey8, RFC_PT, 64, tag);
      MEMORY_BARRIER();
    }
    meas_add(&total, bench_stop(&t));
    progress("Poly1305 SW          ", c + CHUNK, RUNS, total.us);
  }
  neorv32_uart0_printf("\n");
  return total;
}

static meas_t run_poly_hw(void) {
  static uint32_t msg[16], tag[4];
  meas_t total = {0, 0};
  bench_timer_t t;
  memcpy(msg, RFC_PT, 64);
  leds(LED_HW);
  progress("Poly1305 HW          ", 0, RUNS, 0);
  for (uint32_t c = 0; c < RUNS; c += CHUNK) {
    bench_start(&t);
    for (uint32_t i = c; i < c + CHUNK; i++) {
      poly1305_hw_mac64(pkey_w, msg, tag);
      MEMORY_BARRIER();
    }
    meas_add(&total, bench_stop(&t));
    progress("Poly1305 HW          ", c + CHUNK, RUNS, total.us);
  }
  neorv32_uart0_printf("\n");
  return total;
}

static meas_t run_aead_sw(void) {
  static uint8_t ct[64], tag[16], otk[32], nonce[12];
  meas_t total = {0, 0};
  bench_timer_t t;
  memcpy(nonce, nonce8, 12);
  leds(LED_SW);
  progress("ChaCha20-Poly1305 SW ", 0, RUNS, 0);
  for (uint32_t c = 0; c < RUNS; c += CHUNK) {
    bench_start(&t);
    for (uint32_t i = c; i < c + CHUNK; i++) {
      memcpy(nonce, &i, 4);                            /* a new nonce for every message */
      aead_encrypt_sw(key8, nonce, AAD, 12, RFC_PT, 64, ct, tag, otk);
      MEMORY_BARRIER();
    }
    meas_add(&total, bench_stop(&t));
    progress("ChaCha20-Poly1305 SW ", c + CHUNK, RUNS, total.us);
  }
  neorv32_uart0_printf("\n");
  return total;
}

static meas_t run_aead_hw(void) {
  static uint32_t in[16], ct[16], tag[4], otk[8], nonce[3];
  meas_t total = {0, 0};
  bench_timer_t t;
  memcpy(in, RFC_PT, 64);
  memcpy(nonce, nonce_w, 12);
  leds(LED_HW);
  progress("ChaCha20-Poly1305 HW ", 0, RUNS, 0);
  for (uint32_t c = 0; c < RUNS; c += CHUNK) {
    bench_start(&t);
    for (uint32_t i = c; i < c + CHUNK; i++) {
      nonce[0] = i;                                    /* a new nonce for every message */
      aead_encrypt_hw(key_w, nonce, AAD, 12, in, 64, ct, tag, otk);
      MEMORY_BARRIER();
    }
    meas_add(&total, bench_stop(&t));
    progress("ChaCha20-Poly1305 HW ", c + CHUNK, RUNS, total.us);
  }
  neorv32_uart0_printf("\n");
  return total;
}

/* all 1000 runs: software == hardware (ciphertext and tag), not timed */
static int check_all(void) {
  uint8_t  ct_sw[64], tag_sw[16], otk_sw[32], nonce[12];
  uint32_t in[16], ct_hw[16], tag_hw[4], otk_hw[8], nonce_hw[3];
  uint32_t bad = 0;
  memcpy(in, RFC_PT, 64);
  memcpy(nonce, nonce8, 12);
  memcpy(nonce_hw, nonce_w, 12);
  for (uint32_t i = 0; i < RUNS; i++) {
    memcpy(nonce, &i, 4);
    nonce_hw[0] = i;
    aead_encrypt_sw(key8, nonce, AAD, 12, RFC_PT, 64, ct_sw, tag_sw, otk_sw);
    aead_encrypt_hw(key_w, nonce_hw, AAD, 12, in, 64, ct_hw, tag_hw, otk_hw);
    bad += (memcmp(ct_sw, ct_hw, 64) != 0) || (memcmp(tag_sw, tag_hw, 16) != 0);
    if ((i + 1) % CHUNK == 0) {
      neorv32_uart0_printf("\r  Checking SW == HW: %u/%u messages, %u differences   ", i + 1, (uint32_t)RUNS, bad);
    }
  }
  neorv32_uart0_printf(" %s\n", pass_fail(bad == 0));
  return bad != 0;
}

int main(void) {
  neorv32_rte_setup();
  neorv32_uart0_setup(BAUD_RATE, 0);
  neorv32_gpio_dir_set(0xFF);
  memcpy(key_w, key8, 32);
  memcpy(nonce_w, nonce8, 12);
  memcpy(pkey_w, pkey8, 32);

  while (1) {
    leds(LED_IDLE);
    demo_banner("DEMO 2: ChaCha20-Poly1305 (RFC 8439) - software vs hardware");
    int fails = official_tests();
    fails += your_message();

    demo_step("3] Benchmark: 1000 runs each (64-byte message, 12-byte AAD)");
    neorv32_uart0_printf("  LD1 = software running, LD2 = hardware running\n");
    meas_t psw = run_poly_sw();
    meas_t phw = run_poly_hw();
    meas_t asw = run_aead_sw();
    meas_t ahw = run_aead_hw();
    leds(LED_IDLE);
    fails += check_all();

    demo_step("4] Results: time from first input to last output (1 us counter)");
    print_result("Poly1305, software          ", psw, RUNS);
    print_result("Poly1305, hardware          ", phw, RUNS);
    print_result("ChaCha20-Poly1305, software ", asw, RUNS);
    print_result("ChaCha20-Poly1305, hardware ", ahw, RUNS);
    print_speedup("Poly1305         ", psw, phw);
    print_speedup("ChaCha20-Poly1305", asw, ahw);
    neorv32_uart0_printf("  One ChaCha20-Poly1305 run = 2 ChaCha20 blocks (key + message) and Poly1305\n");
    neorv32_uart0_printf("  over 96 bytes. Hardware cores alone: ChaCha20 10 cycles per block,\n");
    neorv32_uart0_printf("  Poly1305 22 cycles per 16 bytes; the rest is the CPU moving the data.\n");

    neorv32_uart0_printf(fails ? "\n*** SOME CHECKS FAILED ***\n" : "\nALL CHECKS PASSED\n");
    leds(fails ? LED_FAIL : LED_PASS);
    wait_for_key();
  }
  return 0;
}
