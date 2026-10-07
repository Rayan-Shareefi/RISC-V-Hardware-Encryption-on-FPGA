/*
 * demo_chacha20_poly1305.c  -  DEMO 2: ChaCha20 + Poly1305 (Encrypt + MAC),
 *                              software vs hardware
 *
 *  [1] Official test   Poly1305 RFC 8439 2.5.2 in SW and HW vs the RFC tag
 *  [2] Your message    encrypt + tag in SW and HW; then 1 bit of the ciphertext
 *                      is changed and the tag check must REJECT it
 *  [3] Benchmark       1000 x Poly1305 and 1000 x (encrypt 64 bytes + tag) in SW
 *                      and HW, live progress, then all 1000 runs checked: SW == HW
 *  [4] Results         time (1 us counter), cycles, speedup
 *
 * One "Encrypt + MAC" run = ChaCha20 encrypts a 64-byte block, then Poly1305
 * makes a 16-byte tag of the ciphertext (the receiver recomputes the tag to
 * detect any change).
 */
#include <neorv32.h>
#include <string.h>
#include "demo_util.h"
#include "crypto_accel.h"
#include "chacha20_sw.h"
#include "poly1305_sw.h"

#define RUNS    1000
#define CHUNK   100

/* ChaCha20 key/nonce/plaintext: RFC 8439 2.4.2 */
static uint8_t key8[32] = {
  0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
  0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
};
static uint8_t nonce8[12] = {0,0,0,0,0,0,0,0x4a,0,0,0,0};
static const uint8_t RFC_PT[64] = "Ladies and Gentlemen of the class of '99: If I could offer you o";

/* Poly1305 key, message and tag: RFC 8439 2.5.2 */
static uint8_t pkey8[32] = {
  0x85,0xd6,0xbe,0x78,0x57,0x55,0x6d,0x33,0x7f,0x44,0x52,0xfe,0x42,0xd5,0x06,0xa8,
  0x01,0x03,0x80,0x8a,0xfb,0x0d,0xb2,0xfd,0x4a,0xbf,0xf6,0xaf,0x41,0x49,0xf5,0x1b
};
static const uint8_t RFC_MSG[34] = "Cryptographic Forum Research Group";
static const uint8_t RFC_TAG[16] = {
  0xa8,0x06,0x1d,0xc1,0x30,0x51,0x36,0xc6,0xc2,0x2b,0x8b,0xaf,0x0c,0x01,0x27,0xa9
};
static const char DEFAULT_MSG[] = "Transfer 100 SAR to account 1234";

static uint32_t key_w[8], nonce_w[3], pkey_w[8];

/* ---------------------------------------------------------------------------
 * [1] official test
 * ------------------------------------------------------------------------- */
static int official_test(void) {
  uint8_t  sw[16];
  uint32_t msg_w[16] = {0}, hw[4];
  memcpy(msg_w, RFC_MSG, 34);

  uint32_t c0 = neorv32_cpu_csr_read(CSR_MCYCLE);
  poly1305_mac(pkey8, RFC_MSG, 34, sw);
  uint32_t c1 = neorv32_cpu_csr_read(CSR_MCYCLE);
  poly1305_hw_mac(pkey_w, msg_w, 34, hw);
  uint32_t c2 = neorv32_cpu_csr_read(CSR_MCYCLE);

  int sw_ok = (memcmp(sw, RFC_TAG, 16) == 0);
  int hw_ok = (memcmp(hw, RFC_TAG, 16) == 0);

  demo_step("1] Official test: Poly1305, RFC 8439 section 2.5.2");
  neorv32_uart0_printf("  Key:       "); print_hex(pkey8, 32);
  neorv32_uart0_printf("\n  Message:   "); print_text(RFC_MSG, 34);
  neorv32_uart0_printf("\n  Expected:  "); print_hex(RFC_TAG, 16);
  neorv32_uart0_printf("\n  Software:  "); print_hex(sw, 16);
  neorv32_uart0_printf("  %s  (%u cycles)\n  Hardware:  ", pass_fail(sw_ok), c1 - c0);
  print_hex((const uint8_t *)hw, 16);
  neorv32_uart0_printf("  %s  (%u cycles)\n", pass_fail(hw_ok), c2 - c1);
  return !(sw_ok && hw_ok);
}

/* ---------------------------------------------------------------------------
 * [2] your message: encrypt + tag, then a tamper test
 * ------------------------------------------------------------------------- */
static int your_message(void) {
  char     text[65];
  uint8_t  pt[64] = {0}, ct_sw[64], tag_sw[16];
  uint32_t pt_w[16], ct_hw[16], tag_hw[4], tag_chk[4];

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

  /* sender: encrypt, then tag the ciphertext (software and hardware) */
  chacha20_sw_encrypt(key8, nonce8, 1, pt, ct_sw);
  poly1305_mac(pkey8, ct_sw, n, tag_sw);
  uint32_t c0 = neorv32_cpu_csr_read(CSR_MCYCLE);
  chacha20_hw_block(key_w, nonce_w, 1, pt_w, ct_hw);
  poly1305_hw_mac(pkey_w, ct_hw, n, tag_hw);
  uint32_t c1 = neorv32_cpu_csr_read(CSR_MCYCLE);
  int same = (memcmp(ct_sw, ct_hw, n) == 0) && (memcmp(tag_sw, tag_hw, 16) == 0);

  neorv32_uart0_printf("  Message:          "); print_text(pt, n);
  neorv32_uart0_printf("  (%u bytes)\n  Ciphertext (HW):  ", n); print_hex((const uint8_t *)ct_hw, n);
  neorv32_uart0_printf("\n  Tag (SW):         "); print_hex(tag_sw, 16);
  neorv32_uart0_printf("\n  Tag (HW):         "); print_hex((const uint8_t *)tag_hw, 16);
  neorv32_uart0_printf("\n  Software == hardware: %s   (hardware encrypt + tag: %u cycles)\n", same ? "YES" : "NO", c1 - c0);

  /* receiver: recompute the tag of what arrived and compare */
  poly1305_hw_mac(pkey_w, ct_hw, n, tag_chk);
  int accept_ok = (memcmp(tag_chk, tag_hw, 16) == 0);
  neorv32_uart0_printf("  Receiver, message unchanged:     tag matches -> %s\n", accept_ok ? "ACCEPTED" : "REJECTED");

  ((uint8_t *)ct_hw)[0] ^= 0x01;                         /* attacker flips 1 bit */
  poly1305_hw_mac(pkey_w, ct_hw, n, tag_chk);
  int reject_ok = (memcmp(tag_chk, tag_hw, 16) != 0);
  neorv32_uart0_printf("  Receiver, 1 bit changed:         new tag ");
  print_hex((const uint8_t *)tag_chk, 16);
  neorv32_uart0_printf("\n                                   tag differs -> %s\n", reject_ok ? "REJECTED (tampering detected)" : "ACCEPTED (BAD)");
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
  progress("Poly1305 SW    ", 0, RUNS, 0);
  for (uint32_t c = 0; c < RUNS; c += CHUNK) {
    bench_start(&t);
    for (uint32_t i = c; i < c + CHUNK; i++) {
      poly1305_mac(pkey8, RFC_PT, 64, tag);
      MEMORY_BARRIER();
    }
    meas_add(&total, bench_stop(&t));
    progress("Poly1305 SW    ", c + CHUNK, RUNS, total.us);
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
  progress("Poly1305 HW    ", 0, RUNS, 0);
  for (uint32_t c = 0; c < RUNS; c += CHUNK) {
    bench_start(&t);
    for (uint32_t i = c; i < c + CHUNK; i++) {
      poly1305_hw_mac64(pkey_w, msg, tag);
      MEMORY_BARRIER();
    }
    meas_add(&total, bench_stop(&t));
    progress("Poly1305 HW    ", c + CHUNK, RUNS, total.us);
  }
  neorv32_uart0_printf("\n");
  return total;
}

static meas_t run_both_sw(void) {
  static uint8_t ct[64], tag[16];
  meas_t total = {0, 0};
  bench_timer_t t;
  leds(LED_SW);
  progress("Encrypt+MAC SW ", 0, RUNS, 0);
  for (uint32_t c = 0; c < RUNS; c += CHUNK) {
    bench_start(&t);
    for (uint32_t i = c; i < c + CHUNK; i++) {
      chacha20_sw_encrypt(key8, nonce8, 1 + i, RFC_PT, ct);
      poly1305_mac(pkey8, ct, 64, tag);
      MEMORY_BARRIER();
    }
    meas_add(&total, bench_stop(&t));
    progress("Encrypt+MAC SW ", c + CHUNK, RUNS, total.us);
  }
  neorv32_uart0_printf("\n");
  return total;
}

static meas_t run_both_hw(void) {
  static uint32_t in[16], ct[16], tag[4];
  meas_t total = {0, 0};
  bench_timer_t t;
  memcpy(in, RFC_PT, 64);
  leds(LED_HW);
  progress("Encrypt+MAC HW ", 0, RUNS, 0);
  for (uint32_t c = 0; c < RUNS; c += CHUNK) {
    bench_start(&t);
    if (c == 0) {
      chacha20_hw_set_key(key_w, nonce_w);              /* key + nonce once, counted in the time */
    }
    for (uint32_t i = c; i < c + CHUNK; i++) {
      chacha20_hw_block_fast(1 + i, in, ct);
      poly1305_hw_mac64(pkey_w, ct, tag);
      MEMORY_BARRIER();
    }
    meas_add(&total, bench_stop(&t));
    progress("Encrypt+MAC HW ", c + CHUNK, RUNS, total.us);
  }
  neorv32_uart0_printf("\n");
  return total;
}

/* all 1000 runs: software == hardware (ciphertext and tag, not timed, so the
   compact loop versions of the drivers are used here to keep the program small) */
static int check_all(void) {
  uint8_t  ct_sw[64], tag_sw[16];
  uint32_t in[16], ct_hw[16], tag_hw[4];
  uint32_t bad = 0;
  memcpy(in, RFC_PT, 64);
  for (uint32_t i = 0; i < RUNS; i++) {
    chacha20_sw_encrypt(key8, nonce8, 1 + i, RFC_PT, ct_sw);
    poly1305_mac(pkey8, ct_sw, 64, tag_sw);
    chacha20_hw_block(key_w, nonce_w, 1 + i, in, ct_hw);
    poly1305_hw_mac(pkey_w, ct_hw, 64, tag_hw);
    bad += (memcmp(ct_sw, ct_hw, 64) != 0) || (memcmp(tag_sw, tag_hw, 16) != 0);
    if ((i + 1) % CHUNK == 0) {
      neorv32_uart0_printf("\r  Checking SW == HW: %u/%u runs, %u differences   ", i + 1, (uint32_t)RUNS, bad);
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
    demo_banner("DEMO 2: ChaCha20 + Poly1305 (Encrypt + MAC) - software vs hardware");
    int fails = official_test();
    fails += your_message();

    demo_step("3] Benchmark: 1000 runs each (64-byte messages)");
    neorv32_uart0_printf("  LD1 = software running, LD2 = hardware running\n");
    meas_t psw = run_poly_sw();
    meas_t phw = run_poly_hw();
    meas_t bsw = run_both_sw();
    meas_t bhw = run_both_hw();
    leds(LED_IDLE);
    fails += check_all();

    demo_step("4] Results: time from first input to last output (1 us counter)");
    print_result("Poly1305, software      ", psw, RUNS);
    print_result("Poly1305, hardware      ", phw, RUNS);
    print_result("Encrypt + MAC, software ", bsw, RUNS);
    print_result("Encrypt + MAC, hardware ", bhw, RUNS);
    print_speedup("Poly1305     ", psw, phw);
    print_speedup("Encrypt + MAC", bsw, bhw);
    neorv32_uart0_printf("  Hardware cores alone: Poly1305 90 cycles (64 bytes), ChaCha20 10 cycles;\n");
    neorv32_uart0_printf("  the rest is the CPU moving the data in and out.\n");

    neorv32_uart0_printf(fails ? "\n*** SOME CHECKS FAILED ***\n" : "\nALL CHECKS PASSED\n");
    leds(fails ? LED_FAIL : LED_PASS);
    wait_for_key();
  }
  return 0;
}
