/*
 * chacha20_poly1305_bench.c  -  Phase 7: ChaCha20 + Poly1305, software vs hardware
 *
 * One run of "Encrypt + MAC" = ChaCha20 encrypts a 64-byte block (counter = run
 * number), then Poly1305 makes a 16-byte tag of that ciphertext.
 *
 * Before timing, the results are checked:
 *   - block 1 ciphertext = RFC 8439 2.4.2, its tag (SW) = tag (HW)
 *   - all 1000 runs: software (ciphertext + tag) == hardware (ciphertext + tag)
 * Then 1000 runs each are timed (1 us counter + cycle counter):
 *   - Poly1305 alone (64-byte message)
 *   - Encrypt + MAC
 *
 * Inputs: ChaCha20 key/nonce/plaintext from RFC 8439 2.4.2, Poly1305 key
 * from RFC 8439 2.5.2. Output: UART0 at 19200 baud (Tera Term, COM3).
 * Press any key to run again.
 */
#include <neorv32.h>
#include <string.h>
#include "bench_util.h"
#include "crypto_accel.h"
#include "chacha20_sw.h"
#include "poly1305_sw.h"
#include "poly1305_vectors.h"

#define BAUD_RATE 19200
#define RUNS      1000

/* ChaCha20 inputs: RFC 8439 2.4.2 */
static uint8_t key8[32] = {
  0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
  0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
};
static uint8_t nonce8[12] = {0,0,0,0,0,0,0,0x4a,0,0,0,0};
static const uint8_t pt8[64] = "Ladies and Gentlemen of the class of '99: If I could offer you o";
static const uint8_t EXP_BLOCK1[64] = {
  0x6e,0x2e,0x35,0x9a,0x25,0x68,0xf9,0x80,0x41,0xba,0x07,0x28,0xdd,0x0d,0x69,0x81,
  0xe9,0x7e,0x7a,0xec,0x1d,0x43,0x60,0xc2,0x0a,0x27,0xaf,0xcc,0xfd,0x9f,0xae,0x0b,
  0xf9,0x1b,0x65,0xc5,0x52,0x47,0x33,0xab,0x8f,0x59,0x3d,0xab,0xcd,0x62,0xb3,0x57,
  0x16,0x39,0xd6,0x24,0xe6,0x51,0x52,0xab,0x8f,0x53,0x0c,0x35,0x9f,0x08,0x61,0xd8
};

/* Poly1305 key: RFC 8439 2.5.2 */
static uint8_t pkey8[32];

/* the same data as 32-bit words for the hardware driver */
static uint32_t key_w[8], nonce_w[3], pt_w[16], pkey_w[8];

/* outputs */
static uint8_t  ct8[64], tag8[16];
static uint32_t ct_w[16], tag_w[4];

/* ---------------------------------------------------------------------------
 * one run in software and in hardware
 * ------------------------------------------------------------------------- */
static void encrypt_mac_sw(uint32_t counter) {
  chacha20_sw_encrypt(key8, nonce8, counter, pt8, ct8);
  poly1305_mac(pkey8, ct8, 64, tag8);
}

static void encrypt_mac_hw(uint32_t counter) {      /* needs chacha20_hw_set_key() first */
  chacha20_hw_block_fast(counter, pt_w, ct_w);
  poly1305_hw_mac64(pkey_w, ct_w, tag_w);
}

/* ---------------------------------------------------------------------------
 * correctness checks (not timed)
 * ------------------------------------------------------------------------- */
static int check_results(void) {
  int fails = 0;

  chacha20_hw_set_key(key_w, nonce_w);
  encrypt_mac_sw(1);
  encrypt_mac_hw(1);
  int ok1 = (memcmp(ct8, EXP_BLOCK1, 64) == 0) && (memcmp(ct_w, EXP_BLOCK1, 64) == 0) &&
            (memcmp(tag8, tag_w, 16) == 0);
  neorv32_uart0_printf("%s  run 1: ciphertext = RFC 8439 2.4.2 (SW and HW), tag SW = HW\n", ok1 ? "PASS" : "FAIL");
  neorv32_uart0_printf("      tag of run 1: ");
  print_hex(tag8, 16);
  neorv32_uart0_printf("\n");
  fails += !ok1;

  uint32_t bad = 0;
  for (uint32_t i = 0; i < RUNS; i++) {
    encrypt_mac_sw(1 + i);
    encrypt_mac_hw(1 + i);
    if (memcmp(ct8, ct_w, 64) || memcmp(tag8, tag_w, 16)) {
      bad++;
    }
  }
  neorv32_uart0_printf("%s  %u runs: software == hardware (ciphertext and tag), %u differences\n",
                       bad ? "FAIL" : "PASS", (uint32_t)RUNS, bad);
  fails += (bad != 0);
  return fails;
}

/* ---------------------------------------------------------------------------
 * timed runs: first input to last output
 * ------------------------------------------------------------------------- */
static meas_t bench_poly_sw(void) {
  bench_timer_t t;
  bench_start(&t);
  for (uint32_t i = 0; i < RUNS; i++) {
    poly1305_mac(pkey8, EXP_BLOCK1, 64, tag8);
  }
  return bench_stop(&t);
}

static meas_t bench_poly_hw(void) {
  bench_timer_t t;
  memcpy(ct_w, EXP_BLOCK1, 64);
  bench_start(&t);
  for (uint32_t i = 0; i < RUNS; i++) {
    poly1305_hw_mac64(pkey_w, ct_w, tag_w);
  }
  return bench_stop(&t);
}

static meas_t bench_both_sw(void) {
  bench_timer_t t;
  bench_start(&t);
  for (uint32_t i = 0; i < RUNS; i++) {
    encrypt_mac_sw(1 + i);
  }
  return bench_stop(&t);
}

static meas_t bench_both_hw(void) {
  bench_timer_t t;
  bench_start(&t);
  chacha20_hw_set_key(key_w, nonce_w);
  for (uint32_t i = 0; i < RUNS; i++) {
    encrypt_mac_hw(1 + i);
  }
  return bench_stop(&t);
}

/* ---------------------------------------------------------------------------
 * printing
 * ------------------------------------------------------------------------- */
static void print_row(const char *name, meas_t m) {
  neorv32_uart0_printf("%s  ", name);
  print_ms(m.us);
  neorv32_uart0_printf("  %u cycles  (%u cycles/run)\n", m.cycles, m.cycles / RUNS);
}

static void print_speedup(const char *name, meas_t sw, meas_t hw) {
  uint32_t x10 = (sw.cycles * 10u + hw.cycles / 2) / hw.cycles;   /* speedup x 10, rounded */
  neorv32_uart0_printf("Speedup %s: %u.%ux\n", name, x10 / 10, x10 % 10);
}

int main(void) {
  neorv32_rte_setup();
  neorv32_uart0_setup(BAUD_RATE, 0);

  if ((neorv32_cpu_csr_read(CSR_MXISA) & (1 << CSR_MXISA_XCFU)) == 0) {
    neorv32_uart0_printf("ERROR: CFU (custom instructions) not implemented!\n");
    return 1;
  }

  memcpy(pkey8, POLY_VECTORS[0].key, 32);
  memcpy(key_w, key8, 32);
  memcpy(nonce_w, nonce8, 12);
  memcpy(pt_w, pt8, 64);
  memcpy(pkey_w, pkey8, 32);

  while (1) {
    neorv32_uart0_printf("\n=== ChaCha20 + Poly1305: software vs hardware, %u runs ===\n", (uint32_t)RUNS);
    neorv32_uart0_printf("One run = encrypt a 64-byte block, then Poly1305 tag of the ciphertext\n");
    int fails = check_results();

    neorv32_uart0_printf("\nRunning %u runs each...\n", (uint32_t)RUNS);
    meas_t psw = bench_poly_sw();
    meas_t phw = bench_poly_hw();
    meas_t bsw = bench_both_sw();
    meas_t bhw = bench_both_hw();

    neorv32_uart0_printf("\nTime from first input to last output (1 us counter):\n");
    print_row("Poly1305 only, SW   ", psw);
    print_row("Poly1305 only, HW   ", phw);
    print_row("Encrypt + MAC, SW   ", bsw);
    print_row("Encrypt + MAC, HW   ", bhw);
    neorv32_uart0_printf("\n");
    print_speedup("Poly1305 only", psw, phw);
    print_speedup("Encrypt + MAC", bsw, bhw);
    neorv32_uart0_printf("HW cores alone: ChaCha20 10 cycles, Poly1305 (64 bytes) 90 cycles\n");

    neorv32_uart0_printf(fails ? "\nRESULT CHECK FAILED\n" : "\nALL RESULT CHECKS PASSED\n");
    neorv32_uart0_printf("Press any key to run again.\n");
    neorv32_uart0_getc();
  }
  return 0;
}
