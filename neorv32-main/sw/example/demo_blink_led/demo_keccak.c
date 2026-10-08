/*
 * demo_keccak.c  -  DEMO 3: Keccak-256 hashing, software vs hardware
 *
 *  [1] Official test   Keccak-256 known values ("test" and the empty message)
 *                      in SW and HW vs the published values
 *  [2] Your message    type a message: hashed in SW and HW; then one letter is
 *                      changed and the hash changes completely (about half of
 *                      the 256 bits flip = "avalanche effect")
 *  [3] Benchmark       1000 hashes of 64-byte messages in SW and HW, live
 *                      progress, then 1000 different messages checked: SW == HW
 *  [4] Results         time (1 us counter), cycles, speedup
 */
#include <neorv32.h>
#include <string.h>
#include "demo_util.h"
#include "crypto_accel.h"
#include "keccak_sw.h"

#define RUNS    1000
#define CHUNK   100

/* Keccak-256 known values (the same as "Keccak-256" online tools, e.g. emn178 keccak_256) */
static const uint8_t KECCAK_TEST[32] = {
  0x9c,0x22,0xff,0x5f,0x21,0xf0,0xb8,0x1b,0x11,0x3e,0x63,0xf7,0xdb,0x6d,0xa9,0x4f,
  0xed,0xef,0x11,0xb2,0x11,0x9b,0x40,0x88,0xb8,0x96,0x64,0xfb,0x9a,0x3c,0xb6,0x58
};
static const uint8_t KECCAK_EMPTY[32] = {
  0xc5,0xd2,0x46,0x01,0x86,0xf7,0x23,0x3c,0x92,0x7e,0x7d,0xb2,0xdc,0xc7,0x03,0xc0,
  0xe5,0x00,0xb6,0x53,0xca,0x82,0x27,0x3b,0x7b,0xfa,0xd8,0x04,0x5d,0x85,0xa4,0x70
};
static const uint8_t BENCH_MSG[64] = "Keccak-256 benchmark message, 64 bytes of data for the Keccak";
static const char DEFAULT_MSG[] = "Hello my keccak";

/* ---------------------------------------------------------------------------
 * [1] official test
 * ------------------------------------------------------------------------- */
static int one_official(const char *name, const uint8_t *msg, uint32_t len, const uint8_t *expected) {
  uint8_t  sw[32];
  uint32_t msg_w[16] = {0}, hw[8];
  memcpy(msg_w, msg, len);

  uint32_t c0 = neorv32_cpu_csr_read(CSR_MCYCLE);
  keccak256(msg, len, sw);
  uint32_t c1 = neorv32_cpu_csr_read(CSR_MCYCLE);
  keccak256_hw(msg_w, len, hw);
  uint32_t c2 = neorv32_cpu_csr_read(CSR_MCYCLE);

  int sw_ok = (memcmp(sw, expected, 32) == 0);
  int hw_ok = (memcmp(hw, expected, 32) == 0);
  neorv32_uart0_printf("  Message:   %s\n  Expected:  ", name); print_hex(expected, 32);
  neorv32_uart0_printf("\n  Software:  "); print_hex(sw, 32);
  neorv32_uart0_printf("  %s  (%u cycles)\n  Hardware:  ", pass_fail(sw_ok), c1 - c0);
  print_hex((const uint8_t *)hw, 32);
  neorv32_uart0_printf("  %s  (%u cycles)\n", pass_fail(hw_ok), c2 - c1);
  return !(sw_ok && hw_ok);
}

static int official_test(void) {
  demo_step("1] Official test: Keccak-256 known values");
  int fails = one_official("\"test\"", (const uint8_t *)"test", 4, KECCAK_TEST);
  fails += one_official("\"\" (empty message)", (const uint8_t *)"", 0, KECCAK_EMPTY);
  return fails;
}

/* ---------------------------------------------------------------------------
 * [2] your message: hash, then change one letter (avalanche effect)
 * ------------------------------------------------------------------------- */
static uint32_t bits_different(const uint8_t *a, const uint8_t *b, uint32_t n) {
  uint32_t count = 0;
  for (uint32_t i = 0; i < n; i++) {
    uint8_t x = a[i] ^ b[i];
    while (x) {
      count += x & 1;
      x >>= 1;
    }
  }
  return count;
}

static int your_message(void) {
  char     text[65];
  uint8_t  msg[64] = {0}, sw[32];
  uint32_t msg_w[16], hw[8], hw2[8];

  demo_step("2] Your message");
  neorv32_uart0_printf("  Type a message (up to 64 characters) and press Enter,\n");
  neorv32_uart0_printf("  or wait %u s for the default message:\n", (uint32_t)INPUT_TIMEOUT);
  uint32_t n = read_line(text, 64);
  if (n == 0) {
    n = strlen(DEFAULT_MSG);
    memcpy(text, DEFAULT_MSG, n + 1);
  }
  memcpy(msg, text, n);
  memcpy(msg_w, msg, 64);

  uint32_t c0 = neorv32_cpu_csr_read(CSR_MCYCLE);
  keccak256(msg, n, sw);
  uint32_t c1 = neorv32_cpu_csr_read(CSR_MCYCLE);
  keccak256_hw(msg_w, n, hw);
  uint32_t c2 = neorv32_cpu_csr_read(CSR_MCYCLE);
  int same = (memcmp(sw, hw, 32) == 0);

  neorv32_uart0_printf("  Message:        "); print_text(msg, n);
  neorv32_uart0_printf("  (%u bytes)\n  Keccak-256 (SW):  ", n); print_hex(sw, 32);
  neorv32_uart0_printf("   %u cycles\n  Keccak-256 (HW):  ", c1 - c0); print_hex((const uint8_t *)hw, 32);
  neorv32_uart0_printf("   %u cycles\n  Software == hardware: %s\n", c2 - c1, same ? "YES" : "NO");

  /* change one letter: flip the lowest bit of the last character */
  uint8_t changed[64];
  memcpy(changed, msg, 64);
  if (n == 0) n = 1;
  changed[n - 1] ^= 0x01;
  memcpy(msg_w, changed, 64);
  keccak256_hw(msg_w, n, hw2);
  uint32_t diff = bits_different((const uint8_t *)hw, (const uint8_t *)hw2, 32);

  neorv32_uart0_printf("\n  Changed 1 bit:  "); print_text(changed, n);
  neorv32_uart0_printf("\n  Keccak-256 (HW):  "); print_hex((const uint8_t *)hw2, 32);
  neorv32_uart0_printf("\n  %u of 256 hash bits changed (about half = good hash)\n", diff);
  return !same;
}

/* ---------------------------------------------------------------------------
 * [3] benchmark (progress printed between chunks, outside the timed part)
 * ------------------------------------------------------------------------- */
static meas_t run_sw(void) {
  static uint8_t d[32];
  meas_t total = {0, 0};
  bench_timer_t t;
  leds(LED_SW);
  progress("SW", 0, RUNS, 0);
  for (uint32_t c = 0; c < RUNS; c += CHUNK) {
    bench_start(&t);
    for (uint32_t i = c; i < c + CHUNK; i++) {
      keccak256(BENCH_MSG, 64, d);
      MEMORY_BARRIER();
    }
    meas_add(&total, bench_stop(&t));
    progress("SW", c + CHUNK, RUNS, total.us);
  }
  neorv32_uart0_printf("\n");
  return total;
}

static meas_t run_hw(void) {
  static uint32_t msg[16], d[8];
  meas_t total = {0, 0};
  bench_timer_t t;
  memcpy(msg, BENCH_MSG, 64);
  leds(LED_HW);
  progress("HW", 0, RUNS, 0);
  for (uint32_t c = 0; c < RUNS; c += CHUNK) {
    bench_start(&t);
    for (uint32_t i = c; i < c + CHUNK; i++) {
      keccak256_hw64(msg, d);
      MEMORY_BARRIER();
    }
    meas_add(&total, bench_stop(&t));
    progress("HW", c + CHUNK, RUNS, total.us);
  }
  neorv32_uart0_printf("\n");
  return total;
}

/* 1000 different messages: software == hardware (not timed) */
static int check_all(void) {
  uint8_t  sw[32];
  uint32_t msg[16], hw[8];
  uint32_t bad = 0;
  for (uint32_t i = 0; i < RUNS; i++) {
    memcpy(msg, BENCH_MSG, 64);
    msg[15] ^= i;                                         /* a different message every time */
    keccak256((const uint8_t *)msg, 64, sw);
    keccak256_hw64(msg, hw);
    bad += (memcmp(sw, hw, 32) != 0);
    if ((i + 1) % 50 == 0) {
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

  while (1) {
    leds(LED_IDLE);
    demo_banner("DEMO 3: Keccak-256 hashing - software vs hardware");
    int fails = official_test();
    fails += your_message();

    demo_step("3] Benchmark: 1000 hashes of a 64-byte message");
    neorv32_uart0_printf("  LD1 = software running, LD2 = hardware running\n");
    neorv32_uart0_printf("  (software needs about 11 s - this CPU has no fast shifter for 64-bit rotations)\n");
    meas_t sw = run_sw();
    meas_t hw = run_hw();
    leds(LED_SW | LED_HW);
    neorv32_uart0_printf("  (checking 1000 different messages also needs about 11 s of software)\n");
    fails += check_all();
    leds(LED_IDLE);

    demo_step("4] Results: time from first input to last output (1 us counter)");
    print_result("Software ", sw, RUNS);
    print_result("Hardware ", hw, RUNS);
    print_speedup("Keccak-256", sw, hw);
    neorv32_uart0_printf("  The Keccak hardware core needs 24 cycles per hash (one round per clock);\n");
    neorv32_uart0_printf("  the rest is the CPU moving 64 bytes in and 32 bytes out.\n");

    neorv32_uart0_printf(fails ? "\n*** SOME CHECKS FAILED ***\n" : "\nALL CHECKS PASSED\n");
    leds(fails ? LED_FAIL : LED_PASS);
    wait_for_key();
  }
  return 0;
}
