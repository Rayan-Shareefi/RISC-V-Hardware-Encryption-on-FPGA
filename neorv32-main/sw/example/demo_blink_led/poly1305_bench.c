/*
 * poly1305_bench.c  -  Phase 5: Poly1305 in RISC-V software
 *
 * 1) Correctness on the RISC-V:
 *    - all official RFC 8439 test vectors (2.5.2 and A.3 #1..#11)
 *    - every message length 0..64 bytes (tags from tools/gen_poly1305_vectors.py)
 * 2) Time for 1000 MACs (1 us counter + cycle counter), for the 34-byte RFC
 *    message and for a 64-byte message (the size the hardware will handle).
 *
 * Output: UART0 at 19200 baud (Tera Term, COM3). Press any key to run again.
 */
#include <neorv32.h>
#include <string.h>
#include "bench_util.h"
#include "poly1305_sw.h"
#include "poly1305_vectors.h"

#define BAUD_RATE 19200
#define RUNS      1000

/* ---------------------------------------------------------------------------
 * correctness checks
 * ------------------------------------------------------------------------- */
static int check_vectors(void) {
  uint8_t key[32], tag[16];
  int fails = 0;

  for (unsigned v = 0; v < POLY_NUM_VECTORS; v++) {
    memcpy(key, POLY_VECTORS[v].key, 32);
    poly1305_mac(key, POLY_VECTORS[v].msg, POLY_VECTORS[v].len, tag);
    int ok = (memcmp(tag, POLY_VECTORS[v].tag, 16) == 0);
    neorv32_uart0_printf("%s  %s (%u bytes)\n", ok ? "PASS" : "FAIL", POLY_VECTORS[v].name, POLY_VECTORS[v].len);
    fails += !ok;
  }

  uint32_t bad = 0;
  memcpy(key, POLY_VECTORS[0].key, 32);
  for (uint32_t n = 0; n <= 64; n++) {
    poly1305_mac(key, SWEEP_MSG, n, tag);
    bad += (memcmp(tag, SWEEP_TAGS[n], 16) != 0);
  }
  neorv32_uart0_printf("%s  every message length 0..64 bytes, %u wrong\n", bad ? "FAIL" : "PASS", bad);
  fails += (bad != 0);
  return fails;
}

/* ---------------------------------------------------------------------------
 * timed runs: first input to last output
 * ------------------------------------------------------------------------- */
static meas_t bench_sw(const uint8_t *msg, uint32_t len) {
  uint8_t key[32], tag[16];
  bench_timer_t t;
  memcpy(key, POLY_VECTORS[0].key, 32);
  bench_start(&t);
  for (uint32_t i = 0; i < RUNS; i++) {
    poly1305_mac(key, msg, len, tag);
  }
  return bench_stop(&t);
}

static void print_row(const char *name, uint32_t len, meas_t m) {
  neorv32_uart0_printf("%s  ", name);
  print_ms(m.us);
  neorv32_uart0_printf("  %u cycles  (%u cycles/MAC, %u cycles/byte)\n",
                       m.cycles, m.cycles / RUNS, m.cycles / (RUNS * len));
}

int main(void) {
  neorv32_rte_setup();
  neorv32_uart0_setup(BAUD_RATE, 0);

  while (1) {
    neorv32_uart0_printf("\n=== Poly1305 in RISC-V software ===\n");

    /* show one real tag: the RFC 8439 2.5.2 example */
    uint8_t key[32], tag[16];
    memcpy(key, POLY_VECTORS[0].key, 32);
    poly1305_mac(key, POLY_VECTORS[0].msg, POLY_VECTORS[0].len, tag);
    neorv32_uart0_printf("Message: \"Cryptographic Forum Research Group\"\nTag:     ");
    print_hex(tag, 16);
    neorv32_uart0_printf("\n\n");

    int fails = check_vectors();

    neorv32_uart0_printf("\nRunning %u MACs each...\n", (uint32_t)RUNS);
    meas_t m34 = bench_sw(POLY_VECTORS[0].msg, POLY_VECTORS[0].len);
    meas_t m64 = bench_sw(SWEEP_MSG, 64);

    neorv32_uart0_printf("\nTime from first input to last output (1 us counter):\n");
    print_row("SW Poly1305, 34-byte message", 34, m34);
    print_row("SW Poly1305, 64-byte message", 64, m64);

    neorv32_uart0_printf(fails ? "\nRESULT CHECK FAILED\n" : "\nALL RESULT CHECKS PASSED\n");
    neorv32_uart0_printf("Press any key to run again.\n");
    neorv32_uart0_getc();
  }
  return 0;
}
