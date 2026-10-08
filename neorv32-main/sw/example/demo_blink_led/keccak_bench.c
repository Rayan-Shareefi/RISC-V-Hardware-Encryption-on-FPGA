/*
 * keccak_bench.c  -  Phases 6 + 8: Keccak (Keccak-256) software vs hardware
 *
 * 1) Correctness (digests from scripts/gen_keccak_vectors.py):
 *    - software: Keccak-256 known values, the pk/ test message "Hello my keccak",
 *      every length 0..64 bytes and multi-block lengths 135..300
 *    - hardware: the same for messages up to 64 bytes
 *    - 100 different 64-byte messages: software == hardware
 * 2) Time for 1000 hashes of a 64-byte message, software and hardware
 *    (1 us counter + cycle counter).
 *
 * Output: UART0 at 19200 baud (Tera Term, COM3). Press any key to run again.
 */
#include <neorv32.h>
#include <string.h>
#include "bench_util.h"
#include "crypto_accel.h"
#include "keccak_sw.h"
#include "keccak_vectors.h"

#define BAUD_RATE   19200
#define RUNS        1000
#define CHECK_RUNS  100     /* software takes 24 ms per hash, so the SW == HW check uses 100 */

/* ---------------------------------------------------------------------------
 * correctness checks
 * ------------------------------------------------------------------------- */
static int check_vectors(void) {
  uint8_t  d[32];
  uint32_t msg[16], dw[8];
  int fails = 0;

  for (unsigned v = 0; v < KECCAK_NUM_VECTORS; v++) {
    keccak256(KECCAK_VECTORS[v].msg, KECCAK_VECTORS[v].len, d);
    int ok = (memcmp(d, KECCAK_VECTORS[v].digest, 32) == 0);
    int hw_ok = 1;
    if (KECCAK_VECTORS[v].len <= 64) {               /* the hardware takes up to 64 bytes */
      memset(msg, 0, 64);
      memcpy(msg, KECCAK_VECTORS[v].msg, KECCAK_VECTORS[v].len);
      keccak256_hw(msg, KECCAK_VECTORS[v].len, dw);
      hw_ok = (memcmp(dw, KECCAK_VECTORS[v].digest, 32) == 0);
    }
    neorv32_uart0_printf("%s  %s (%u bytes)  SW %s, HW %s\n", (ok && hw_ok) ? "PASS" : "FAIL",
                         KECCAK_VECTORS[v].name, KECCAK_VECTORS[v].len, ok ? "ok" : "WRONG",
                         KECCAK_VECTORS[v].len <= 64 ? (hw_ok ? "ok" : "WRONG") : "-");
    fails += !(ok && hw_ok);
  }

  uint32_t bad = 0;
  memcpy(msg, KECCAK_PATTERN, 64);
  for (unsigned k = 0; k < KECCAK_NUM_LENS; k++) {
    keccak256(KECCAK_PATTERN, KECCAK_LENS[k], d);
    bad += (memcmp(d, KECCAK_LEN_DIGESTS[k], 32) != 0);
    if (KECCAK_LENS[k] <= 64) {
      keccak256_hw(msg, KECCAK_LENS[k], dw);
      bad += (memcmp(dw, KECCAK_LEN_DIGESTS[k], 32) != 0);
    }
  }
  neorv32_uart0_printf("%s  every length 0..64 (SW and HW) + multi-block 135..300 (SW), %u wrong\n",
                       bad ? "FAIL" : "PASS", bad);
  fails += (bad != 0);

  /* different messages: software == hardware */
  uint32_t diff = 0;
  for (uint32_t i = 0; i < CHECK_RUNS; i++) {
    memcpy(msg, KECCAK_PATTERN, 64);
    msg[0] ^= i;                                     /* a different message each run */
    keccak256((const uint8_t *)msg, 64, d);
    keccak256_hw64(msg, dw);
    diff += (memcmp(d, dw, 32) != 0);
  }
  neorv32_uart0_printf("%s  %u different messages: software == hardware, %u differences\n",
                       diff ? "FAIL" : "PASS", (uint32_t)CHECK_RUNS, diff);
  fails += (diff != 0);
  return fails;
}

/* ---------------------------------------------------------------------------
 * timed runs: first input to last output
 * ------------------------------------------------------------------------- */
static meas_t bench_sw(void) {
  uint8_t d[32];
  bench_timer_t t;
  bench_start(&t);
  for (uint32_t i = 0; i < RUNS; i++) {
    keccak256(KECCAK_PATTERN, 64, d);
  }
  return bench_stop(&t);
}

static meas_t bench_hw(void) {
  uint32_t msg[16], d[8];
  bench_timer_t t;
  memcpy(msg, KECCAK_PATTERN, 64);
  bench_start(&t);
  for (uint32_t i = 0; i < RUNS; i++) {
    keccak256_hw64(msg, d);
  }
  return bench_stop(&t);
}

static void print_row(const char *name, meas_t m) {
  neorv32_uart0_printf("%s  ", name);
  print_ms(m.us);
  neorv32_uart0_printf("  %u cycles  (%u cycles/hash)\n", m.cycles, m.cycles / RUNS);
}

int main(void) {
  neorv32_rte_setup();
  neorv32_uart0_setup(BAUD_RATE, 0);

  if ((neorv32_cpu_csr_read(CSR_MXISA) & (1 << CSR_MXISA_XCFU)) == 0) {
    neorv32_uart0_printf("ERROR: CFU (custom instructions) not implemented!\n");
    return 1;
  }

  while (1) {
    neorv32_uart0_printf("\n=== Keccak (Keccak-256): software vs hardware, %u hashes ===\n", (uint32_t)RUNS);

    /* show one real digest: the pk/ test message, from software and hardware */
    uint8_t d[32];
    uint32_t msg[16] = {0}, dw[8];
    keccak256((const uint8_t *)"Hello my keccak", 15, d);
    memcpy(msg, "Hello my keccak", 15);
    keccak256_hw(msg, 15, dw);
    neorv32_uart0_printf("Message: \"Hello my keccak\"\nSW: ");
    print_hex(d, 32);
    neorv32_uart0_printf("\nHW: ");
    print_hex((const uint8_t *)dw, 32);
    neorv32_uart0_printf("\n\n");

    int fails = check_vectors();

    neorv32_uart0_printf("\nRunning %u hashes of a 64-byte message (software takes about 11 s)...\n", (uint32_t)RUNS);
    meas_t sw = bench_sw();
    meas_t hw = bench_hw();

    neorv32_uart0_printf("\nTime from first input to last output (1 us counter):\n");
    print_row("Keccak-256, SW  ", sw);
    print_row("Keccak-256, HW  ", hw);
    uint32_t x10 = (uint32_t)(((uint64_t)sw.cycles * 10u + hw.cycles / 2) / hw.cycles);
    neorv32_uart0_printf("\nSpeedup: %u.%ux\n", x10 / 10, x10 % 10);
    neorv32_uart0_printf("HW core alone: 24 cycles/hash (one Keccak round per clock)\n");

    neorv32_uart0_printf(fails ? "\nRESULT CHECK FAILED\n" : "\nALL RESULT CHECKS PASSED\n");
    neorv32_uart0_printf("Press any key to run again.\n");
    neorv32_uart0_getc();
  }
  return 0;
}
