/*
 * keccak_bench.c  -  Phase 6: Keccak (SHA3-256) in RISC-V software
 *
 * 1) Correctness on the RISC-V (digests from scripts/gen_keccak_vectors.py):
 *    - NIST SHA3-256 examples + the pk/ test message "Hello my keccak"
 *    - every message length 0..64 bytes and multi-block lengths (135..300)
 * 2) Time for 1000 hashes (1 us counter + cycle counter) of a 64-byte message
 *    (the size the hardware will handle; one Keccak-f[1600] permutation).
 *
 * Output: UART0 at 19200 baud (Tera Term, COM3). Press any key to run again.
 */
#include <neorv32.h>
#include <string.h>
#include "bench_util.h"
#include "keccak_sw.h"
#include "keccak_vectors.h"

#define BAUD_RATE 19200
#define RUNS      1000

/* ---------------------------------------------------------------------------
 * correctness checks
 * ------------------------------------------------------------------------- */
static int check_vectors(void) {
  uint8_t d[32];
  int fails = 0;

  for (unsigned v = 0; v < KECCAK_NUM_VECTORS; v++) {
    sha3_256(KECCAK_VECTORS[v].msg, KECCAK_VECTORS[v].len, d);
    int ok = (memcmp(d, KECCAK_VECTORS[v].digest, 32) == 0);
    neorv32_uart0_printf("%s  %s (%u bytes)\n", ok ? "PASS" : "FAIL", KECCAK_VECTORS[v].name, KECCAK_VECTORS[v].len);
    fails += !ok;
  }

  uint32_t bad = 0;
  for (unsigned k = 0; k < KECCAK_NUM_LENS; k++) {
    sha3_256(KECCAK_PATTERN, KECCAK_LENS[k], d);
    bad += (memcmp(d, KECCAK_LEN_DIGESTS[k], 32) != 0);
  }
  neorv32_uart0_printf("%s  every length 0..64 bytes + multi-block 135..300 bytes, %u wrong\n",
                       bad ? "FAIL" : "PASS", bad);
  fails += (bad != 0);
  return fails;
}

/* ---------------------------------------------------------------------------
 * timed run: first input to last output
 * ------------------------------------------------------------------------- */
static meas_t bench_sw(const uint8_t *msg, uint32_t len) {
  uint8_t d[32];
  bench_timer_t t;
  bench_start(&t);
  for (uint32_t i = 0; i < RUNS; i++) {
    sha3_256(msg, len, d);
  }
  return bench_stop(&t);
}

int main(void) {
  neorv32_rte_setup();
  neorv32_uart0_setup(BAUD_RATE, 0);

  while (1) {
    neorv32_uart0_printf("\n=== Keccak (SHA3-256) in RISC-V software ===\n");

    /* show one real digest: the pk/ test message */
    uint8_t d[32];
    sha3_256((const uint8_t *)"Hello my keccak", 15, d);
    neorv32_uart0_printf("Message: \"Hello my keccak\"\nSHA3-256: ");
    print_hex(d, 32);
    neorv32_uart0_printf("\n\n");

    int fails = check_vectors();

    neorv32_uart0_printf("\nRunning %u hashes of a 64-byte message...\n", (uint32_t)RUNS);
    meas_t m = bench_sw(KECCAK_PATTERN, 64);

    neorv32_uart0_printf("\nTime from first input to last output (1 us counter):\n");
    neorv32_uart0_printf("SW SHA3-256, 64-byte message  ");
    print_ms(m.us);
    neorv32_uart0_printf("  %u cycles  (%u cycles/hash)\n", m.cycles, m.cycles / RUNS);

    neorv32_uart0_printf(fails ? "\nRESULT CHECK FAILED\n" : "\nALL RESULT CHECKS PASSED\n");
    neorv32_uart0_printf("Press any key to run again.\n");
    neorv32_uart0_getc();
  }
  return 0;
}
