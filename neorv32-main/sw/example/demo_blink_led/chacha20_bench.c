/*
 * chacha20_bench.c  -  Phase 4: ChaCha20 software vs hardware, 1000 runs each
 *
 * Task: run ChaCha20 1000 times in hardware and 1000 times in software, and
 * measure the time from the first input to the last output with the
 * 1 microsecond counter. Cycles are measured too (CPU cycle counter).
 *
 * Input: RFC 8439 2.4.2 key and nonce, the first 64 bytes of its plaintext,
 * block counter 1..1000 (= encrypting a 64,000-byte message block by block).
 *
 * Before timing, the results are checked:
 *   - block 1 must equal the RFC 8439 ciphertext
 *   - all 1000 blocks: software == hardware (both drivers)
 *
 * Output: UART0 at 19200 baud (Tera Term, COM3). Press any key to run again.
 */
#include <neorv32.h>
#include <string.h>
#include "crypto_accel.h"
#include "chacha20_sw.h"

#define BAUD_RATE 19200
#define RUNS      1000

/* RFC 8439 2.4.2 inputs */
static uint8_t key8[32] = {
  0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
  0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
};
static uint8_t nonce8[12] = {0,0,0,0,0,0,0,0x4a,0,0,0,0};
static const uint8_t pt8[64] = "Ladies and Gentlemen of the class of '99: If I could offer you o";

/* expected ciphertext of block 1 (RFC 8439 2.4.2) */
static const uint8_t EXP_BLOCK1[64] = {
  0x6e,0x2e,0x35,0x9a,0x25,0x68,0xf9,0x80,0x41,0xba,0x07,0x28,0xdd,0x0d,0x69,0x81,
  0xe9,0x7e,0x7a,0xec,0x1d,0x43,0x60,0xc2,0x0a,0x27,0xaf,0xcc,0xfd,0x9f,0xae,0x0b,
  0xf9,0x1b,0x65,0xc5,0x52,0x47,0x33,0xab,0x8f,0x59,0x3d,0xab,0xcd,0x62,0xb3,0x57,
  0x16,0x39,0xd6,0x24,0xe6,0x51,0x52,0xab,0x8f,0x53,0x0c,0x35,0x9f,0x08,0x61,0xd8
};

/* the same data as 32-bit words for the hardware driver */
static uint32_t key_w[8], nonce_w[3], pt_w[16];
static uint32_t out_w[16];
static uint8_t  out8[64];

typedef struct {
  uint32_t us;      /* time from the 1 us counter */
  uint32_t cycles;  /* CPU clock cycles */
} meas_t;

/* ---------------------------------------------------------------------------
 * correctness checks (not timed)
 * ------------------------------------------------------------------------- */
static int check_results(void) {
  uint8_t sw[64];
  uint32_t hw1[16], hw2[16];
  int fails = 0;

  /* block 1 against the RFC */
  chacha20_sw_encrypt(key8, nonce8, 1, pt8, sw);
  chacha20_hw_block(key_w, nonce_w, 1, pt_w, hw1);
  int rfc_ok = (memcmp(sw, EXP_BLOCK1, 64) == 0) && (memcmp(hw1, EXP_BLOCK1, 64) == 0);
  neorv32_uart0_printf("%s  block 1 = RFC 8439 2.4.2 ciphertext (SW and HW)\n", rfc_ok ? "PASS" : "FAIL");
  fails += !rfc_ok;

  /* all blocks: software == hardware (simple driver) == hardware (fast driver) */
  uint32_t bad = 0;
  chacha20_hw_set_key(key_w, nonce_w);
  for (uint32_t i = 0; i < RUNS; i++) {
    chacha20_sw_encrypt(key8, nonce8, 1 + i, pt8, sw);
    chacha20_hw_block(key_w, nonce_w, 1 + i, pt_w, hw1);
    chacha20_hw_block_fast(1 + i, pt_w, hw2);
    if (memcmp(sw, hw1, 64) || memcmp(sw, hw2, 64)) {
      bad++;
    }
  }
  neorv32_uart0_printf("%s  %u blocks: software == hardware (both drivers), %u differences\n",
                       bad ? "FAIL" : "PASS", (uint32_t)RUNS, bad);
  fails += (bad != 0);
  return fails;
}

/* ---------------------------------------------------------------------------
 * timed runs: first input to last output
 * ------------------------------------------------------------------------- */
static meas_t bench_sw(void) {
  uint32_t us0 = US_COUNTER;
  uint64_t c0  = neorv32_cpu_get_cycle();
  for (uint32_t i = 0; i < RUNS; i++) {
    chacha20_sw_encrypt(key8, nonce8, 1 + i, pt8, out8);
  }
  uint64_t c1  = neorv32_cpu_get_cycle();
  uint32_t us1 = US_COUNTER;
  return (meas_t){ us1 - us0, (uint32_t)(c1 - c0) };
}

/* hardware, simple driver: key, nonce, counter and data sent every block */
static meas_t bench_hw_simple(void) {
  uint32_t us0 = US_COUNTER;
  uint64_t c0  = neorv32_cpu_get_cycle();
  for (uint32_t i = 0; i < RUNS; i++) {
    chacha20_hw_block(key_w, nonce_w, 1 + i, pt_w, out_w);
  }
  uint64_t c1  = neorv32_cpu_get_cycle();
  uint32_t us1 = US_COUNTER;
  return (meas_t){ us1 - us0, (uint32_t)(c1 - c0) };
}

/* hardware, fast driver: key and nonce sent once, then counter and data per block */
static meas_t bench_hw_fast(void) {
  uint32_t us0 = US_COUNTER;
  uint64_t c0  = neorv32_cpu_get_cycle();
  chacha20_hw_set_key(key_w, nonce_w);
  for (uint32_t i = 0; i < RUNS; i++) {
    chacha20_hw_block_fast(1 + i, pt_w, out_w);
  }
  uint64_t c1  = neorv32_cpu_get_cycle();
  uint32_t us1 = US_COUNTER;
  return (meas_t){ us1 - us0, (uint32_t)(c1 - c0) };
}

/* ---------------------------------------------------------------------------
 * printing helpers (the NEORV32 printf has no width/decimal formatting)
 * ------------------------------------------------------------------------- */
static void print_ms(uint32_t us) {   /* 1234567 us -> "1234.567 ms" */
  uint32_t f = us % 1000;
  neorv32_uart0_printf("%u.%c%c%c ms", us / 1000, '0' + f / 100, '0' + (f / 10) % 10, '0' + f % 10);
}

static void print_row(const char *name, meas_t m) {
  neorv32_uart0_printf("%s  ", name);
  print_ms(m.us);
  neorv32_uart0_printf("  %u cycles  (%u cycles/block, %u KB/s)\n",
                       m.cycles, m.cycles / RUNS, (uint32_t)(64u * RUNS * 1000u / m.us));
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

  memcpy(key_w, key8, 32);
  memcpy(nonce_w, nonce8, 12);
  memcpy(pt_w, pt8, 64);

  while (1) {
    neorv32_uart0_printf("\n=== ChaCha20: software vs hardware, %u blocks x 64 bytes ===\n", (uint32_t)RUNS);
    int fails = check_results();

    neorv32_uart0_printf("\nRunning %u blocks each...\n", (uint32_t)RUNS);
    meas_t sw  = bench_sw();
    meas_t hw1 = bench_hw_simple();
    meas_t hw2 = bench_hw_fast();

    neorv32_uart0_printf("\nTime from first input to last output (1 us counter):\n");
    print_row("SW (project-1 C code)  ", sw);
    print_row("HW (simple driver)     ", hw1);
    print_row("HW (fast driver)       ", hw2);
    neorv32_uart0_printf("\n");
    print_speedup("HW simple vs SW", sw, hw1);
    print_speedup("HW fast   vs SW", sw, hw2);
    neorv32_uart0_printf("HW core alone: 10 cycles/block (the rest is moving data in and out)\n");

    neorv32_uart0_printf(fails ? "\nRESULT CHECK FAILED\n" : "\nALL RESULT CHECKS PASSED\n");
    neorv32_uart0_printf("Press any key to run again.\n");
    neorv32_uart0_getc();
  }
  return 0;
}
