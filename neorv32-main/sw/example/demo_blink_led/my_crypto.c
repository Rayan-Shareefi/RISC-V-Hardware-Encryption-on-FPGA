/*
 * my_crypto.c  -  YOUR OWN TEST: edit the values below, build, upload, check online
 *
 * 1) Edit MY_MESSAGE / MY_KEY / MY_NONCE / MY_COUNTER / MY_POLY_KEY / MY_RUNS below.
 * 2) Build: in a terminal in this folder type   make APP=my_crypto clean exe
 *    -> creates neorv32_exe.bin in this folder.
 * 3) Upload neorv32_exe.bin with Tera Term (bootloader: u, send file as binary, e).
 *
 * What the board does with your message:
 *   [1] ChaCha20 encryption, Poly1305 tag of the ciphertext and Keccak-256 hash, once in
 *       software and once in hardware. Every result is printed in hex on its own line(s),
 *       ready to copy and check online:
 *         ChaCha20:   CyberChef "ChaCha" (key/nonce UTF8, counter = MY_COUNTER, 20 rounds)
 *         Keccak-256: emn178.github.io/online-tools/keccak_256.html
 *   [2] Benchmark: each algorithm MY_RUNS times in software and in hardware.
 *   [3] Summary: time and cycles of every algorithm, software vs hardware, and the total.
 */
#include <neorv32.h>
#include <string.h>
#include "demo_util.h"
#include "crypto_accel.h"
#include "chacha20_sw.h"
#include "poly1305_sw.h"
#include "keccak_sw.h"

/* ============================ EDIT HERE ============================ */
#define MY_MESSAGE   "Hello from our RISC-V crypto accelerator!"   /* 1..64 characters       */
#define MY_KEY       "my 32-byte secret key 4 ChaCha20"            /* exactly 32 characters  */
#define MY_NONCE     "unique nonce"                                 /* exactly 12 characters  */
#define MY_COUNTER   1                                              /* ChaCha20 block counter */
#define MY_POLY_KEY  "one-time Poly1305 key, 32 bytes!"            /* exactly 32 characters  */
#define MY_RUNS      1000                                           /* benchmark runs (10..1000) */
/* =================================================================== */

/* the build stops here with a clear message if a value is wrong */
_Static_assert(sizeof(MY_MESSAGE) - 1 >= 1 && sizeof(MY_MESSAGE) - 1 <= 64, "MY_MESSAGE must be 1..64 characters");
_Static_assert(sizeof(MY_KEY) - 1 == 32, "MY_KEY must be exactly 32 characters");
_Static_assert(sizeof(MY_NONCE) - 1 == 12, "MY_NONCE must be exactly 12 characters");
_Static_assert(sizeof(MY_POLY_KEY) - 1 == 32, "MY_POLY_KEY must be exactly 32 characters");
_Static_assert(MY_RUNS >= 10 && MY_RUNS <= 1000, "MY_RUNS must be 10..1000");

#define MSG_LEN (sizeof(MY_MESSAGE) - 1)
#define CHUNKS  10                         /* progress bar steps */

static uint8_t  key[32], nonce[12], pkey[32], msg[64];
static uint32_t key_w[8], nonce_w[3], pkey_w[8], msg_w[16];
static uint8_t  ct[64], tag[16], dig[32];                 /* software results */
static uint32_t ct_w[16], back_w[16], tag_w[4], dig_w[8];  /* hardware results */

/* ---------------------------------------------------------------------------
 * printing helpers
 * ------------------------------------------------------------------------- */
/* hex in lines of 32 bytes (64 characters), so Tera Term never wraps them */
static void hex_lines(const uint8_t *p, uint32_t n) {
  for (uint32_t i = 0; i < n; i += 32) {
    neorv32_uart0_printf("    ");
    print_hex(p + i, (n - i > 32) ? 32 : (int)(n - i));
    neorv32_uart0_printf("\n");
  }
}

static void result(const char *name, const uint8_t *p, uint32_t n) {
  neorv32_uart0_printf("  %s\n", name);
  hex_lines(p, n);
}

/* unsigned number right-aligned in 'width' characters (NEORV32 printf has no widths) */
static void put_u(uint32_t v, int width) {
  char b[11];
  int n = 0;
  do { b[n++] = (char)('0' + v % 10); v /= 10; } while (v);
  while (width-- > n) neorv32_uart0_putc(' ');
  while (n) neorv32_uart0_putc(b[--n]);
}

/* microseconds as "1234.567 ms", right-aligned to 'width' characters */
static void put_ms(uint32_t us, int width) {
  uint32_t f = us % 1000;
  put_u(us / 1000, width - 7);             /* 7 = ".123 ms" */
  neorv32_uart0_printf(".%c%c%c ms", '0' + f / 100, '0' + (f / 10) % 10, '0' + f % 10);
}

/* speedup = software cycles / hardware cycles, with one decimal (32-bit math is enough:
   the largest software total is about 330,000,000 cycles, x10 < 2^32) */
static void put_speedup(meas_t sw, meas_t hw) {
  uint32_t x10 = (sw.cycles * 10u + hw.cycles / 2) / hw.cycles;
  put_u(x10 / 10, 6);
  neorv32_uart0_printf(".%ux", x10 % 10);
}

/* ---------------------------------------------------------------------------
 * [1] one run of each algorithm, results for online checking
 * ------------------------------------------------------------------------- */
static int run_once(void) {
  int ok = 1;

  neorv32_uart0_printf("\n[1] Results (copy the hex lines to check them online)\n");

  /* ChaCha20 */
  neorv32_uart0_printf("\n  ChaCha20 ciphertext of the message (key, nonce, counter %u)\n", (uint32_t)MY_COUNTER);
  leds(LED_SW);
  chacha20_sw_encrypt(key, nonce, MY_COUNTER, msg, ct);
  leds(LED_HW);
  chacha20_hw_block(key_w, nonce_w, MY_COUNTER, msg_w, ct_w);
  chacha20_hw_block(key_w, nonce_w, MY_COUNTER, ct_w, back_w);       /* decrypt = encrypt again */
  result("Software:", ct, MSG_LEN);
  result("Hardware:", (const uint8_t *)ct_w, MSG_LEN);
  int ch_ok = (memcmp(ct, ct_w, MSG_LEN) == 0) && (memcmp(back_w, msg, MSG_LEN) == 0);
  neorv32_uart0_printf("  Decrypted by hardware: "); print_text((const uint8_t *)back_w, MSG_LEN);
  neorv32_uart0_printf("\n  %s\n", ch_ok ? "PASS: software == hardware, decryption gives the message back" : "FAIL");
  ok &= ch_ok;

  /* Poly1305 over the ciphertext */
  neorv32_uart0_printf("\n  Poly1305 tag of the ciphertext (Encrypt + MAC)\n");
  leds(LED_SW);
  poly1305_mac(pkey, ct, MSG_LEN, tag);
  leds(LED_HW);
  poly1305_hw_mac(pkey_w, ct_w, MSG_LEN, tag_w);
  result("Software:", tag, 16);
  result("Hardware:", (const uint8_t *)tag_w, 16);
  int po_ok = (memcmp(tag, tag_w, 16) == 0);
  neorv32_uart0_printf("  %s\n", po_ok ? "PASS: software == hardware" : "FAIL");
  ok &= po_ok;

  /* Keccak-256 of the message */
  neorv32_uart0_printf("\n  Keccak-256 hash of the message\n");
  leds(LED_SW);
  keccak256(msg, MSG_LEN, dig);
  leds(LED_HW);
  keccak256_hw(msg_w, MSG_LEN, dig_w);
  result("Software:", dig, 32);
  result("Hardware:", (const uint8_t *)dig_w, 32);
  int ke_ok = (memcmp(dig, dig_w, 32) == 0);
  neorv32_uart0_printf("  %s\n", ke_ok ? "PASS: software == hardware" : "FAIL");
  ok &= ke_ok;
  return ok;
}

/* ---------------------------------------------------------------------------
 * [2] benchmark: MY_RUNS runs of each algorithm in software and in hardware.
 *     Timed in CHUNKS parts; the progress bar is printed between the parts
 *     (outside the timed code). Every run reads its input from memory and
 *     writes its result to memory (MEMORY_BARRIER).
 * ------------------------------------------------------------------------- */
typedef enum { CHACHA_SW, CHACHA_HW, POLY_SW, POLY_HW, KECCAK_SW, KECCAK_HW } job_t;

static void one_run(job_t job, uint32_t i) {
  static uint8_t  o8[64];
  static uint32_t o32[16];
  switch (job) {
    case CHACHA_SW: chacha20_sw_encrypt(key, nonce, MY_COUNTER + i, msg, o8); break;
    case CHACHA_HW: chacha20_hw_block_fast(MY_COUNTER + i, msg_w, o32);       break;
    case POLY_SW:   poly1305_mac(pkey, ct, MSG_LEN, o8);                       break;
    case POLY_HW:   poly1305_hw_mac(pkey_w, ct_w, MSG_LEN, o32);               break;
    case KECCAK_SW: keccak256(msg, MSG_LEN, o8);                               break;
    case KECCAK_HW: keccak256_hw(msg_w, MSG_LEN, o32);                         break;
  }
  MEMORY_BARRIER();
}

static meas_t bench(const char *name, job_t job) {
  meas_t total = {0, 0};
  bench_timer_t t;
  int hw = (job == CHACHA_HW || job == POLY_HW || job == KECCAK_HW);
  leds(hw ? LED_HW : LED_SW);
  progress(name, 0, MY_RUNS, 0);
  for (uint32_t c = 0; c < CHUNKS; c++) {
    uint32_t from = MY_RUNS * c / CHUNKS, to = MY_RUNS * (c + 1) / CHUNKS;
    bench_start(&t);
    if (job == CHACHA_HW && c == 0) {
      chacha20_hw_set_key(key_w, nonce_w);              /* key + nonce once, counted in the time */
    }
    for (uint32_t i = from; i < to; i++) {
      one_run(job, i);
    }
    meas_add(&total, bench_stop(&t));
    progress(name, to, MY_RUNS, total.us);
  }
  neorv32_uart0_printf("\n");
  return total;
}

/* ---------------------------------------------------------------------------
 * [3] summary
 * ------------------------------------------------------------------------- */
static void summary_row(const char *name, meas_t sw, meas_t hw) {
  neorv32_uart0_printf("  %s", name);
  put_ms(sw.us, 15);
  put_u(sw.cycles / MY_RUNS, 11);
  put_ms(hw.us, 15);
  put_u(hw.cycles / MY_RUNS, 11);
  put_speedup(sw, hw);
  neorv32_uart0_printf("\n");
}

int main(void) {
  neorv32_rte_setup();
  neorv32_uart0_setup(BAUD_RATE, 0);
  neorv32_gpio_dir_set(0xFF);

  memcpy(key, MY_KEY, 32);       memcpy(key_w, key, 32);
  memcpy(nonce, MY_NONCE, 12);   memcpy(nonce_w, nonce, 12);
  memcpy(pkey, MY_POLY_KEY, 32); memcpy(pkey_w, pkey, 32);
  memset(msg, 0, 64);            memcpy(msg, MY_MESSAGE, MSG_LEN);
  memcpy(msg_w, msg, 64);

  while (1) {
    leds(LED_IDLE);
    demo_banner("MY CRYPTO TEST - your own inputs (edit my_crypto.c)");

    neorv32_uart0_printf("\nInputs\n");
    neorv32_uart0_printf("  Message (%u bytes): ", (uint32_t)MSG_LEN); print_text(msg, MSG_LEN);
    neorv32_uart0_printf("\n");
    hex_lines(msg, MSG_LEN);
    neorv32_uart0_printf("  ChaCha20 key:   "); print_text(key, 32);
    neorv32_uart0_printf("\n");
    hex_lines(key, 32);
    neorv32_uart0_printf("  ChaCha20 nonce: "); print_text(nonce, 12);
    neorv32_uart0_printf("   counter: %u\n", (uint32_t)MY_COUNTER);
    hex_lines(nonce, 12);
    neorv32_uart0_printf("  Poly1305 key:   "); print_text(pkey, 32);
    neorv32_uart0_printf("\n");
    hex_lines(pkey, 32);

    int ok = run_once();

    neorv32_uart0_printf("\n[2] Benchmark: %u runs of each, software (LD1) then hardware (LD2)\n", (uint32_t)MY_RUNS);
    meas_t ch_sw = bench("ChaCha20   SW", CHACHA_SW);
    meas_t ch_hw = bench("ChaCha20   HW", CHACHA_HW);
    meas_t po_sw = bench("Poly1305   SW", POLY_SW);
    meas_t po_hw = bench("Poly1305   HW", POLY_HW);
    meas_t ke_sw = bench("Keccak-256 SW", KECCAK_SW);
    meas_t ke_hw = bench("Keccak-256 HW", KECCAK_HW);
    leds(LED_IDLE);

    meas_t all_sw = ch_sw, all_hw = ch_hw;
    meas_add(&all_sw, po_sw);  meas_add(&all_sw, ke_sw);
    meas_add(&all_hw, po_hw);  meas_add(&all_hw, ke_hw);

    neorv32_uart0_printf("\n[3] SUMMARY - %u runs of each, your %u-byte message, %u MHz CPU\n",
                         (uint32_t)MY_RUNS, (uint32_t)MSG_LEN, neorv32_sysinfo_get_clk() / 1000000);
    neorv32_uart0_printf("    time = hardware 1 us counter, cycles = CPU cycle counter\n\n");
    neorv32_uart0_printf("              ------- Software -------  ------- Hardware -------\n");
    neorv32_uart0_printf("                 total time cycles/run     total time cycles/run  Speedup\n");
    summary_row("ChaCha20  ", ch_sw, ch_hw);
    summary_row("Poly1305  ", po_sw, po_hw);
    summary_row("Keccak-256", ke_sw, ke_hw);
    neorv32_uart0_printf("  -----------------------------------------------------------------------\n");
    summary_row("TOTAL     ", all_sw, all_hw);

    neorv32_uart0_printf(ok ? "\nALL CHECKS PASSED\n" : "\n*** SOME CHECKS FAILED ***\n");
    leds(ok ? LED_PASS : LED_FAIL);
    wait_for_key();
  }
  return 0;
}
