/*
 * demo_chacha20.c  -  DEMO 1: ChaCha20 encryption, software vs hardware
 *
 *  [1] Official test   RFC 8439 2.4.2 block 1 in software and hardware vs the RFC value
 *  [2] Your message    type a message: encrypted in SW and HW, then decrypted again
 *  [3] Benchmark       1000 blocks (64,000 bytes) in SW and in HW, live progress,
 *                      (HW: key + nonce loaded once, then counter + data per block),
 *                      then all 1000 blocks checked: SW == HW
 *  [4] Results         time (1 us counter), cycles, speedup
 *
 * LEDs: LD1 = software running, LD2 = hardware running, RGB green/red = result.
 * Output: UART0 19200 baud (Tera Term, COM3). Build: make APP=demo_chacha20 clean exe
 */
#include <neorv32.h>
#include <string.h>
#include "demo_util.h"
#include "crypto_accel.h"
#include "chacha20_sw.h"

#define RUNS    1000
#define CHUNK   100

/* RFC 8439 2.4.2 inputs and the expected ciphertext of block 1 */
static uint8_t key8[32] = {
  0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
  0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
};
static uint8_t nonce8[12] = {0,0,0,0,0,0,0,0x4a,0,0,0,0};
static const uint8_t RFC_PT[64] = "Ladies and Gentlemen of the class of '99: If I could offer you o";
static const uint8_t RFC_CT[64] = {
  0x6e,0x2e,0x35,0x9a,0x25,0x68,0xf9,0x80,0x41,0xba,0x07,0x28,0xdd,0x0d,0x69,0x81,
  0xe9,0x7e,0x7a,0xec,0x1d,0x43,0x60,0xc2,0x0a,0x27,0xaf,0xcc,0xfd,0x9f,0xae,0x0b,
  0xf9,0x1b,0x65,0xc5,0x52,0x47,0x33,0xab,0x8f,0x59,0x3d,0xab,0xcd,0x62,0xb3,0x57,
  0x16,0x39,0xd6,0x24,0xe6,0x51,0x52,0xab,0x8f,0x53,0x0c,0x35,0x9f,0x08,0x61,0xd8
};
static const char DEFAULT_MSG[] = "Hello professor, this is ChaCha20 running on our RISC-V!";

static uint32_t key_w[8], nonce_w[3];

/* ---------------------------------------------------------------------------
 * [1] official test
 * ------------------------------------------------------------------------- */
static int official_test(void) {
  uint8_t  sw[64];
  uint32_t pt_w[16], hw[16];
  memcpy(pt_w, RFC_PT, 64);

  uint32_t c0 = neorv32_cpu_csr_read(CSR_MCYCLE);
  chacha20_sw_encrypt(key8, nonce8, 1, RFC_PT, sw);
  uint32_t c1 = neorv32_cpu_csr_read(CSR_MCYCLE);
  chacha20_hw_block(key_w, nonce_w, 1, pt_w, hw);
  uint32_t c2 = neorv32_cpu_csr_read(CSR_MCYCLE);

  int sw_ok = (memcmp(sw, RFC_CT, 64) == 0);
  int hw_ok = (memcmp(hw, RFC_CT, 64) == 0);

  demo_step("1] Official test: RFC 8439 section 2.4.2, block 1");
  neorv32_uart0_printf("  Key:        "); print_hex(key8, 32);
  neorv32_uart0_printf("\n  Nonce:      "); print_hex(nonce8, 12);
  neorv32_uart0_printf("   Counter: 1\n  Plaintext:  "); print_text(RFC_PT, 64);
  neorv32_uart0_printf("\n  Expected:   "); print_hex(RFC_CT, 32);
  neorv32_uart0_printf("...  (first 32 of 64 bytes)\n  Software:   "); print_hex(sw, 32);
  neorv32_uart0_printf("...  %s  (%u cycles)\n  Hardware:   ", pass_fail(sw_ok), c1 - c0);
  print_hex((const uint8_t *)hw, 32);
  neorv32_uart0_printf("...  %s  (%u cycles)\n", pass_fail(hw_ok), c2 - c1);
  return !(sw_ok && hw_ok);
}

/* ---------------------------------------------------------------------------
 * [2] your message: encrypt in SW and HW, decrypt in HW
 * ------------------------------------------------------------------------- */
static int your_message(void) {
  char     text[65];
  uint8_t  pt[64] = {0}, sw[64];
  uint32_t pt_w[16], hw[16], back[16];

  demo_step("2] Your message");
  neorv32_uart0_printf("  Type a message (up to 64 characters) and press Enter,\n");
  neorv32_uart0_printf("  or wait %u s for the default message:\n", (uint32_t)INPUT_TIMEOUT);
  uint32_t n = read_line(text, 64);
  if (n == 0) {
    n = strlen(DEFAULT_MSG);
    memcpy(text, DEFAULT_MSG, n + 1);
  }
  memcpy(pt, text, n);
  memcpy(pt_w, pt, 64);

  chacha20_sw_encrypt(key8, nonce8, 1, pt, sw);
  uint32_t c0 = neorv32_cpu_csr_read(CSR_MCYCLE);
  chacha20_hw_block(key_w, nonce_w, 1, pt_w, hw);
  uint32_t c1 = neorv32_cpu_csr_read(CSR_MCYCLE);
  chacha20_hw_block(key_w, nonce_w, 1, hw, back);       /* ChaCha20 again = decryption */

  int same = (memcmp(sw, hw, n) == 0);
  int back_ok = (memcmp(back, pt, n) == 0);

  neorv32_uart0_printf("  Plaintext:        "); print_text(pt, n);
  neorv32_uart0_printf("  (%u bytes)\n  Ciphertext (SW):  ", n); print_hex(sw, n);
  neorv32_uart0_printf("\n  Ciphertext (HW):  "); print_hex((const uint8_t *)hw, n);
  neorv32_uart0_printf("\n  Ciphertext as text (unreadable = encrypted): "); print_text((const uint8_t *)hw, n);
  neorv32_uart0_printf("\n  Software == hardware: %s   (hardware took %u cycles)\n", same ? "YES" : "NO", c1 - c0);
  neorv32_uart0_printf("  Decrypted by HW:  "); print_text((const uint8_t *)back, n);
  neorv32_uart0_printf("  %s\n", back_ok ? "= original message" : "WRONG");
  return !(same && back_ok);
}

/* ---------------------------------------------------------------------------
 * [3] benchmark: 1000 blocks, timed in chunks of 100 (progress is printed
 *     between chunks, outside the timed part)
 * ------------------------------------------------------------------------- */
static meas_t run_sw(void) {
  static uint8_t out[64];
  meas_t total = {0, 0};
  bench_timer_t t;
  leds(LED_SW);
  progress("SW", 0, RUNS, 0);
  for (uint32_t c = 0; c < RUNS; c += CHUNK) {
    bench_start(&t);
    for (uint32_t i = c; i < c + CHUNK; i++) {
      chacha20_sw_encrypt(key8, nonce8, 1 + i, RFC_PT, out);
      MEMORY_BARRIER();
    }
    meas_add(&total, bench_stop(&t));
    progress("SW", c + CHUNK, RUNS, total.us);
  }
  neorv32_uart0_printf("\n");
  return total;
}

static meas_t run_hw(void) {
  static uint32_t in[16], out[16];
  meas_t total = {0, 0};
  bench_timer_t t;
  memcpy(in, RFC_PT, 64);
  leds(LED_HW);
  progress("HW", 0, RUNS, 0);
  for (uint32_t c = 0; c < RUNS; c += CHUNK) {
    bench_start(&t);
    if (c == 0) {
      chacha20_hw_set_key(key_w, nonce_w);              /* key + nonce once, counted in the time */
    }
    for (uint32_t i = c; i < c + CHUNK; i++) {
      chacha20_hw_block_fast(1 + i, in, out);
      MEMORY_BARRIER();
    }
    meas_add(&total, bench_stop(&t));
    progress("HW", c + CHUNK, RUNS, total.us);
  }
  neorv32_uart0_printf("\n");
  return total;
}

/* all 1000 blocks: software == hardware (not timed) */
static int check_all(void) {
  uint8_t  sw[64];
  uint32_t in[16], hw[16];
  uint32_t bad = 0;
  memcpy(in, RFC_PT, 64);
  chacha20_hw_set_key(key_w, nonce_w);
  for (uint32_t i = 0; i < RUNS; i++) {
    chacha20_sw_encrypt(key8, nonce8, 1 + i, RFC_PT, sw);
    chacha20_hw_block_fast(1 + i, in, hw);
    bad += (memcmp(sw, hw, 64) != 0);
    if ((i + 1) % CHUNK == 0) {
      neorv32_uart0_printf("\r  Checking SW == HW: %u/%u blocks, %u differences   ", i + 1, (uint32_t)RUNS, bad);
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

  while (1) {
    leds(LED_IDLE);
    demo_banner("DEMO 1: ChaCha20 encryption - software vs hardware");
    int fails = official_test();
    fails += your_message();

    demo_step("3] Benchmark: encrypt 1000 blocks of 64 bytes (64,000 bytes)");
    neorv32_uart0_printf("  LD1 = software running, LD2 = hardware running\n");
    meas_t sw = run_sw();
    meas_t hw = run_hw();
    leds(LED_IDLE);
    fails += check_all();

    demo_step("4] Results: time from first input to last output (1 us counter)");
    print_result("Software ", sw, RUNS);
    print_result("Hardware ", hw, RUNS);
    print_speedup("ChaCha20", sw, hw);
    neorv32_uart0_printf("  The ChaCha20 hardware core itself needs 10 cycles per block;\n");
    neorv32_uart0_printf("  the rest is the CPU moving 64 bytes in and 64 bytes out.\n");

    neorv32_uart0_printf(fails ? "\n*** SOME CHECKS FAILED ***\n" : "\nALL CHECKS PASSED\n");
    leds(fails ? LED_FAIL : LED_PASS);
    wait_for_key();
  }
  return 0;
}
