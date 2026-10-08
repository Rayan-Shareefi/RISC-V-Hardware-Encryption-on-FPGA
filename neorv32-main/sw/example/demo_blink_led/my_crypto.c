/*
 * my_crypto.c  -  YOUR OWN TEST: edit the values below, build, upload, check online
 *
 * 1) Edit MY_MESSAGE / MY_AAD / MY_KEY / MY_NONCE / MY_RUNS below.
 * 2) Build: in a terminal in this folder type   make APP=my_crypto clean exe
 *    -> creates neorv32_exe.bin in this folder.
 * 3) Upload neorv32_exe.bin with Tera Term (bootloader: u, send file as binary, e).
 *
 * What the board does with your message:
 *   [1] ChaCha20-Poly1305 (RFC 8439): encrypts the message and makes the 16-byte tag
 *       (Poly1305 key = ChaCha20 block 0, encryption = blocks 1, 2, ...), then the
 *       receiver checks the tag and decrypts. Also the Keccak-256 hash of the message.
 *       Everything once in software and once in hardware; every result is printed in
 *       hex on its own line(s), ready to copy and check online:
 *         ChaCha20 (ciphertext):  CyberChef "ChaCha" (key/nonce UTF8, counter 1, 20 rounds)
 *         Poly1305 (tag):         javainuse.com/poly1305mac (one-time key + MAC input, hex)
 *         Keccak-256:             CyberChef "Keccak" (size 256)
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
#include "chacha20_poly1305.h"

/* ============================ EDIT HERE ============================ */
#define MY_MESSAGE   "test"   /* 1..256 characters      */
#define MY_AAD       "AAD key"                                /* 0..64 characters, sent in clear but protected by the tag */
#define MY_KEY       "my 32-byte secret key 4 ChaCha20"            /* exactly 32 characters  */
#define MY_NONCE     "unique nonce"                                 /* exactly 12 characters  */
#define MY_RUNS      1000                                           /* benchmark runs (10..1000) */
/* =================================================================== */

/* the build stops here with a clear message if a value is wrong */
_Static_assert(sizeof(MY_MESSAGE) - 1 >= 1 && sizeof(MY_MESSAGE) - 1 <= AEAD_MAX_MSG, "MY_MESSAGE must be 1..256 characters");
_Static_assert(sizeof(MY_AAD) - 1 <= AEAD_MAX_AAD, "MY_AAD must be 0..64 characters");
_Static_assert(sizeof(MY_KEY) - 1 == 32, "MY_KEY must be exactly 32 characters");
_Static_assert(sizeof(MY_NONCE) - 1 == 12, "MY_NONCE must be exactly 12 characters");
_Static_assert(MY_RUNS >= 10 && MY_RUNS <= 1000, "MY_RUNS must be 10..1000");

#define MSG_LEN (sizeof(MY_MESSAGE) - 1)
#define AAD_LEN (sizeof(MY_AAD) - 1)
#define MSG_W   ((AEAD_MAX_MSG + 3) / 4)
#define CHUNKS  10                         /* progress bar steps */

static uint8_t  key[32], nonce[12], msg[AEAD_MAX_MSG], aad[AEAD_MAX_AAD + 1];
static uint32_t key_w[8], nonce_w[3], msg_w[MSG_W];
static uint8_t  ct[AEAD_MAX_MSG], tag[16], otk[32], dig[32];     /* software results */
static uint32_t ct_w[MSG_W], back_w[MSG_W], tag_w[4], otk_w[8], dig_w[8];  /* hardware results */
static uint32_t mac_w[(AEAD_MAX_AAD + 16 + AEAD_MAX_MSG + 16 + 16) / 4];   /* MAC input (copy) */
static uint32_t mac_len;

/* ---------------------------------------------------------------------------
 * printing helpers
 * ------------------------------------------------------------------------- */
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

  /* ChaCha20-Poly1305: sender */
  leds(LED_SW);
  aead_encrypt_sw(key, nonce, aad, AAD_LEN, msg, MSG_LEN, ct, tag, otk);
  leds(LED_HW);
  aead_encrypt_hw(key_w, nonce_w, aad, AAD_LEN, msg_w, MSG_LEN, ct_w, tag_w, otk_w);
  mac_len = aead_mac_input(aad, AAD_LEN, (const uint8_t *)ct_w, MSG_LEN);
  memcpy(mac_w, aead_mac_buf, mac_len);            /* keep it for the Poly1305 benchmark */

  neorv32_uart0_printf("\n  ChaCha20 ciphertext of the message (key, nonce, counter 1)\n");
  result("Software:", ct, MSG_LEN);
  result("Hardware:", (const uint8_t *)ct_w, MSG_LEN);
  int ch_ok = (memcmp(ct, ct_w, MSG_LEN) == 0);
  neorv32_uart0_printf("  %s\n", ch_ok ? "PASS: software == hardware" : "FAIL");
  ok &= ch_ok;

  neorv32_uart0_printf("\n  Poly1305 one-time key (= ChaCha20 block 0, first 32 bytes)\n");
  result("Software:", otk, 32);
  result("Hardware:", (const uint8_t *)otk_w, 32);
  neorv32_uart0_printf("  Poly1305 MAC input (%u bytes = AAD | zeros | ciphertext | zeros | lengths)\n", mac_len);
  hex_lines((const uint8_t *)mac_w, mac_len);
  neorv32_uart0_printf("  Poly1305 tag\n");
  result("Software:", tag, 16);
  result("Hardware:", (const uint8_t *)tag_w, 16);
  int po_ok = (memcmp(otk, otk_w, 32) == 0) && (memcmp(tag, tag_w, 16) == 0);
  neorv32_uart0_printf("  %s\n", po_ok ? "PASS: software == hardware" : "FAIL");
  ok &= po_ok;

  /* ChaCha20-Poly1305: receiver */
  int rx_ok = aead_decrypt_hw(key_w, nonce_w, aad, AAD_LEN, ct_w, MSG_LEN, tag_w, back_w)
              && (memcmp(back_w, msg, MSG_LEN) == 0);
  neorv32_uart0_printf("\n  Receiver (hardware): tag %s, decrypted: ", rx_ok ? "OK" : "WRONG");
  print_text((const uint8_t *)back_w, MSG_LEN);
  neorv32_uart0_printf("\n  %s\n", rx_ok ? "PASS: the message comes back" : "FAIL");
  ok &= rx_ok;

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
 *       ChaCha20  = encrypt the whole message (blocks 1, 2, ...); the hardware gets
 *                   the key + nonce once (counted in the time), like demo_chacha20
 *       Poly1305  = tag of the MAC input with the one-time key
 *       Keccak-256 = hash of the message
 * ------------------------------------------------------------------------- */
typedef enum { CHACHA_SW, CHACHA_HW, POLY_SW, POLY_HW, KECCAK_SW, KECCAK_HW } job_t;

static void one_run(job_t job) {
  static uint8_t  o8[AEAD_MAX_MSG];
  static uint32_t o32[MSG_W];
  switch (job) {
    case CHACHA_SW: chacha20_sw_crypt(key, nonce, 1, msg, o8, MSG_LEN);                 break;
    case CHACHA_HW: chacha20_hw_crypt(1, msg_w, o32, MSG_LEN);                          break;
    case POLY_SW:   poly1305_mac(otk, (const uint8_t *)mac_w, mac_len, o8);             break;
    case POLY_HW:   poly1305_hw_mac(otk_w, mac_w, mac_len, o32);                        break;
    case KECCAK_SW: keccak256(msg, MSG_LEN, o8);                                        break;
    case KECCAK_HW: keccak256_hw(msg_w, MSG_LEN, o32);                                  break;
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
      one_run(job);
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
  memcpy(aad, MY_AAD, AAD_LEN);
  memcpy(msg, MY_MESSAGE, MSG_LEN);
  memcpy(msg_w, msg, MSG_LEN);

  while (1) {
    leds(LED_IDLE);
    demo_banner("MY CRYPTO TEST - your own inputs (edit my_crypto.c)");

    neorv32_uart0_printf("\nInputs\n");
    neorv32_uart0_printf("  Message (%u bytes): ", (uint32_t)MSG_LEN); print_text(msg, MSG_LEN);
    neorv32_uart0_printf("\n");
    hex_lines(msg, MSG_LEN);
    neorv32_uart0_printf("  AAD (%u bytes, sent in clear, protected by the tag): ", (uint32_t)AAD_LEN);
    print_text(aad, AAD_LEN);
    neorv32_uart0_printf("\n");
    hex_lines(aad, AAD_LEN);
    neorv32_uart0_printf("  Key:   "); print_text(key, 32);
    neorv32_uart0_printf("\n");
    hex_lines(key, 32);
    neorv32_uart0_printf("  Nonce: "); print_text(nonce, 12);
    neorv32_uart0_printf("\n");
    hex_lines(nonce, 12);

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
    neorv32_uart0_printf("    ChaCha20 = encrypt the message, Poly1305 = tag of the %u-byte MAC input\n", mac_len);
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
