/*
 * my_crypto.c  -  YOUR OWN TEST WITH A MENU: edit the values below, build, upload, choose 1..6
 *
 * 1) Edit MY_MESSAGE / MY_AAD / MY_KEY / MY_NONCE / MY_RUNS below.
 * 2) Build: in a terminal in this folder type   make APP=my_crypto clean exe
 *    -> creates neorv32_exe.bin in this folder.
 * 3) Upload neorv32_exe.bin with Tera Term (bootloader: u, send file as binary, e).
 * 4) Type a number in Tera Term:
 *      1 = ChaCha20 software      2 = ChaCha20 hardware      encrypt the message
 *      3 = Poly1305 software      4 = Poly1305 hardware      ChaCha20-Poly1305 (RFC 8439): ChaCha20
 *                                                            first (one-time key + ciphertext), then
 *                                                            Poly1305 (tag); prints the ChaCha20 time,
 *                                                            the Poly1305 time and their total
 *      5 = Keccak-256 software    6 = Keccak-256 hardware    hash of the message (time alone)
 *    Each option (a) runs once and prints the result in hex, to check it online (HOW_TO_RUN.md),
 *    (b) checks it against the other version (software vs hardware, not timed),
 *    (c) runs MY_RUNS times and prints the time. After a software option, the hardware
 *        option of the same algorithm also prints the speedup.
 *
 * ============================== HOW THE TIME IS MEASURED ==============================
 * See measure() below. Two counters are read just before and just after the MY_RUNS runs:
 *   - CPU cycle counter: +1 every clock cycle (12 MHz clock = 12 cycles per microsecond).
 *     Read with neorv32_cpu_get_cycle()  (neorv32-main/sw/lib/source/neorv32_cpu.c, it reads
 *     the RISC-V "cycle" register).
 *   - 1 microsecond counter: our own hardware in the CFS (neorv32_cfs.vhd, process us_counter):
 *     it counts 12 clock cycles, then adds 1. Read with US_COUNTER (crypto_accel.h).
 *
 *     cycles = end_cycle - start_cycle
 *     time   = cycles / 12 MHz        (in us: cycles / 12, in ms: cycles * 1000 / 12,000,000)
 *     The 1 us counter gives the same time directly: time_us = end_us - start_us.
 *     One run = total / MY_RUNS.   Speedup = software cycles / hardware cycles.
 *   Nothing is printed between start and end, so only the algorithm is timed.
 *   One run = the whole job, including giving the key to the algorithm (the hardware gets the
 *   key + nonce in every run, like the software).
 *
 * ============================== FUNCTIONS USED (inputs -> output) =====================
 * Software (C code that runs on the RISC-V CPU):
 *   chacha20_block(key, nonce, counter, out)                                 chacha20_sw.c
 *       key = 32 bytes, nonce = 12 bytes, counter = block number.
 *       Fills the 4x4 state of 32-bit words (4 constants, key, counter, nonce), runs 20 rounds
 *       (10 x: 4 column + 4 diagonal quarterrounds), adds the start state -> out = 64 bytes of
 *       keystream.
 *   quarterround(a, b, c, d)                                                 chacha20_sw.c
 *       4 state words; add, XOR and rotate left by 16, 12, 8, 7 -> changes them in place.
 *   chacha20_sw_encrypt(key, nonce, counter, in, out)                        chacha20_sw.c
 *       one 64-byte block: out = in XOR chacha20_block(key, nonce, counter).
 *   chacha20_sw_crypt(key, nonce, counter, in, out, len)                     chacha20_poly1305.h
 *       any length: blocks counter, counter+1, ...; the last partial block uses only len bytes.
 *       Encrypting and decrypting are the same operation.
 *   aead_mac_input(aad, aad_len, ct, len)                                    chacha20_poly1305.h
 *       builds the Poly1305 input of RFC 8439 in aead_mac_buf and returns its length:
 *       AAD | zeros to 16 | ciphertext | zeros to 16 | len(AAD) (8 bytes) | len(ciphertext) (8 bytes)
 *   poly1305_mac(key, msg, len, tag)                                         poly1305_sw.c
 *       key = 32 bytes (r = first 16, s = last 16), msg = len bytes. For every 16-byte piece:
 *       h = (h + piece) * r  mod 2^130 - 5  (h kept in 5 parts of 26 bits);
 *       at the end tag = h + s -> 16 bytes.
 *   keccak256(msg, len, digest)                                              keccak_sw.c
 *       takes msg in 136-byte blocks: XOR each block into the 200-byte state, then keccak_f1600;
 *       the last block is padded with 0x01 ... 0x80 (original Keccak); digest = first 32 bytes.
 *   keccak_f1600(A)                                                          keccak_sw.c
 *       A = 25 words of 64 bits; 24 rounds of theta, rho, pi, chi, iota.
 * Hardware drivers (crypto_accel.h): they move the data into the accelerator with our custom
 * instructions. The hardware uses 32-bit words: key_w, msg_w, ... hold the same bytes as key, msg.
 *   CRYPTO_WRITE(index, value) / CRYPTO_READ(index)  write / read one accelerator register
 *   CHACHA_START() / POLY_START() / KECCAK_START()  start a unit; the next read waits for the result
 *   chacha20_hw_set_key(key_w, nonce_w)          key (8 words) + nonce (3 words) -> registers
 *   chacha20_hw_block_fast(counter, in, out)     one 64-byte block (16 words)
 *   chacha20_hw_crypt(counter, in, out, len)     any length (key + nonce loaded before)
 *   poly1305_hw_mac(key_w, msg_w, len, tag_w)    tag of any length, sent in 64-byte pieces
 *   keccak256_hw(msg_w, len, digest_w)           hash of any length, sent in 136-byte blocks
 * This program:
 *   run_job(job)    one run of one job (the list of jobs is at job_t)
 *   measure(job)    times MY_RUNS runs of one job (see "HOW THE TIME IS MEASURED")
 *   print_time()    prints cycles, cycles / 12 MHz and the 1 us counter
 *   option_chacha() / option_poly() / option_keccak()   the menu options
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
#define MY_RUNS      1000                                           /* timed runs (10..1000) */
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

/* inputs: bytes for the software, 32-bit words (same bytes) for the hardware */
static uint8_t  key[32], nonce[12], msg[AEAD_MAX_MSG], aad[AEAD_MAX_AAD + 1];
static uint32_t key_w[8], nonce_w[3], msg_w[MSG_W];
/* results: software (bytes) and hardware (words) */
static uint8_t  ct[AEAD_MAX_MSG], otk[32], tag[16], dig[32];
static uint32_t ct_w[MSG_W], otk_w[8], tag_w[4], dig_w[8];
static uint32_t mac_len;                         /* length of the Poly1305 MAC input in bytes */

/* ---------------------------------------------------------------------------
 * one run of one job
 * ------------------------------------------------------------------------- */
typedef enum {
  CHACHA_SW, CHACHA_HW,                /* ChaCha20: encrypt the message (blocks 1, 2, ...)          */
  AEAD_CHACHA_SW, AEAD_CHACHA_HW,      /* ChaCha20 part of ChaCha20-Poly1305: one-time key + encrypt */
  AEAD_POLY_SW, AEAD_POLY_HW,          /* Poly1305 part: MAC input + tag                             */
  KECCAK_SW, KECCAK_HW                 /* Keccak-256 hash of the message                             */
} job_t;

static void run_job(job_t job) {
  static uint32_t zero[16];            /* all 0: ChaCha20 block 0 of zeros = the keystream itself */
  uint8_t  blk0[64];
  uint32_t blk0_w[16];
  switch (job) {
    case CHACHA_SW:
      chacha20_sw_crypt(key, nonce, 1, msg, ct, MSG_LEN);
      break;
    case CHACHA_HW:
      chacha20_hw_set_key(key_w, nonce_w);
      chacha20_hw_crypt(1, msg_w, ct_w, MSG_LEN);
      break;
    case AEAD_CHACHA_SW:
      chacha20_block(key, nonce, 0, blk0);                 /* one-time key = block 0 */
      memcpy(otk, blk0, 32);
      chacha20_sw_crypt(key, nonce, 1, msg, ct, MSG_LEN);  /* encrypt with blocks 1, 2, ... */
      break;
    case AEAD_CHACHA_HW:
      chacha20_hw_set_key(key_w, nonce_w);
      chacha20_hw_block_fast(0, zero, blk0_w);             /* one-time key = block 0 */
      for (int i = 0; i < 8; i++) otk_w[i] = blk0_w[i];
      chacha20_hw_crypt(1, msg_w, ct_w, MSG_LEN);          /* encrypt with blocks 1, 2, ... */
      break;
    case AEAD_POLY_SW:
      mac_len = aead_mac_input(aad, AAD_LEN, ct, MSG_LEN);
      poly1305_mac(otk, (const uint8_t *)aead_mac_buf, mac_len, tag);
      break;
    case AEAD_POLY_HW:
      mac_len = aead_mac_input(aad, AAD_LEN, (const uint8_t *)ct_w, MSG_LEN);
      poly1305_hw_mac(otk_w, aead_mac_buf, mac_len, tag_w);
      break;
    case KECCAK_SW:
      keccak256(msg, MSG_LEN, dig);
      break;
    case KECCAK_HW:
      keccak256_hw(msg_w, MSG_LEN, dig_w);
      break;
  }
  MEMORY_BARRIER();                    /* every run really reads its input and writes its result */
}

/* ---------------------------------------------------------------------------
 * TIME MEASUREMENT: MY_RUNS runs of one job between two readings of the counters
 * ------------------------------------------------------------------------- */
static meas_t measure(job_t job) {
  /* START: read both counters */
  uint64_t start_cycle = neorv32_cpu_get_cycle();   /* CPU clock cycles since reset      */
  uint32_t start_us    = US_COUNTER;                /* microseconds since reset (CFS)    */

  for (uint32_t i = 0; i < MY_RUNS; i++) {
    run_job(job);                                   /* the algorithm, MY_RUNS times      */
  }

  /* END: read both counters again */
  uint32_t end_us      = US_COUNTER;
  uint64_t end_cycle   = neorv32_cpu_get_cycle();

  meas_t m;
  m.cycles = (uint32_t)(end_cycle - start_cycle);   /* total cycles     = end - start    */
  m.us     = end_us - start_us;                     /* total time in us = end - start    */
  return m;
}

/* ---------------------------------------------------------------------------
 * printing
 * ------------------------------------------------------------------------- */
/* total microseconds / MY_RUNS as "1675.083 us" (time of one run) */
static void print_us_per_run(uint32_t total_us) {
  uint32_t whole = total_us / MY_RUNS;
  uint32_t frac  = (total_us % MY_RUNS) * 1000 / MY_RUNS;
  neorv32_uart0_printf("%u.%c%c%c us", whole, '0' + frac / 100, '0' + (frac / 10) % 10, '0' + frac % 10);
}

static void print_time(const char *name, meas_t m) {
  uint32_t mhz = neorv32_sysinfo_get_clk() / 1000000;     /* 12 */
  uint32_t us  = m.cycles / mhz;                           /* time = cycles / 12 MHz, in us */
  neorv32_uart0_printf("  %s, %u runs\n", name, (uint32_t)MY_RUNS);
  neorv32_uart0_printf("    cycles = end_cycle - start_cycle = %u   (one run: %u cycles)\n",
                       m.cycles, m.cycles / MY_RUNS);
  neorv32_uart0_printf("    time   = cycles / %u MHz = ", mhz);
  print_ms(us);
  neorv32_uart0_printf("   (one run: ");
  print_us_per_run(us);
  neorv32_uart0_printf(")\n    1 us counter: end_us - start_us = ");
  print_ms(m.us);
  neorv32_uart0_printf("\n");
}

static void print_check(int ok, int hw) {
  neorv32_uart0_printf("  Check against the %s: %s\n", hw ? "software" : "hardware",
                       ok ? "PASS (same result)" : "FAIL");
}

static void timing_title(int hw) {
  neorv32_uart0_printf("\n  Timing (%s on, please wait)...\n", hw ? "LD2" : "LD1");
  while (neorv32_uart0_tx_busy());                         /* text is out before the timing starts */
  leds(hw ? LED_HW : LED_SW);
}

/* software times, kept for the speedup of the hardware options */
static meas_t sw_ch, sw_ach, sw_apo, sw_ke;
static int    have_ch, have_aead, have_ke;

/* ---------------------------------------------------------------------------
 * menu options
 * ------------------------------------------------------------------------- */
static void option_chacha(int hw) {
  neorv32_uart0_printf("\n[%c] ChaCha20 %s: encrypt your %u-byte message (key, nonce, counter 1)\n",
                       hw ? '2' : '1', hw ? "HARDWARE" : "SOFTWARE", (uint32_t)MSG_LEN);
  run_job(CHACHA_SW);                                      /* one run of each, to check */
  run_job(CHACHA_HW);
  int ok = (memcmp(ct, ct_w, MSG_LEN) == 0);
  neorv32_uart0_printf("  Ciphertext:\n");
  hex_lines(hw ? (const uint8_t *)ct_w : ct, MSG_LEN);
  print_check(ok, hw);

  timing_title(hw);
  meas_t m = measure(hw ? CHACHA_HW : CHACHA_SW);
  leds(LED_IDLE);
  print_time(hw ? "ChaCha20 HW" : "ChaCha20 SW", m);

  if (!hw) { sw_ch = m; have_ch = 1; }
  else if (have_ch) print_speedup("ChaCha20", sw_ch, m);
  else neorv32_uart0_printf("  (run option 1 to see the speedup)\n");
  leds(ok ? LED_PASS : LED_FAIL);
}

static void option_poly(int hw) {
  neorv32_uart0_printf("\n[%c] Poly1305 %s: ChaCha20-Poly1305 (RFC 8439)\n", hw ? '4' : '3', hw ? "HARDWARE" : "SOFTWARE");
  neorv32_uart0_printf("  ChaCha20 runs first (one-time key = block 0, ciphertext = blocks 1, 2, ...),\n");
  neorv32_uart0_printf("  then Poly1305 makes the 16-byte tag of the MAC input.\n");
  if (hw) { run_job(AEAD_CHACHA_SW); run_job(AEAD_POLY_SW); run_job(AEAD_CHACHA_HW); run_job(AEAD_POLY_HW); }
  else    { run_job(AEAD_CHACHA_HW); run_job(AEAD_POLY_HW); run_job(AEAD_CHACHA_SW); run_job(AEAD_POLY_SW); }
  int ok = (memcmp(ct, ct_w, MSG_LEN) == 0) && (memcmp(otk, otk_w, 32) == 0) && (memcmp(tag, tag_w, 16) == 0);
  neorv32_uart0_printf("  ChaCha20 ciphertext:\n");
  hex_lines(hw ? (const uint8_t *)ct_w : ct, MSG_LEN);
  neorv32_uart0_printf("  Poly1305 one-time key (first 32 bytes of ChaCha20 block 0):\n");
  hex_lines(hw ? (const uint8_t *)otk_w : otk, 32);
  neorv32_uart0_printf("  Poly1305 MAC input (%u bytes = AAD | zeros | ciphertext | zeros | lengths):\n", mac_len);
  hex_lines((const uint8_t *)aead_mac_buf, mac_len);       /* built by the last run (the chosen version) */
  neorv32_uart0_printf("  Poly1305 tag:\n");
  hex_lines(hw ? (const uint8_t *)tag_w : tag, 16);
  print_check(ok, hw);

  timing_title(hw);
  meas_t mc = measure(hw ? AEAD_CHACHA_HW : AEAD_CHACHA_SW);
  meas_t mp = measure(hw ? AEAD_POLY_HW : AEAD_POLY_SW);
  leds(LED_IDLE);
  meas_t mt = mc;
  meas_add(&mt, mp);                                       /* total = ChaCha20 + Poly1305 */
  print_time(hw ? "ChaCha20 HW (one-time key + encrypt)" : "ChaCha20 SW (one-time key + encrypt)", mc);
  print_time(hw ? "Poly1305 HW (MAC input + tag)" : "Poly1305 SW (MAC input + tag)", mp);
  print_time(hw ? "TOTAL HW = ChaCha20 + Poly1305" : "TOTAL SW = ChaCha20 + Poly1305", mt);

  if (!hw) { sw_ach = mc; sw_apo = mp; have_aead = 1; }
  else if (have_aead) {
    meas_t st = sw_ach;
    meas_add(&st, sw_apo);
    print_speedup("ChaCha20", sw_ach, mc);
    print_speedup("Poly1305", sw_apo, mp);
    print_speedup("TOTAL   ", st, mt);
  }
  else neorv32_uart0_printf("  (run option 3 to see the speedup)\n");
  leds(ok ? LED_PASS : LED_FAIL);
}

static void option_keccak(int hw) {
  neorv32_uart0_printf("\n[%c] Keccak-256 %s: hash of your %u-byte message\n",
                       hw ? '6' : '5', hw ? "HARDWARE" : "SOFTWARE", (uint32_t)MSG_LEN);
  run_job(KECCAK_SW);
  run_job(KECCAK_HW);
  int ok = (memcmp(dig, dig_w, 32) == 0);
  neorv32_uart0_printf("  Keccak-256 hash:\n");
  hex_lines(hw ? (const uint8_t *)dig_w : dig, 32);
  print_check(ok, hw);

  timing_title(hw);
  meas_t m = measure(hw ? KECCAK_HW : KECCAK_SW);
  leds(LED_IDLE);
  print_time(hw ? "Keccak-256 HW" : "Keccak-256 SW", m);

  if (!hw) { sw_ke = m; have_ke = 1; }
  else if (have_ke) print_speedup("Keccak-256", sw_ke, m);
  else neorv32_uart0_printf("  (run option 5 to see the speedup)\n");
  leds(ok ? LED_PASS : LED_FAIL);
}

int main(void) {
  neorv32_rte_setup();
  neorv32_uart0_setup(BAUD_RATE, 0);
  neorv32_gpio_dir_set(0xFF);
  leds(LED_IDLE);

  memcpy(key, MY_KEY, 32);       memcpy(key_w, key, 32);
  memcpy(nonce, MY_NONCE, 12);   memcpy(nonce_w, nonce, 12);
  memcpy(aad, MY_AAD, AAD_LEN);
  memcpy(msg, MY_MESSAGE, MSG_LEN);
  memcpy(msg_w, msg, MSG_LEN);

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

  while (1) {
    neorv32_uart0_printf("\n=================== MENU (%u runs per timing) ===================\n", (uint32_t)MY_RUNS);
    neorv32_uart0_printf("  1 = ChaCha20 software      2 = ChaCha20 hardware\n");
    neorv32_uart0_printf("  3 = Poly1305 software      4 = Poly1305 hardware   (ChaCha20 + Poly1305 + total)\n");
    neorv32_uart0_printf("  5 = Keccak-256 software    6 = Keccak-256 hardware\n");
    neorv32_uart0_printf("Choose 1-6: ");
    char c;
    do { c = neorv32_uart0_getc(); } while (c < '1' || c > '6');
    neorv32_uart0_printf("%c\n", c);
    leds(LED_IDLE);
    switch (c) {
      case '1': option_chacha(0); break;
      case '2': option_chacha(1); break;
      case '3': option_poly(0);   break;
      case '4': option_poly(1);   break;
      case '5': option_keccak(0); break;
      default:  option_keccak(1); break;
    }
  }
  return 0;
}
