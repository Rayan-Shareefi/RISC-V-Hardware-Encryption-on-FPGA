/*
 * file_crypto.c  -  ENCRYPT / DECRYPT A PICTURE OR ANY FILE (up to 120 KB) on the board
 *
 * Build:  make APP=file_crypto clean exe     (needs the bitstream with 128 KB data memory)
 * Upload neorv32_exe.bin with Tera Term as usual (19200 baud: u, send file binary, e).
 *
 * 1) The program asks you to switch Tera Term to 115200 baud (Setup > Serial port > Speed),
 *    because files are big; everything below runs at 115200. Press BTN0 and switch back to
 *    19200 to use the bootloader / the other programs again.
 * 2) Menu: 1 = encrypt a file, 2 = decrypt a file.
 * 3) Files go both ways with Tera Term's YMODEM (ymodem.h):
 *      to the board:   File > Transfer > YMODEM > Send...  (choose the file)
 *      from the board: File > Transfer > YMODEM > Receive  (Tera Term saves the files in its
 *                      transfer folder: File > Change directory... shows / sets it)
 *
 * Encrypt "x": ChaCha20-Poly1305 (RFC 8439, no AAD) with FILE_KEY / FILE_NONCE below and the
 *   Keccak-256 hash of the file, every step in software AND in hardware on the same file (one
 *   run each). The board sends back "x.enc" (ciphertext + 16-byte tag) and "x.enc.hex.txt"
 *   (the same bytes as hex text). Software and hardware give the same ciphertext; the board
 *   checks this (equal Keccak-256 of both ciphertexts), so one file is enough.
 *   (Only one copy of a 120 KB file fits in memory: the software encrypts it in place, the
 *    hardware decrypts it back (checked), then the hardware encrypts it.)
 * Decrypt "x.enc": the tag is checked first (software and hardware); if it is wrong nothing is
 *   decrypted (REJECTED). Otherwise software and hardware decrypt it (same result checked) and
 *   the board sends back "decrypted_x".
 * Each mode prints a SUMMARY: software vs hardware time for ChaCha20, Poly1305, Keccak-256.
 *
 * Check yourself: CyberChef, open x.enc as input -> ChaCha (counter 1) -> Render Image.
 */
#include <neorv32.h>
#include <string.h>
#include "demo_util.h"
#include "crypto_accel.h"
#include "chacha20_sw.h"
#include "poly1305_sw.h"
#include "keccak_sw.h"
#include "chacha20_poly1305.h"
#include "ymodem.h"

/* ============================ EDIT HERE ============================ */
#define FILE_KEY     "my 32-byte secret key 4 ChaCha20"   /* exactly 32 characters */
#define FILE_NONCE   "unique nonce"                        /* exactly 12 characters */
/* =================================================================== */
_Static_assert(sizeof(FILE_KEY) - 1 == 32, "FILE_KEY must be exactly 32 characters");
_Static_assert(sizeof(FILE_NONCE) - 1 == 12, "FILE_NONCE must be exactly 12 characters");

#define FILE_BAUD    115200
#define MAX_FILE     (120 * 1024)        /* largest file in bytes                     */
#define WAIT_S       120                 /* how long the board waits for a transfer   */

/* the file + room for the Poly1305 padding and the two lengths (MAC input in place) */
static uint32_t buf_w[(MAX_FILE + 16 + 16 + 16) / 4];
#define BUF ((uint8_t *)buf_w)

static uint8_t  key[32], nonce[12];
static uint32_t key_w[8], nonce_w[3];

static char     in_name[YM_MAX_NAME + 1];
static char     out_name[YM_MAX_NAME + 16], hex_name[YM_MAX_NAME + 24];
static uint32_t file_len;                /* bytes of the file / ciphertext in BUF      */
static uint8_t  tag_out[16];             /* tag appended to the encrypted file         */

/* ---------------------------------------------------------------------------
 * printing helpers
 * ------------------------------------------------------------------------- */
static void put_u(uint32_t v, int width) {        /* right-aligned unsigned number */
  char b[11];
  int n = 0;
  do { b[n++] = (char)('0' + v % 10); v /= 10; } while (v);
  while (width-- > n) neorv32_uart0_putc(' ');
  while (n) neorv32_uart0_putc(b[--n]);
}

static void put_ms(uint32_t us, int width) {      /* "1234.567 ms" right-aligned */
  uint32_t f = us % 1000;
  put_u(us / 1000, width - 7);
  neorv32_uart0_printf(".%c%c%c ms", '0' + f / 100, '0' + (f / 10) % 10, '0' + f % 10);
}

static void put_speedup(meas_t sw, meas_t hw) {   /* software cycles / hardware cycles */
  uint32_t x10 = (sw.cycles * 10u + hw.cycles / 2) / hw.cycles;
  put_u(x10 / 10, 6);
  neorv32_uart0_printf(".%ux", x10 % 10);
}

static void summary_row(const char *name, meas_t sw, meas_t hw) {
  neorv32_uart0_printf("  %s", name);
  put_ms(sw.us, 15);
  put_u(sw.cycles, 12);
  put_ms(hw.us, 15);
  put_u(hw.cycles, 11);
  put_speedup(sw, hw);
  neorv32_uart0_printf("\n");
}

static void print_summary(const char *what, uint32_t n, meas_t ch_sw, meas_t ch_hw,
                          meas_t po_sw, meas_t po_hw, meas_t ke_sw, meas_t ke_hw) {
  meas_t all_sw = ch_sw, all_hw = ch_hw;
  meas_add(&all_sw, po_sw);  meas_add(&all_sw, ke_sw);
  meas_add(&all_hw, po_hw);  meas_add(&all_hw, ke_hw);
  neorv32_uart0_printf("\nSUMMARY - %s, %u bytes, one run, %u MHz CPU (time = 1 us counter)\n",
                       what, n, neorv32_sysinfo_get_clk() / 1000000);
  neorv32_uart0_printf("              ------- Software --------  ------- Hardware -------\n");
  neorv32_uart0_printf("                 total time      cycles     total time     cycles  Speedup\n");
  summary_row("ChaCha20  ", ch_sw, ch_hw);
  summary_row("Poly1305  ", po_sw, po_hw);
  summary_row("Keccak-256", ke_sw, ke_hw);
  neorv32_uart0_printf("  -----------------------------------------------------------------------\n");
  summary_row("TOTAL     ", all_sw, all_hw);
}

static void print_digest(const char *label, const uint8_t *d) {
  neorv32_uart0_printf("%s", label);
  print_hex(d, 32);
  neorv32_uart0_printf("\n");
}

/* ---------------------------------------------------------------------------
 * files for YMODEM "send": the encrypted file, its hex text, the decrypted file
 * ------------------------------------------------------------------------- */
static uint8_t enc_byte(uint32_t k) { return (k < file_len) ? BUF[k] : tag_out[k - file_len]; }

static void read_enc(uint32_t off, uint8_t *dst, uint32_t len) {          /* ciphertext + tag */
  for (uint32_t i = 0; i < len; i++) dst[i] = enc_byte(off + i);
}

/* hex text: 32 bytes = 64 hex characters + CR LF per line */
static uint32_t hex_size(uint32_t m) {
  return (m / 32) * 66 + ((m % 32) ? (m % 32) * 2 + 2 : 0);
}

static void read_hex(uint32_t off, uint8_t *dst, uint32_t len) {
  static const char HX[] = "0123456789abcdef";
  uint32_t m = file_len + 16, full = m / 32;
  for (uint32_t i = 0; i < len; i++) {
    uint32_t k = off + i, line = k / 66, pos = k % 66;
    uint32_t lb = (line < full) ? 64 : (m % 32) * 2;                    /* hex characters in this line */
    if (pos < lb) {
      uint8_t b = enc_byte(line * 32 + pos / 2);
      dst[i] = (uint8_t)HX[(pos & 1) ? (b & 15) : (b >> 4)];
    } else {
      dst[i] = (pos == lb) ? '\r' : '\n';
    }
  }
}

static void read_plain(uint32_t off, uint8_t *dst, uint32_t len) {        /* the decrypted file */
  memcpy(dst, BUF + off, len);
}

/* ---------------------------------------------------------------------------
 * transfers
 * ------------------------------------------------------------------------- */
static void flush_rx(void) {
  uint32_t t0 = US_COUNTER;
  while (US_COUNTER - t0 < 50000) {              /* 50 ms: drop old characters (Enter etc.) */
    if (neorv32_uart0_char_received()) {
      (void)neorv32_uart0_char_received_get();
      t0 = US_COUNTER;
    }
  }
}

/* receive a file with YMODEM; returns its size, 0 = nothing / error */
static uint32_t get_file(const char *what, uint32_t max) {
  uint32_t n = 0;
  neorv32_uart0_printf("\nSend the %s now:\n", what);
  neorv32_uart0_printf("  Tera Term: File > Transfer > YMODEM > Send...  > choose the file > Open\n");
  neorv32_uart0_printf("  (largest %u bytes; the board waits %u s; the letters C below are the board asking - normal)\n",
                       max, (uint32_t)WAIT_S);
  while (neorv32_uart0_tx_busy());
  flush_rx();
  leds(LED_SW);
  int r = ym_receive(BUF, max, in_name, &n, WAIT_S);
  leds(LED_IDLE);
  if (r == YM_OK) {
    neorv32_uart0_printf("\nReceived \"%s\": %u bytes.\n", in_name, n);
    return n;
  }
  if (r == YM_TOO_BIG)        neorv32_uart0_printf("\nThe file is too big: %u bytes (largest %u). Nothing was done.\n", n, max);
  else if (r == YM_TIMEOUT)   neorv32_uart0_printf("\nNo file arrived (waited %u s).\n", (uint32_t)WAIT_S);
  else if (r == YM_CANCELLED) neorv32_uart0_printf("\nThe transfer was cancelled.\n");
  else                        neorv32_uart0_printf("\nTransfer error - please try again.\n");
  return 0;
}

/* send files with YMODEM; prints what to do and the result */
static void put_files(const ym_file_t *files, int count) {
  neorv32_uart0_printf("\nSave the result now:  Tera Term: File > Transfer > YMODEM > Receive\n");
  for (int i = 0; i < count; i++) neorv32_uart0_printf("  -> \"%s\" (%u bytes)\n", files[i].name, files[i].size);
  while (neorv32_uart0_tx_busy());
  flush_rx();
  leds(LED_HW);
  int r = ym_send(files, count, WAIT_S);
  leds(LED_IDLE);
  flush_rx();
  if (r == YM_OK) {
    neorv32_uart0_printf("\nDone. Tera Term saved ");
    for (int i = 0; i < count; i++) neorv32_uart0_printf("%s\"%s\"", i ? " and " : "", files[i].name);
    neorv32_uart0_printf("\nin its transfer folder (File > Change directory... shows / sets that folder).\n");
  } else {
    neorv32_uart0_printf("\nThe files were not saved (%s). Choose the menu item again.\n",
                         r == YM_TIMEOUT ? "YMODEM Receive was not started in time" : "transfer error");
  }
}

/* MAC input in place after the ciphertext: zeros to a multiple of 16, then
   len(AAD) = 0 and len(ciphertext) = n as 8-byte little-endian numbers. Returns its length. */
static uint32_t build_mac_input(uint32_t n) {
  uint32_t m = n;
  while (m % 16) BUF[m++] = 0;
  buf_w[m / 4]     = 0;      /* AAD length (no AAD for files) */
  buf_w[m / 4 + 1] = 0;
  buf_w[m / 4 + 2] = n;      /* ciphertext length */
  buf_w[m / 4 + 3] = 0;
  return m + 16;
}

/* one-time Poly1305 key = first 32 bytes of ChaCha20 block 0 (hardware; also loads key + nonce) */
static __attribute__((noinline)) void one_time_key_hw(uint32_t otk_w[8]) {
  static uint32_t zero[16];
  uint32_t blk0[16];
  chacha20_hw_set_key(key_w, nonce_w);
  chacha20_hw_block_fast(0, zero, blk0);
  for (int i = 0; i < 8; i++) otk_w[i] = blk0[i];
}

static __attribute__((noinline)) void chacha_hw(uint32_t n) {              /* ChaCha20 in place, hardware (counter 1, 2, ...) */
  chacha20_hw_set_key(key_w, nonce_w);
  chacha20_hw_crypt(1, buf_w, buf_w, n);
}

/* the hardware drivers in crypto_accel.h are inline and fully unrolled; here they are
   wrapped once, so their code exists only once in this (big) program */
static __attribute__((noinline)) void keccak_hw1(const uint32_t *m, uint32_t n, uint32_t d[8]) { keccak256_hw(m, n, d); }
static __attribute__((noinline)) void poly_hw1(const uint32_t k[8], const uint32_t *m, uint32_t n, uint32_t tag[4]) { poly1305_hw_mac(k, m, n, tag); }

static int same32(const uint32_t *a, const uint32_t *b) { return memcmp(a, b, 32) == 0; }

/* ---------------------------------------------------------------------------
 * 1) encrypt
 * ------------------------------------------------------------------------- */
static void encrypt_file(void) {
  uint8_t  dig_sw[32], otk_sw[64], tag_sw[16];
  uint32_t dig_hw[8], h_back[8], h_ct_sw[8], h_ct_hw[8], otk_hw[8], tag_hw[4];
  bench_timer_t t;
  meas_t ke_sw, ke_hw, ch_sw, ch_hw, po_sw, po_hw;

  uint32_t n = get_file("file to ENCRYPT", MAX_FILE);
  if (n == 0) return;
  file_len = n;
  neorv32_uart0_printf("Encrypting in software and in hardware (the software needs a few seconds)...\n");

  /* Keccak-256 of the original file */
  leds(LED_SW); bench_start(&t); keccak256(BUF, n, dig_sw);          ke_sw = bench_stop(&t);
  leds(LED_HW); bench_start(&t); keccak_hw1(buf_w, n, dig_hw);     ke_hw = bench_stop(&t);
  int ke_ok = (memcmp(dig_sw, dig_hw, 32) == 0);

  /* one-time Poly1305 key (ChaCha20 block 0) */
  chacha20_block(key, nonce, 0, otk_sw);
  one_time_key_hw(otk_hw);
  int otk_ok = (memcmp(otk_sw, otk_hw, 32) == 0);

  /* ChaCha20: software encryption (in place) */
  leds(LED_SW); bench_start(&t);
  chacha20_sw_crypt(key, nonce, 1, BUF, BUF, n);
  ch_sw = bench_stop(&t);
  keccak_hw1(buf_w, n, h_ct_sw);                 /* fingerprint of the software ciphertext */
  chacha_hw(n);                                    /* back to the original file (not timed)  */
  keccak_hw1(buf_w, n, h_back);
  /* ChaCha20: hardware encryption (in place) = the encrypted file that is sent back */
  leds(LED_HW); bench_start(&t);
  chacha_hw(n);
  ch_hw = bench_stop(&t);
  keccak_hw1(buf_w, n, h_ct_hw);
  int ch_ok = same32(h_back, dig_hw) && same32(h_ct_sw, h_ct_hw);

  /* Poly1305 tag of the ciphertext (+ padding + lengths) */
  uint32_t mac_len = build_mac_input(n);
  leds(LED_SW); bench_start(&t); poly1305_mac(otk_sw, BUF, mac_len, tag_sw);      po_sw = bench_stop(&t);
  leds(LED_HW); bench_start(&t); poly_hw1(otk_hw, buf_w, mac_len, tag_hw); po_hw = bench_stop(&t);
  int po_ok = otk_ok && (memcmp(tag_sw, tag_hw, 16) == 0);
  memcpy(tag_out, tag_hw, 16);
  leds(LED_IDLE);

  int ok = ke_ok && ch_ok && po_ok;
  neorv32_uart0_printf("\nENCRYPTION FINISHED (key \"%s\", nonce \"%s\")\n", FILE_KEY, FILE_NONCE);
  print_digest("Keccak-256 of the original file:   ", (const uint8_t *)dig_hw);
  print_digest("Keccak-256 of the ciphertext (SW): ", (const uint8_t *)h_ct_sw);
  print_digest("Keccak-256 of the ciphertext (HW): ", (const uint8_t *)h_ct_hw);
  neorv32_uart0_printf("Poly1305 tag (SW): "); print_hex(tag_sw, 16);
  neorv32_uart0_printf("\nPoly1305 tag (HW): "); print_hex((const uint8_t *)tag_hw, 16);
  neorv32_uart0_printf("\nChecks: Keccak SW == HW %s | ciphertext SW == HW %s | tag SW == HW %s\n",
                       pass_fail(ke_ok), pass_fail(ch_ok), pass_fail(po_ok));
  neorv32_uart0_printf("(software and hardware give exactly the same encrypted file, so one file is sent)\n");
  print_summary("ENCRYPTION", n, ch_sw, ch_hw, po_sw, po_hw, ke_sw, ke_hw);
  neorv32_uart0_printf(ok ? "ALL CHECKS PASSED\n" : "*** SOME CHECKS FAILED ***\n");
  leds(ok ? LED_PASS : LED_FAIL);
  if (!ok) return;

  /* send back: x.enc (ciphertext + tag) and x.enc.hex.txt (the same as hex text) */
  strcpy(out_name, in_name); strcat(out_name, ".enc");
  strcpy(hex_name, out_name); strcat(hex_name, ".hex.txt");
  ym_file_t files[2] = {
    { out_name, n + 16, read_enc },
    { hex_name, hex_size(n + 16), read_hex },
  };
  put_files(files, 2);
}

/* ---------------------------------------------------------------------------
 * 2) decrypt
 * ------------------------------------------------------------------------- */
static void decrypt_file(void) {
  uint8_t  tag_rx[16], otk_sw[64], tag_sw[16], dig_sw[32];
  uint32_t otk_hw[8], tag_hw[4], h_ct[8], h_back[8], h_pt_sw[8], h_pt_hw[8], dig_hw[8];
  uint32_t diff = 0;
  bench_timer_t t;
  meas_t po_sw, po_hw, ch_sw, ch_hw, ke_sw, ke_hw;

  uint32_t n = get_file("ENCRYPTED file (the .enc file)", MAX_FILE + 16);
  if (n == 0) return;
  if (n < 16) {
    neorv32_uart0_printf("Too short: an encrypted file has at least the 16-byte tag.\n");
    return;
  }
  n -= 16;                                       /* n = ciphertext length */
  file_len = n;
  memcpy(tag_rx, BUF + n, 16);
  neorv32_uart0_printf("Checking and decrypting in software and in hardware...\n");
  keccak_hw1(buf_w, n, h_ct);                  /* fingerprint of the ciphertext */

  /* 1) the tag first (software and hardware) */
  chacha20_block(key, nonce, 0, otk_sw);
  one_time_key_hw(otk_hw);
  uint32_t mac_len = build_mac_input(n);
  leds(LED_SW); bench_start(&t); poly1305_mac(otk_sw, BUF, mac_len, tag_sw);      po_sw = bench_stop(&t);
  leds(LED_HW); bench_start(&t); poly_hw1(otk_hw, buf_w, mac_len, tag_hw); po_hw = bench_stop(&t);
  leds(LED_IDLE);
  for (int i = 0; i < 16; i++) diff |= ((const uint8_t *)tag_hw)[i] ^ tag_rx[i];
  int po_ok = (memcmp(tag_sw, tag_hw, 16) == 0);

  neorv32_uart0_printf("\nReceived tag:          "); print_hex(tag_rx, 16);
  neorv32_uart0_printf("\nRecomputed tag (SW):   "); print_hex(tag_sw, 16);
  neorv32_uart0_printf("\nRecomputed tag (HW):   "); print_hex((const uint8_t *)tag_hw, 16);
  neorv32_uart0_printf("\n");
  if (diff || !po_ok) {
    neorv32_uart0_printf("REJECTED: the tag is wrong (file changed, or wrong key/nonce). Nothing was decrypted.\n");
    neorv32_uart0_printf("(tag check: software %u us, hardware %u us)\n", po_sw.us, po_hw.us);
    leds(LED_FAIL);
    return;
  }
  neorv32_uart0_printf("Tag OK: the file was not changed.\n");

  /* 2) ChaCha20: software decryption (in place), back to the ciphertext, hardware decryption */
  leds(LED_SW); bench_start(&t);
  chacha20_sw_crypt(key, nonce, 1, BUF, BUF, n);
  ch_sw = bench_stop(&t);
  keccak_hw1(buf_w, n, h_pt_sw);               /* fingerprint of the software result */
  chacha_hw(n);                                  /* back to the ciphertext (not timed) */
  keccak_hw1(buf_w, n, h_back);
  leds(LED_HW); bench_start(&t);
  chacha_hw(n);
  ch_hw = bench_stop(&t);
  keccak_hw1(buf_w, n, h_pt_hw);
  int ch_ok = same32(h_back, h_ct) && same32(h_pt_sw, h_pt_hw);

  /* 3) Keccak-256 of the decrypted file */
  leds(LED_SW); bench_start(&t); keccak256(BUF, n, dig_sw);      ke_sw = bench_stop(&t);
  leds(LED_HW); bench_start(&t); keccak_hw1(buf_w, n, dig_hw); ke_hw = bench_stop(&t);
  leds(LED_IDLE);
  int ke_ok = (memcmp(dig_sw, dig_hw, 32) == 0);

  int ok = po_ok && ch_ok && ke_ok;
  neorv32_uart0_printf("\nDECRYPTION FINISHED\n");
  print_digest("Keccak-256 of the decrypted file: ", (const uint8_t *)dig_hw);
  neorv32_uart0_printf("(must equal the hash of the original file printed when it was encrypted)\n");
  neorv32_uart0_printf("Checks: tag SW == HW %s | decrypted file SW == HW %s | Keccak SW == HW %s\n",
                       pass_fail(po_ok), pass_fail(ch_ok), pass_fail(ke_ok));
  print_summary("DECRYPTION", n, ch_sw, ch_hw, po_sw, po_hw, ke_sw, ke_hw);
  neorv32_uart0_printf(ok ? "ALL CHECKS PASSED\n" : "*** SOME CHECKS FAILED ***\n");
  leds(ok ? LED_PASS : LED_FAIL);
  if (!ok) return;

  /* send back "decrypted_x" (x = the name without ".enc") */
  uint32_t L = strlen(in_name);
  strcpy(out_name, "decrypted_");
  strcat(out_name, in_name);
  if (L > 4 && strcmp(in_name + L - 4, ".enc") == 0) out_name[10 + L - 4] = 0;
  ym_file_t files[1] = { { out_name, n, read_plain } };
  put_files(files, 1);
}

int main(void) {
  neorv32_rte_setup();
  neorv32_uart0_setup(BAUD_RATE, 0);
  neorv32_gpio_dir_set(0xFF);
  leds(LED_IDLE);
  memcpy(key, FILE_KEY, 32);     memcpy(key_w, key, 32);
  memcpy(nonce, FILE_NONCE, 12); memcpy(nonce_w, nonce, 12);

  demo_banner("FILE CRYPTO - encrypt / decrypt a picture or any file (ChaCha20-Poly1305 + Keccak-256)");
  neorv32_uart0_printf("\nFiles are big, so this program uses %u baud.\n", (uint32_t)FILE_BAUD);
  neorv32_uart0_printf("Set Tera Term to %u now (Setup > Serial port > Speed), then press any key.\n", (uint32_t)FILE_BAUD);
  neorv32_uart0_printf("(Afterwards: press BTN0 and set Tera Term back to 19200 for the bootloader.)\n");
  while (neorv32_uart0_tx_busy());
  neorv32_uart0_setup(FILE_BAUD, 0);
  flush_rx();
  (void)neorv32_uart0_getc();

  while (1) {
    neorv32_uart0_printf("\n=== FILE CRYPTO (%u baud) ===\n", (uint32_t)FILE_BAUD);
    neorv32_uart0_printf("Key: \"%s\"   Nonce: \"%s\"   (ChaCha20-Poly1305, RFC 8439, no AAD)\n", FILE_KEY, FILE_NONCE);
    neorv32_uart0_printf("  1 = encrypt a file\n  2 = decrypt a file\nChoose 1 or 2: ");
    char c;
    do { c = neorv32_uart0_getc(); } while (c != '1' && c != '2');
    neorv32_uart0_printf("%c\n", c);
    leds(LED_IDLE);
    if (c == '1') encrypt_file();
    else          decrypt_file();
  }
  return 0;
}
