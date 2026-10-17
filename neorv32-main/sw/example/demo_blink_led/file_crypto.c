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
 * ChaCha20-Poly1305 (RFC 8439) with FILE_KEY / FILE_NONCE below, every step in software AND in
 * hardware on the same file (one run each).
 *   BMP picture ("BM" at the start): the header (everything before the pixels; its length is
 *     written in bytes 10..13 of the file) stays in clear, only the pixels are encrypted. The
 *     header is the AAD: not encrypted, but protected by the tag. So the encrypted picture still
 *     opens in a picture viewer and shows noise. Encrypt "x.bmp" -> "x.enc.bmp".
 *   Any other file: everything is encrypted (no AAD). Encrypt "x" -> "x.enc".
 *   The encrypted file = header (BMP only) | ciphertext | 16-byte tag; the board also sends the
 *   same bytes as hex text ("....hex.txt").
 * Decrypt: the tag is checked first (software and hardware); if it is wrong nothing is decrypted
 *   (REJECTED). Otherwise software and hardware decrypt it -> "decrypted_x.bmp" / "decrypted_x".
 * Each mode prints a SUMMARY: software vs hardware time for ChaCha20, Poly1305 and the TOTAL.
 *
 * Only one copy of a 120 KB file fits in memory, so the software and the hardware work on the
 * same buffer one after the other (the software result is turned back with the hardware, not
 * timed). The checks use a Poly1305 tag of the whole buffer as a fingerprint (not timed).
 */
#include <neorv32.h>
#include <string.h>
#include "demo_util.h"
#include "crypto_accel.h"
#include "chacha20_sw.h"
#include "poly1305_sw.h"
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

/* The buffer holds the MAC input in place (RFC 8439, AAD = header):
     header | zeros to 16 | data (encrypted in place) | zeros to 16 | len(header) | len(data)
   so it needs room for the file + 2 x 15 zeros + 16 bytes of lengths (+ the tag while receiving). */
static uint32_t buf_w[(MAX_FILE + 64) / 4];
#define BUF ((uint8_t *)buf_w)
#define PAD16(x) (((x) + 15) & ~15u)
#define DATA_B   (BUF + PAD16(file_hdr))           /* the data (bytes)           */
#define DATA_W   (buf_w + PAD16(file_hdr) / 4)     /* the data (words, hardware) */

static uint8_t  key[32], nonce[12];
static uint32_t key_w[8], nonce_w[3];

static char     in_name[YM_MAX_NAME + 1];
static char     out_name[YM_MAX_NAME + 16], hex_name[YM_MAX_NAME + 24];
static uint32_t file_hdr;                /* header bytes kept in clear (BMP), else 0   */
static uint32_t file_len;                /* data bytes (encrypted part)                */
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

static void print_summary(const char *what, meas_t ch_sw, meas_t ch_hw, meas_t po_sw, meas_t po_hw) {
  meas_t all_sw = ch_sw, all_hw = ch_hw;
  meas_add(&all_sw, po_sw);
  meas_add(&all_hw, po_hw);
  neorv32_uart0_printf("\nSUMMARY - %s, %u bytes encrypted", what, file_len);
  if (file_hdr) neorv32_uart0_printf(" + %u-byte header (AAD)", file_hdr);
  neorv32_uart0_printf(", one run, %u MHz CPU (time = 1 us counter)\n", neorv32_sysinfo_get_clk() / 1000000);
  neorv32_uart0_printf("              ------- Software --------  ------- Hardware -------\n");
  neorv32_uart0_printf("                 total time      cycles     total time     cycles  Speedup\n");
  summary_row("ChaCha20  ", ch_sw, ch_hw);
  summary_row("Poly1305  ", po_sw, po_hw);
  neorv32_uart0_printf("  -----------------------------------------------------------------------\n");
  summary_row("TOTAL     ", all_sw, all_hw);
}

static void print_tag(const char *label, const uint8_t *t) {
  neorv32_uart0_printf("%s", label);
  print_hex(t, 16);
  neorv32_uart0_printf("\n");
}

/* ---------------------------------------------------------------------------
 * header (BMP) and the buffer layout
 * ------------------------------------------------------------------------- */
/* BMP picture? Its header = everything before the pixels; the pixel offset is the 32-bit
   little-endian number in bytes 10..13. Returns the header length, 0 = not a BMP. */
static uint32_t bmp_header_len(uint32_t n) {
  if (n < 26 || BUF[0] != 'B' || BUF[1] != 'M') return 0;
  uint32_t off = BUF[10] | ((uint32_t)BUF[11] << 8) | ((uint32_t)BUF[12] << 16) | ((uint32_t)BUF[13] << 24);
  return (off >= 26 && off < n) ? off : 0;
}

/* the file (header | data) arrived at the start of BUF: move the data up to a multiple of 16
   after the header and put zeros in the gap (the MAC input layout above) */
static void place_data(uint32_t n) {
  file_hdr = bmp_header_len(n);
  file_len = n - file_hdr;
  memmove(DATA_B, BUF + file_hdr, file_len);
  memset(BUF + file_hdr, 0, PAD16(file_hdr) - file_hdr);
  if (file_hdr) {
    neorv32_uart0_printf("BMP picture: the %u-byte header stays in clear (protected by the tag),\n", file_hdr);
    neorv32_uart0_printf("the %u bytes of pixels are encrypted / decrypted.\n", file_len);
  } else {
    neorv32_uart0_printf("Not a BMP picture: the whole file (%u bytes) is encrypted / decrypted.\n", file_len);
  }
}

/* finish the MAC input after the data: zeros to a multiple of 16, then len(AAD) = header
   length and len(ciphertext) = data length as 8-byte little-endian numbers. Returns its length. */
static uint32_t build_mac_input(void) {
  uint32_t m = PAD16(file_hdr) + file_len;
  while (m % 16) BUF[m++] = 0;
  buf_w[m / 4]     = file_hdr;   /* AAD length */
  buf_w[m / 4 + 1] = 0;
  buf_w[m / 4 + 2] = file_len;   /* ciphertext length */
  buf_w[m / 4 + 3] = 0;
  return m + 16;
}

/* ---------------------------------------------------------------------------
 * files for YMODEM "send": the encrypted file, its hex text, the decrypted file
 * ------------------------------------------------------------------------- */
static uint8_t file_byte(uint32_t k) {           /* byte k of header | data (data after the gap) */
  return (k < file_hdr) ? BUF[k] : DATA_B[k - file_hdr];
}

static uint8_t enc_byte(uint32_t k) {            /* byte k of header | ciphertext | tag */
  uint32_t n = file_hdr + file_len;
  return (k < n) ? file_byte(k) : tag_out[k - n];
}

static void read_enc(uint32_t off, uint8_t *dst, uint32_t len) {
  for (uint32_t i = 0; i < len; i++) dst[i] = enc_byte(off + i);
}

/* hex text: 32 bytes = 64 hex characters + CR LF per line */
static uint32_t hex_size(uint32_t m) {
  return (m / 32) * 66 + ((m % 32) ? (m % 32) * 2 + 2 : 0);
}

static void read_hex(uint32_t off, uint8_t *dst, uint32_t len) {
  static const char HX[] = "0123456789abcdef";
  uint32_t m = file_hdr + file_len + 16, full = m / 32;
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

static void read_plain(uint32_t off, uint8_t *dst, uint32_t len) {        /* header | decrypted data */
  for (uint32_t i = 0; i < len; i++) dst[i] = file_byte(off + i);
}

/* name ends with this text? (letters compared without case: ".BMP" = ".bmp") */
static int ends_with(const char *s, const char *end) {
  uint32_t a = strlen(s), b = strlen(end);
  if (a < b) return 0;
  for (uint32_t i = 0; i < b; i++) {
    char c = s[a - b + i];
    if (c >= 'A' && c <= 'Z') c += 32;
    if (c != end[i]) return 0;
  }
  return 1;
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

/* ---------------------------------------------------------------------------
 * hardware steps (wrapped once: the drivers in crypto_accel.h are inline and fully unrolled,
 * so their code exists only once in this big program)
 * ------------------------------------------------------------------------- */
/* one-time Poly1305 key = first 32 bytes of ChaCha20 block 0 (also loads key + nonce) */
static __attribute__((noinline)) void one_time_key_hw(uint32_t otk_w[8]) {
  static uint32_t zero[16];
  uint32_t blk0[16];
  chacha20_hw_set_key(key_w, nonce_w);
  chacha20_hw_block_fast(0, zero, blk0);
  for (int i = 0; i < 8; i++) otk_w[i] = blk0[i];
}

static __attribute__((noinline)) void chacha_hw(void) {     /* the data in place, counter 1, 2, ... */
  chacha20_hw_set_key(key_w, nonce_w);
  chacha20_hw_crypt(1, DATA_W, DATA_W, file_len);
}

static __attribute__((noinline)) void poly_hw1(const uint32_t k[8], uint32_t n, uint32_t t[4]) {
  poly1305_hw_mac(k, buf_w, n, t);
}

/* fingerprint of the buffer for the checks (not timed): hardware tag of the current MAC input */
static void fingerprint(const uint32_t otk_w[8], uint32_t t[4]) {
  poly_hw1(otk_w, build_mac_input(), t);
}

static int same16(const void *a, const void *b) { return memcmp(a, b, 16) == 0; }

/* ---------------------------------------------------------------------------
 * 1) encrypt
 * ------------------------------------------------------------------------- */
static void encrypt_file(void) {
  uint8_t  otk_sw[64], tag_sw[16];
  uint32_t otk_hw[8], tag_hw[4], fp_plain[4], fp_back[4];
  bench_timer_t t;
  meas_t ch_sw, ch_hw, po_sw, po_hw;

  uint32_t n = get_file("file to ENCRYPT", MAX_FILE);
  if (n == 0) return;
  place_data(n);
  neorv32_uart0_printf("Encrypting in software and in hardware (the software needs a few seconds)...\n");

  /* one-time Poly1305 key (ChaCha20 block 0) + fingerprint of the original data */
  chacha20_block(key, nonce, 0, otk_sw);
  one_time_key_hw(otk_hw);
  int otk_ok = (memcmp(otk_sw, otk_hw, 32) == 0);
  fingerprint(otk_hw, fp_plain);

  /* software: ChaCha20 (in place), then the Poly1305 tag */
  leds(LED_SW); bench_start(&t);
  chacha20_sw_crypt(key, nonce, 1, DATA_B, DATA_B, file_len);
  ch_sw = bench_stop(&t);
  uint32_t mac_len = build_mac_input();
  bench_start(&t); poly1305_mac(otk_sw, BUF, mac_len, tag_sw); po_sw = bench_stop(&t);

  /* back to the original with the hardware (not timed): checks that the hardware
     keystream is the software keystream */
  chacha_hw();
  fingerprint(otk_hw, fp_back);
  int ch_ok = same16(fp_back, fp_plain);

  /* hardware: ChaCha20 (in place) = the encrypted file that is sent back, then the tag */
  leds(LED_HW); bench_start(&t);
  chacha_hw();
  ch_hw = bench_stop(&t);
  mac_len = build_mac_input();
  bench_start(&t); poly_hw1(otk_hw, mac_len, tag_hw); po_hw = bench_stop(&t);
  int po_ok = otk_ok && same16(tag_sw, tag_hw);
  memcpy(tag_out, tag_hw, 16);
  leds(LED_IDLE);

  int ok = ch_ok && po_ok;
  neorv32_uart0_printf("\nENCRYPTION FINISHED (key \"%s\", nonce \"%s\")\n", FILE_KEY, FILE_NONCE);
  print_tag("Poly1305 tag (SW): ", tag_sw);
  print_tag("Poly1305 tag (HW): ", (const uint8_t *)tag_hw);
  neorv32_uart0_printf("Checks: ciphertext SW == HW %s | tag SW == HW %s\n", pass_fail(ch_ok), pass_fail(po_ok));
  neorv32_uart0_printf("(software and hardware give exactly the same encrypted file, so one file is sent)\n");
  print_summary("ENCRYPTION", ch_sw, ch_hw, po_sw, po_hw);
  neorv32_uart0_printf(ok ? "ALL CHECKS PASSED\n" : "*** SOME CHECKS FAILED ***\n");
  leds(ok ? LED_PASS : LED_FAIL);
  if (!ok) return;

  /* names: "x.bmp" -> "x.enc.bmp" (still a picture), other files "x" -> "x.enc" */
  strcpy(out_name, in_name);
  if (file_hdr) {
    if (ends_with(out_name, ".bmp")) out_name[strlen(out_name) - 4] = 0;
    strcat(out_name, ".enc.bmp");
  } else {
    strcat(out_name, ".enc");
  }
  strcpy(hex_name, out_name); strcat(hex_name, ".hex.txt");
  uint32_t total = file_hdr + file_len + 16;
  ym_file_t files[2] = {
    { out_name, total, read_enc },
    { hex_name, hex_size(total), read_hex },
  };
  put_files(files, 2);
}

/* ---------------------------------------------------------------------------
 * 2) decrypt
 * ------------------------------------------------------------------------- */
static void decrypt_file(void) {
  uint8_t  tag_rx[16], otk_sw[64], tag_sw[16];
  uint32_t otk_hw[8], tag_hw[4], fp_back[4], fp_pt_sw[4], fp_pt_hw[4];
  uint32_t diff = 0;
  bench_timer_t t;
  meas_t po_sw, po_hw, ch_sw, ch_hw;

  uint32_t n = get_file("ENCRYPTED file (the .enc or .enc.bmp file)", MAX_FILE + 16);
  if (n == 0) return;
  if (n < 16) {
    neorv32_uart0_printf("Too short: an encrypted file has at least the 16-byte tag.\n");
    return;
  }
  n -= 16;                                       /* header + ciphertext */
  memcpy(tag_rx, BUF + n, 16);
  place_data(n);
  neorv32_uart0_printf("Checking and decrypting in software and in hardware...\n");

  /* 1) the tag first (software and hardware) */
  chacha20_block(key, nonce, 0, otk_sw);
  one_time_key_hw(otk_hw);
  uint32_t mac_len = build_mac_input();
  leds(LED_SW); bench_start(&t); poly1305_mac(otk_sw, BUF, mac_len, tag_sw); po_sw = bench_stop(&t);
  leds(LED_HW); bench_start(&t); poly_hw1(otk_hw, mac_len, tag_hw);          po_hw = bench_stop(&t);
  leds(LED_IDLE);
  for (int i = 0; i < 16; i++) diff |= ((const uint8_t *)tag_hw)[i] ^ tag_rx[i];
  int po_ok = same16(tag_sw, tag_hw);

  print_tag("\nReceived tag:          ", tag_rx);
  print_tag("Recomputed tag (SW):   ", tag_sw);
  print_tag("Recomputed tag (HW):   ", (const uint8_t *)tag_hw);
  if (diff || !po_ok) {
    neorv32_uart0_printf("REJECTED: the tag is wrong (file changed, or wrong key/nonce). Nothing was decrypted.\n");
    neorv32_uart0_printf("(tag check: software %u us, hardware %u us)\n", po_sw.us, po_hw.us);
    leds(LED_FAIL);
    return;
  }
  neorv32_uart0_printf("Tag OK: the file was not changed.\n");

  /* 2) software decryption (in place) */
  leds(LED_SW); bench_start(&t);
  chacha20_sw_crypt(key, nonce, 1, DATA_B, DATA_B, file_len);
  ch_sw = bench_stop(&t);
  fingerprint(otk_hw, fp_pt_sw);                 /* fingerprint of the software result */
  /* back to the ciphertext with the hardware (not timed): its tag must be the received tag */
  chacha_hw();
  fingerprint(otk_hw, fp_back);
  /* 3) hardware decryption (in place) = the decrypted file that is sent back */
  leds(LED_HW); bench_start(&t);
  chacha_hw();
  ch_hw = bench_stop(&t);
  leds(LED_IDLE);
  fingerprint(otk_hw, fp_pt_hw);
  int ch_ok = same16(fp_back, tag_rx) && same16(fp_pt_sw, fp_pt_hw);

  int ok = po_ok && ch_ok;
  neorv32_uart0_printf("\nDECRYPTION FINISHED\n");
  neorv32_uart0_printf("Checks: tag SW == HW %s | decrypted file SW == HW %s\n", pass_fail(po_ok), pass_fail(ch_ok));
  print_summary("DECRYPTION", ch_sw, ch_hw, po_sw, po_hw);
  neorv32_uart0_printf(ok ? "ALL CHECKS PASSED\n" : "*** SOME CHECKS FAILED ***\n");
  leds(ok ? LED_PASS : LED_FAIL);
  if (!ok) return;

  /* names: "x.enc.bmp" -> "decrypted_x.bmp", "x.enc" -> "decrypted_x" */
  strcpy(out_name, "decrypted_");
  strcat(out_name, in_name);
  if (ends_with(out_name, ".enc.bmp"))  strcpy(out_name + strlen(out_name) - 8, ".bmp");
  else if (ends_with(out_name, ".enc")) out_name[strlen(out_name) - 4] = 0;
  ym_file_t files[1] = { { out_name, file_hdr + file_len, read_plain } };
  put_files(files, 1);
}

int main(void) {
  neorv32_rte_setup();
  neorv32_uart0_setup(BAUD_RATE, 0);
  neorv32_gpio_dir_set(0xFF);
  leds(LED_IDLE);
  memcpy(key, FILE_KEY, 32);     memcpy(key_w, key, 32);
  memcpy(nonce, FILE_NONCE, 12); memcpy(nonce_w, nonce, 12);

  demo_banner("FILE CRYPTO - encrypt / decrypt a picture or any file (ChaCha20-Poly1305)");
  neorv32_uart0_printf("\nFiles are big, so this program uses %u baud.\n", (uint32_t)FILE_BAUD);
  neorv32_uart0_printf("Set Tera Term to %u now (Setup > Serial port > Speed), then press any key.\n", (uint32_t)FILE_BAUD);
  neorv32_uart0_printf("(Afterwards: press BTN0 and set Tera Term back to 19200 for the bootloader.)\n");
  while (neorv32_uart0_tx_busy());
  neorv32_uart0_setup(FILE_BAUD, 0);
  flush_rx();
  (void)neorv32_uart0_getc();

  while (1) {
    neorv32_uart0_printf("\n=== FILE CRYPTO (%u baud) ===\n", (uint32_t)FILE_BAUD);
    neorv32_uart0_printf("Key: \"%s\"   Nonce: \"%s\"   (ChaCha20-Poly1305, RFC 8439)\n", FILE_KEY, FILE_NONCE);
    neorv32_uart0_printf("BMP pictures: the header stays in clear (AAD), only the pixels are encrypted.\n");
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
