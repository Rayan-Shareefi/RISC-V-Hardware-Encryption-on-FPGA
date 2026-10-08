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
 * 3) Send the file with Tera Term: File > Send file > tick "Binary". The end of the file is
 *    detected when nothing arrives for 1 second.
 *
 * Encrypt: ChaCha20-Poly1305 (RFC 8439, no AAD) with FILE_KEY / FILE_NONCE below, and the
 *   Keccak-256 hash of the file. Every step runs in software AND in hardware on the same file
 *   (one run each) and the SUMMARY shows both times and the speedup. Output: the encrypted file
 *   = ciphertext followed by the 16-byte tag, in hex between BEGIN/END lines.
 *   (Only one copy of a 120 KB file fits in memory, so for ChaCha20 the software encrypts the
 *    file in place and the hardware decrypts it back; the file must come back unchanged, which
 *    is checked with its Keccak-256 hash. Then the hardware encrypts it again for the output.)
 * Decrypt: send the encrypted file (ciphertext + tag). The tag is checked first; if it is
 *   wrong, nothing is decrypted (REJECTED). Otherwise the decrypted file is printed in hex
 *   between BEGIN/END lines, with its Keccak-256 hash (equal to the hash of the original).
 *
 * See the picture again: CyberChef  From Hex -> Render Image  (demo/HOW_TO_RUN.md).
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
#define FILE_KEY     "my 32-byte secret key 4 ChaCha20"   /* exactly 32 characters */
#define FILE_NONCE   "unique nonce"                        /* exactly 12 characters */
/* =================================================================== */
_Static_assert(sizeof(FILE_KEY) - 1 == 32, "FILE_KEY must be exactly 32 characters");
_Static_assert(sizeof(FILE_NONCE) - 1 == 12, "FILE_NONCE must be exactly 12 characters");

#define FILE_BAUD    115200
#define MAX_FILE     (120 * 1024)        /* largest file in bytes                    */
#define END_IDLE_US  1000000             /* end of file: no byte for 1 second        */
#define START_WAIT_S 120                 /* give up if no file arrives within 120 s  */

/* the file + room for the Poly1305 padding and the two lengths (MAC input in place) */
static uint32_t buf_w[(MAX_FILE + 16 + 16 + 16) / 4];
#define BUF ((uint8_t *)buf_w)

static uint8_t  key[32], nonce[12];
static uint32_t key_w[8], nonce_w[3];

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

/* the file in hex, 32 bytes (64 characters) per line, no spaces: ready for CyberChef */
static void hex_block(const char *what, const uint8_t *p, uint32_t n, const uint8_t *tail, uint32_t tn) {
  static const char HX[] = "0123456789abcdef";
  uint32_t col = 0;
  neorv32_uart0_printf("-----BEGIN %s-----\n", what);
  for (uint32_t i = 0; i < n + tn; i++) {
    uint8_t b = (i < n) ? p[i] : tail[i - n];
    neorv32_uart0_putc(HX[b >> 4]);
    neorv32_uart0_putc(HX[b & 15]);
    if (++col == 32) { neorv32_uart0_putc('\n'); col = 0; }
  }
  if (col) neorv32_uart0_putc('\n');
  neorv32_uart0_printf("-----END %s-----\n", what);
}

static void print_digest(const char *label, const uint8_t *d) {
  neorv32_uart0_printf("%s", label);
  print_hex(d, 32);
  neorv32_uart0_printf("\n");
}

/* ---------------------------------------------------------------------------
 * receiving a file (nothing else may run here: at 115200 a byte arrives every 87 us)
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

/* returns the number of bytes received (> max: the file was too big), 0 = nothing came */
static uint32_t receive_file(uint8_t *dst, uint32_t max) {
  uint32_t n = 0, t0 = US_COUNTER, last;
  while (!neorv32_uart0_char_received()) {       /* wait for the first byte */
    if (US_COUNTER - t0 > START_WAIT_S * 1000000u) return 0;
  }
  last = US_COUNTER;
  while (1) {
    if (neorv32_uart0_char_received()) {
      uint8_t c = (uint8_t)neorv32_uart0_char_received_get();
      if (n < max) dst[n] = c;
      n++;
      last = US_COUNTER;
      if ((n & 1023) == 0) leds((n & 2048) ? LED_HW : LED_SW);   /* LD1/LD2 blink while receiving */
    } else if (US_COUNTER - last > END_IDLE_US) {
      break;                                     /* 1 s without a byte: end of the file */
    }
  }
  leds(LED_IDLE);
  return n;
}

static uint32_t ask_for_file(const char *what, uint32_t max) {
  neorv32_uart0_printf("\nSend the %s now: Tera Term  File > Send file > tick \"Binary\" > choose the file.\n", what);
  neorv32_uart0_printf("(largest %u bytes; the end is detected 1 s after the last byte)\n", max);
  while (neorv32_uart0_tx_busy());
  flush_rx();
  uint32_t n = receive_file(BUF, max);
  if (n == 0) {
    neorv32_uart0_printf("No file arrived within %u s.\n", (uint32_t)START_WAIT_S);
  } else if (n > max) {
    neorv32_uart0_printf("The file is too big: %u bytes (largest %u). Nothing was done.\n", n, max);
    n = 0;
  } else {
    neorv32_uart0_printf("Received %u bytes.\n", n);
  }
  return n;
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
static void one_time_key_hw(uint32_t otk_w[8]) {
  static uint32_t zero[16];
  uint32_t blk0[16];
  chacha20_hw_set_key(key_w, nonce_w);
  chacha20_hw_block_fast(0, zero, blk0);
  for (int i = 0; i < 8; i++) otk_w[i] = blk0[i];
}

/* ---------------------------------------------------------------------------
 * 1) encrypt
 * ------------------------------------------------------------------------- */
static void encrypt_file(void) {
  uint8_t  dig_sw[32], otk_sw[64], tag_sw[16];
  uint32_t dig_hw[8], dig_chk[8], otk_hw[8], tag_hw[4];
  bench_timer_t t;
  meas_t ke_sw, ke_hw, ch_sw, ch_hw, po_sw, po_hw;

  uint32_t n = ask_for_file("file to ENCRYPT", MAX_FILE);
  if (n == 0) return;
  neorv32_uart0_printf("Working: software and hardware on the whole file (the software needs a few seconds)...\n");

  /* Keccak-256 of the original file */
  leds(LED_SW); bench_start(&t); keccak256(BUF, n, dig_sw);          ke_sw = bench_stop(&t);
  leds(LED_HW); bench_start(&t); keccak256_hw(buf_w, n, dig_hw);     ke_hw = bench_stop(&t);
  int ke_ok = (memcmp(dig_sw, dig_hw, 32) == 0);

  /* one-time Poly1305 key (ChaCha20 block 0) in software and hardware */
  chacha20_block(key, nonce, 0, otk_sw);
  one_time_key_hw(otk_hw);
  int otk_ok = (memcmp(otk_sw, otk_hw, 32) == 0);

  /* ChaCha20: software encrypts in place, hardware decrypts back in place */
  leds(LED_SW); bench_start(&t);
  chacha20_sw_crypt(key, nonce, 1, BUF, BUF, n);
  ch_sw = bench_stop(&t);
  leds(LED_HW); bench_start(&t);
  chacha20_hw_set_key(key_w, nonce_w);
  chacha20_hw_crypt(1, buf_w, buf_w, n);
  ch_hw = bench_stop(&t);
  keccak256_hw(buf_w, n, dig_chk);                 /* the file must be back unchanged */
  int ch_ok = (memcmp(dig_chk, dig_hw, 32) == 0);

  /* the real encryption for the output (hardware, not timed) */
  chacha20_hw_crypt(1, buf_w, buf_w, n);
  uint32_t mac_len = build_mac_input(n);

  /* Poly1305 tag of the ciphertext (+ padding + lengths) */
  leds(LED_SW); bench_start(&t); poly1305_mac(otk_sw, BUF, mac_len, tag_sw);  po_sw = bench_stop(&t);
  leds(LED_HW); bench_start(&t); poly1305_hw_mac(otk_hw, buf_w, mac_len, tag_hw); po_hw = bench_stop(&t);
  int po_ok = otk_ok && (memcmp(tag_sw, tag_hw, 16) == 0);
  leds(LED_IDLE);

  meas_t all_sw = ch_sw, all_hw = ch_hw;
  meas_add(&all_sw, po_sw);  meas_add(&all_sw, ke_sw);
  meas_add(&all_hw, po_hw);  meas_add(&all_hw, ke_hw);

  neorv32_uart0_printf("\nFile: %u bytes   (ChaCha20: %u blocks of 64 B, Poly1305: %u bytes of MAC input, Keccak: %u blocks of 136 B)\n",
                       n, (n + 63) / 64, mac_len, n / 136 + 1);
  print_digest("Keccak-256 of the original file:  ", (const uint8_t *)dig_hw);
  neorv32_uart0_printf("Checks: Keccak SW == HW %s | ChaCha20 SW encrypt + HW decrypt gives the file back %s | Poly1305 SW == HW %s\n",
                       pass_fail(ke_ok), pass_fail(ch_ok), pass_fail(po_ok));

  neorv32_uart0_printf("\nSUMMARY - one run on your %u-byte file, %u MHz CPU (time = 1 us counter)\n",
                       n, neorv32_sysinfo_get_clk() / 1000000);
  neorv32_uart0_printf("              ------- Software --------  ------- Hardware -------\n");
  neorv32_uart0_printf("                 total time      cycles     total time     cycles  Speedup\n");
  summary_row("ChaCha20  ", ch_sw, ch_hw);
  summary_row("Poly1305  ", po_sw, po_hw);
  summary_row("Keccak-256", ke_sw, ke_hw);
  neorv32_uart0_printf("  -----------------------------------------------------------------------\n");
  summary_row("TOTAL     ", all_sw, all_hw);

  neorv32_uart0_printf("\nPoly1305 tag: ");
  print_hex((const uint8_t *)tag_hw, 16);
  neorv32_uart0_printf("\nEncrypted file = ciphertext (%u bytes) + tag (16 bytes) = %u bytes:\n", n, n + 16);
  hex_block("ENCRYPTED FILE", BUF, n, (const uint8_t *)tag_hw, 16);
  int ok = ke_ok && ch_ok && po_ok;
  neorv32_uart0_printf(ok ? "ALL CHECKS PASSED\n" : "*** SOME CHECKS FAILED ***\n");
  leds(ok ? LED_PASS : LED_FAIL);
}

/* ---------------------------------------------------------------------------
 * 2) decrypt
 * ------------------------------------------------------------------------- */
static void decrypt_file(void) {
  uint8_t  tag_rx[16];
  uint32_t otk_hw[8], tag_hw[4], dig_hw[8], diff = 0;
  bench_timer_t t;
  meas_t po_hw, ch_hw, ke_hw;

  uint32_t n = ask_for_file("ENCRYPTED file (ciphertext + 16-byte tag)", MAX_FILE + 16);
  if (n == 0) return;
  if (n < 16) {
    neorv32_uart0_printf("Too short: an encrypted file has at least the 16-byte tag.\n");
    return;
  }
  n -= 16;                                       /* n = ciphertext length */
  memcpy(tag_rx, BUF + n, 16);

  /* check the tag first */
  one_time_key_hw(otk_hw);
  uint32_t mac_len = build_mac_input(n);
  bench_start(&t); poly1305_hw_mac(otk_hw, buf_w, mac_len, tag_hw); po_hw = bench_stop(&t);
  for (int i = 0; i < 16; i++) diff |= ((const uint8_t *)tag_hw)[i] ^ tag_rx[i];

  neorv32_uart0_printf("\nCiphertext: %u bytes\nReceived tag:   ", n);
  print_hex(tag_rx, 16);
  neorv32_uart0_printf("\nRecomputed tag: ");
  print_hex((const uint8_t *)tag_hw, 16);
  neorv32_uart0_printf("   (hardware: %u us, %u cycles)\n", po_hw.us, po_hw.cycles);
  if (diff) {
    neorv32_uart0_printf("REJECTED: the tag is wrong (file changed, or wrong key/nonce). Nothing was decrypted.\n");
    leds(LED_FAIL);
    return;
  }
  neorv32_uart0_printf("Tag OK: the file was not changed.\n");

  /* decrypt + hash */
  bench_start(&t);
  chacha20_hw_set_key(key_w, nonce_w);
  chacha20_hw_crypt(1, buf_w, buf_w, n);
  ch_hw = bench_stop(&t);
  bench_start(&t); keccak256_hw(buf_w, n, dig_hw); ke_hw = bench_stop(&t);
  neorv32_uart0_printf("Decrypted in hardware: %u us, %u cycles\n", ch_hw.us, ch_hw.cycles);
  print_digest("Keccak-256 of the decrypted file: ", (const uint8_t *)dig_hw);
  neorv32_uart0_printf("(must equal the hash printed when the file was encrypted; %u us in hardware)\n", ke_hw.us);
  hex_block("DECRYPTED FILE", BUF, n, 0, 0);
  neorv32_uart0_printf("DECRYPTION DONE\n");
  leds(LED_PASS);
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
    neorv32_uart0_printf("Key:   \"%s\"   Nonce: \"%s\"   (ChaCha20-Poly1305, RFC 8439, no AAD)\n", FILE_KEY, FILE_NONCE);
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
