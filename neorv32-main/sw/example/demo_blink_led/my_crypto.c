/*
 * my_crypto.c  -  YOUR OWN TEST: edit the values below, build, upload, check online
 *
 * 1) Edit MY_MESSAGE / MY_KEY / MY_NONCE / MY_COUNTER / MY_POLY_KEY below.
 * 2) Build: in a terminal in this folder type   make APP=my_crypto clean exe
 *    -> creates neorv32_exe.bin in this folder.
 * 3) Upload neorv32_exe.bin with Tera Term (bootloader: u, send file as binary, e).
 *
 * The board computes ChaCha20, Poly1305 and Keccak-256 once in software and once
 * in hardware and prints all inputs and results in hex, so you can check them:
 *   - ChaCha20: CyberChef "ChaCha" (key/nonce as UTF8 text, counter = MY_COUNTER, 20 rounds)
 *   - Keccak-256: emn178.github.io/online-tools/keccak_256.html (input: the message)
 *   - SHA3-256 is also printed (software only) to show why a "SHA3-256" tool gives
 *     a different hash: same Keccak, only the padding byte differs (0x06 instead of 0x01).
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
/* =================================================================== */

/* the build stops here with a clear message if a length is wrong */
_Static_assert(sizeof(MY_MESSAGE) - 1 >= 1 && sizeof(MY_MESSAGE) - 1 <= 64, "MY_MESSAGE must be 1..64 characters");
_Static_assert(sizeof(MY_KEY) - 1 == 32, "MY_KEY must be exactly 32 characters");
_Static_assert(sizeof(MY_NONCE) - 1 == 12, "MY_NONCE must be exactly 12 characters");
_Static_assert(sizeof(MY_POLY_KEY) - 1 == 32, "MY_POLY_KEY must be exactly 32 characters");

#define MSG_LEN (sizeof(MY_MESSAGE) - 1)

/* SHA3-256 (NIST FIPS 202) = the same Keccak with padding 0x06 instead of 0x01, software only,
   printed only to show why a SHA3-256 online tool gives a different hash than Keccak-256 */
static void sha3_256_compare(const uint8_t *msg, uint32_t len, uint8_t digest[32]) {
  uint64_t A[25];
  uint8_t  block[136];
  memset(A, 0, sizeof A);
  memset(block, 0, sizeof block);
  memcpy(block, msg, len);                 /* len <= 64 < 136: one block */
  block[len] ^= 0x06;                      /* Keccak-256 puts 0x01 here */
  block[135] ^= 0x80;
  for (int i = 0; i < 17; i++) {
    uint64_t w = 0;
    for (int b = 7; b >= 0; b--) w = (w << 8) | block[8 * i + b];
    A[i] ^= w;
  }
  keccak_f1600(A);                         /* the same Keccak permutation */
  for (int i = 0; i < 32; i++) digest[i] = (uint8_t)(A[i / 8] >> (8 * (i % 8)));
}

static uint32_t t_us, t_cyc;               /* time of the last measured operation */
#define MEASURE(code) do { uint32_t u0 = US_COUNTER, c0 = neorv32_cpu_csr_read(CSR_MCYCLE); code; \
                           t_cyc = neorv32_cpu_csr_read(CSR_MCYCLE) - c0; t_us = US_COUNTER - u0; } while (0)

static void line(const char *name, const uint8_t *p, uint32_t n) {
  neorv32_uart0_printf("  %s", name);
  print_hex(p, n);
  neorv32_uart0_printf("   %u cycles (%u us)\n", t_cyc, t_us);
}

int main(void) {
  static uint8_t  key[32], nonce[12], pkey[32], msg[64];
  static uint32_t key_w[8], nonce_w[3], pkey_w[8], msg_w[16], ct_w[16], back_w[16], tag_w[4], dig_w[8];
  static uint8_t  ct[64], tag[16], dig[32];

  neorv32_rte_setup();
  neorv32_uart0_setup(BAUD_RATE, 0);
  neorv32_gpio_dir_set(0xFF);

  memcpy(key, MY_KEY, 32);       memcpy(key_w, key, 32);
  memcpy(nonce, MY_NONCE, 12);   memcpy(nonce_w, nonce, 12);
  memcpy(pkey, MY_POLY_KEY, 32); memcpy(pkey_w, pkey, 32);
  memset(msg, 0, 64);            memcpy(msg, MY_MESSAGE, MSG_LEN);
  memcpy(msg_w, msg, 64);

  while (1) {
    int ok = 1;
    leds(LED_IDLE);
    demo_banner("MY CRYPTO TEST - your own inputs (edit my_crypto.c)");

    neorv32_uart0_printf("\nInputs\n");
    neorv32_uart0_printf("  Message:        "); print_text(msg, MSG_LEN);
    neorv32_uart0_printf("  (%u bytes)\n                  ", (uint32_t)MSG_LEN); print_hex(msg, MSG_LEN);
    neorv32_uart0_printf("\n  ChaCha20 key:   "); print_text(key, 32);
    neorv32_uart0_printf("\n                  "); print_hex(key, 32);
    neorv32_uart0_printf("\n  ChaCha20 nonce: "); print_text(nonce, 12);
    neorv32_uart0_printf("  = "); print_hex(nonce, 12);
    neorv32_uart0_printf("\n  Counter:        %u\n", (uint32_t)MY_COUNTER);
    neorv32_uart0_printf("  Poly1305 key:   "); print_text(pkey, 32);
    neorv32_uart0_printf("\n                  "); print_hex(pkey, 32);
    neorv32_uart0_printf("\n");

    /* ChaCha20 */
    neorv32_uart0_printf("\n[ChaCha20] ciphertext = message XOR keystream(key, nonce, counter)\n");
    leds(LED_SW);
    MEASURE(chacha20_sw_encrypt(key, nonce, MY_COUNTER, msg, ct));
    line("Software: ", ct, MSG_LEN);
    leds(LED_HW);
    MEASURE(chacha20_hw_block(key_w, nonce_w, MY_COUNTER, msg_w, ct_w));
    line("Hardware: ", (const uint8_t *)ct_w, MSG_LEN);
    chacha20_hw_block(key_w, nonce_w, MY_COUNTER, ct_w, back_w);     /* decrypt = encrypt again */
    int ch_ok = (memcmp(ct, ct_w, MSG_LEN) == 0) && (memcmp(back_w, msg, MSG_LEN) == 0);
    neorv32_uart0_printf("  Decrypted by hardware: "); print_text((const uint8_t *)back_w, MSG_LEN);
    neorv32_uart0_printf("\n  %s\n", ch_ok ? "PASS: software == hardware, decryption gives the message back" : "FAIL");
    ok &= ch_ok;

    /* Poly1305 over the ciphertext */
    neorv32_uart0_printf("\n[Poly1305] tag of the ciphertext (Encrypt + MAC)\n");
    leds(LED_SW);
    MEASURE(poly1305_mac(pkey, ct, MSG_LEN, tag));
    line("Software: ", tag, 16);
    leds(LED_HW);
    MEASURE(poly1305_hw_mac(pkey_w, ct_w, MSG_LEN, tag_w));
    line("Hardware: ", (const uint8_t *)tag_w, 16);
    int po_ok = (memcmp(tag, tag_w, 16) == 0);
    neorv32_uart0_printf("  %s\n", po_ok ? "PASS: software == hardware" : "FAIL");
    ok &= po_ok;

    /* Keccak-256 of the message */
    neorv32_uart0_printf("\n[Keccak-256] hash of the message (original Keccak, padding 0x01)\n");
    leds(LED_SW);
    MEASURE(keccak256(msg, MSG_LEN, dig));
    line("Software: ", dig, 32);
    leds(LED_HW);
    MEASURE(keccak256_hw(msg_w, MSG_LEN, dig_w));
    line("Hardware: ", (const uint8_t *)dig_w, 32);
    int ke_ok = (memcmp(dig, dig_w, 32) == 0);
    neorv32_uart0_printf("  %s\n", ke_ok ? "PASS: software == hardware" : "FAIL");
    ok &= ke_ok;

    neorv32_uart0_printf("\n[SHA3-256, padding 0x06 - software only, for comparison]\n");
    MEASURE(sha3_256_compare(msg, MSG_LEN, dig));
    line("Software: ", dig, 32);
    neorv32_uart0_printf("  Same Keccak-f[1600] rounds as Keccak-256, only the padding byte differs,\n");
    neorv32_uart0_printf("  so a \"SHA3-256\" online tool gives this value, a \"Keccak-256\" tool the one above.\n");

    neorv32_uart0_printf(ok ? "\nALL CHECKS PASSED\n" : "\n*** SOME CHECKS FAILED ***\n");
    leds(ok ? LED_PASS : LED_FAIL);
    wait_for_key();
  }
  return 0;
}
