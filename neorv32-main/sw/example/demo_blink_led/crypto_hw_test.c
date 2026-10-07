/*
 * crypto_hw_test.c  -  test all crypto hardware units on the RISC-V
 * (was chacha20_hw_test.c in Phase 3; Poly1305 added in Phase 7)
 *
 * 1) ChaCha20: encrypts 4 blocks with the custom instructions and compares
 *    with the expected ciphertext (RFC 8439 test vectors + the project-1 test,
 *    the same 4 tests as hw/tb_crypto_accel.vhd).
 * 2) Poly1305: the RFC 8439 vectors that fit in 64 bytes and every message
 *    length 0..64 (poly1305_vectors.h, same as hw/tb_crypto_accel.vhd).
 * 3) Checks the 1 microsecond counter against the CPU cycle counter.
 *
 * Short and fast, so it is also used for the full-system simulation
 * (hw/run_system_sim.bat). Output: UART0 at 19200 baud (Tera Term, COM3).
 * Press any key to run again.
 */
#include <neorv32.h>
#include <string.h>
#include "crypto_accel.h"
#include "poly1305_vectors.h"

#define BAUD_RATE 19200

typedef struct {
  const char *name;
  uint8_t key[32];
  uint8_t nonce[12];
  uint32_t counter;
  uint8_t plaintext[64];   /* shorter text is padded with zeros */
  const uint8_t *expected; /* 64 bytes ciphertext */
} test_t;

/* expected ciphertexts (RFC 8439, cross-checked with the project-1 C chacha20_block) */
static const uint8_t EXP_RFC232[64] = {
  0x10,0xf1,0xe7,0xe4,0xd1,0x3b,0x59,0x15,0x50,0x0f,0xdd,0x1f,0xa3,0x20,0x71,0xc4,
  0xc7,0xd1,0xf4,0xc7,0x33,0xc0,0x68,0x03,0x04,0x22,0xaa,0x9a,0xc3,0xd4,0x6c,0x4e,
  0xd2,0x82,0x64,0x46,0x07,0x9f,0xaa,0x09,0x14,0xc2,0xd7,0x05,0xd9,0x8b,0x02,0xa2,
  0xb5,0x12,0x9c,0xd1,0xde,0x16,0x4e,0xb9,0xcb,0xd0,0x83,0xe8,0xa2,0x50,0x3c,0x4e
};
static const uint8_t EXP_RFC242_1[64] = {
  0x6e,0x2e,0x35,0x9a,0x25,0x68,0xf9,0x80,0x41,0xba,0x07,0x28,0xdd,0x0d,0x69,0x81,
  0xe9,0x7e,0x7a,0xec,0x1d,0x43,0x60,0xc2,0x0a,0x27,0xaf,0xcc,0xfd,0x9f,0xae,0x0b,
  0xf9,0x1b,0x65,0xc5,0x52,0x47,0x33,0xab,0x8f,0x59,0x3d,0xab,0xcd,0x62,0xb3,0x57,
  0x16,0x39,0xd6,0x24,0xe6,0x51,0x52,0xab,0x8f,0x53,0x0c,0x35,0x9f,0x08,0x61,0xd8
};
static const uint8_t EXP_RFC242_2[64] = {
  0x07,0xca,0x0d,0xbf,0x50,0x0d,0x6a,0x61,0x56,0xa3,0x8e,0x08,0x8a,0x22,0xb6,0x5e,
  0x52,0xbc,0x51,0x4d,0x16,0xcc,0xf8,0x06,0x81,0x8c,0xe9,0x1a,0xb7,0x79,0x37,0x36,
  0x5a,0xf9,0x0b,0xbf,0x74,0xa3,0x5b,0xe6,0xb4,0x0b,0x8e,0xed,0xf2,0x78,0x5e,0x42,
  0x87,0x4d,0x74,0x03,0x73,0x20,0x1a,0xa1,0x88,0xfb,0xbc,0xe8,0x39,0x91,0xc4,0xed
};
static const uint8_t EXP_PROJECT1[64] = {
  0xd7,0x62,0x8b,0xd2,0x3a,0x71,0x55,0x03,0xb8,0xd9,0xff,0x1d,0x10,0x45,0x69,0x3f,
  0xfb,0x0f,0x29,0xa0,0x48,0xe3,0x65,0x69,0x12,0xc6,0x53,0x3e,0x32,0xee,0x7a,0xed,
  0x29,0xb7,0x21,0x76,0x9c,0xe6,0x4e,0x43,0xd5,0x71,0x33,0xb0,0x74,0xd8,0x39,0xd5,
  0x31,0xed,0x1f,0x28,0x51,0x0a,0xfb,0x45,0xac,0xe1,0x0a,0x1f,0x4b,0x79,0x4d,0x6f
};

#define KEY_RFC { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f, \
                  0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f }

static const test_t tests[] = {
  { "RFC 8439 2.3.2 block function", KEY_RFC,
    {0,0,0,0x09,0,0,0,0x4a,0,0,0,0}, 1, {0}, EXP_RFC232 },
  { "RFC 8439 2.4.2 sunscreen blk 1", KEY_RFC,
    {0,0,0,0,0,0,0,0x4a,0,0,0,0}, 1,
    "Ladies and Gentlemen of the class of '99: If I could offer you o", EXP_RFC242_1 },
  { "RFC 8439 2.4.2 sunscreen blk 2", KEY_RFC,
    {0,0,0,0,0,0,0,0x4a,0,0,0,0}, 2,
    "nly one tip for the future, sunscreen would be it.", EXP_RFC242_2 },
  { "Project-1 test (Hello my chacha20)", {0},
    {0}, 1, "Hello my chacha20", EXP_PROJECT1 },
};
#define NUM_TESTS (sizeof(tests) / sizeof(tests[0]))

static void print_hex(const uint8_t *p, int n) {
  for (int i = 0; i < n; i++) {
    neorv32_uart0_printf("%c%c", "0123456789abcdef"[p[i] >> 4], "0123456789abcdef"[p[i] & 15]);
  }
  neorv32_uart0_printf("\n");
}

/* run the ChaCha20 hardware tests, return number of failures */
static int test_chacha20_hw(void) {
  int fails = 0;
  for (unsigned t = 0; t < NUM_TESTS; t++) {
    uint32_t key[8], nonce[3], in[16], out[16];
    memcpy(key, tests[t].key, 32);
    memcpy(nonce, tests[t].nonce, 12);
    memcpy(in, tests[t].plaintext, 64);

    uint32_t c0 = neorv32_cpu_csr_read(CSR_MCYCLE);
    chacha20_hw_block(key, nonce, tests[t].counter, in, out);
    uint32_t c1 = neorv32_cpu_csr_read(CSR_MCYCLE);

    if (memcmp(out, tests[t].expected, 64) == 0) {
      neorv32_uart0_printf("PASS  %s  (%u cycles)\n", tests[t].name, c1 - c0);
    } else {
      neorv32_uart0_printf("FAIL  %s\n  got:      ", tests[t].name);
      print_hex((const uint8_t *)out, 64);
      neorv32_uart0_printf("  expected: ");
      print_hex(tests[t].expected, 64);
      fails++;
    }
  }
  return fails;
}

/* compare the 1 us counter with the cycle counter over 20 ms, return 1 on failure */
static int test_us_counter(void) {
  uint32_t clk = neorv32_sysinfo_get_clk();
  uint32_t wait_cycles = clk / 50;  /* 20 ms */

  uint32_t us0 = US_COUNTER;
  uint32_t c0 = neorv32_cpu_csr_read(CSR_MCYCLE);
  while ((neorv32_cpu_csr_read(CSR_MCYCLE) - c0) < wait_cycles);
  uint32_t c1 = neorv32_cpu_csr_read(CSR_MCYCLE);
  uint32_t us1 = US_COUNTER;

  uint32_t us_hw  = us1 - us0;                       /* from the 1 us counter   */
  uint32_t us_cyc = (c1 - c0) / (clk / 1000000);     /* from the cycle counter  */
  uint32_t diff   = (us_hw > us_cyc) ? (us_hw - us_cyc) : (us_cyc - us_hw);
  int ok = (diff <= us_cyc / 100);                   /* within 1 % */

  neorv32_uart0_printf("%s  1 us counter: %u us, cycle counter: %u us\n",
                       ok ? "PASS" : "FAIL", us_hw, us_cyc);
  return !ok;
}

/* Poly1305 hardware: RFC vectors (<= 64 bytes) + every length 0..64, return number of failures */
static int test_poly1305_hw(void) {
  uint32_t key[8], msg[16], tag[4];
  uint32_t nrfc = 0, bad_rfc = 0, bad_len = 0, c64 = 0;

  for (unsigned v = 0; v < POLY_NUM_VECTORS; v++) {
    if (POLY_VECTORS[v].len > 64) continue;           /* the hardware takes up to 64 bytes */
    memcpy(key, POLY_VECTORS[v].key, 32);
    memset(msg, 0, 64);
    memcpy(msg, POLY_VECTORS[v].msg, POLY_VECTORS[v].len);
    poly1305_hw_mac(key, msg, POLY_VECTORS[v].len, tag);
    nrfc++;
    if (memcmp(tag, POLY_VECTORS[v].tag, 16) != 0) {
      neorv32_uart0_printf("FAIL  Poly1305 %s\n", POLY_VECTORS[v].name);
      bad_rfc++;
    }
  }
  neorv32_uart0_printf("%s  Poly1305 %u RFC 8439 vectors (<= 64 bytes)\n", bad_rfc ? "FAIL" : "PASS", nrfc);

  memcpy(key, POLY_VECTORS[0].key, 32);
  memcpy(msg, SWEEP_MSG, 64);
  for (uint32_t n = 0; n <= 64; n++) {
    uint32_t c0 = neorv32_cpu_csr_read(CSR_MCYCLE);
    poly1305_hw_mac(key, msg, n, tag);
    uint32_t c1 = neorv32_cpu_csr_read(CSR_MCYCLE);
    if (n == 64) c64 = c1 - c0;
    bad_len += (memcmp(tag, SWEEP_TAGS[n], 16) != 0);
  }
  neorv32_uart0_printf("%s  Poly1305 every length 0..64 bytes, %u wrong (64 bytes: %u cycles)\n",
                       bad_len ? "FAIL" : "PASS", bad_len, c64);
  return (bad_rfc != 0) + (bad_len != 0);
}

int main(void) {
  neorv32_rte_setup();
  neorv32_uart0_setup(BAUD_RATE, 0);

  neorv32_uart0_printf("\n=== Crypto hardware test (custom instructions) ===\n");

  if ((neorv32_cpu_csr_read(CSR_MXISA) & (1 << CSR_MXISA_XCFU)) == 0) {
    neorv32_uart0_printf("ERROR: CFU (custom instructions) not implemented!\n");
    return 1;
  }

  while (1) {
    int fails = test_chacha20_hw();
    fails += test_poly1305_hw();
    fails += test_us_counter();
    if (fails == 0) {
      neorv32_uart0_printf("ALL TESTS PASSED\n");
    } else {
      neorv32_uart0_printf("%u TEST(S) FAILED\n", (uint32_t)fails);
    }
    neorv32_uart0_printf("Press any key to run again.\n");
    neorv32_uart0_getc();
  }
  return 0;
}
