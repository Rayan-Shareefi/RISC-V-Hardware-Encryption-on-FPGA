/*
 * demo_util.h  -  helpers for the 3 demo programs (demo_chacha20.c,
 * demo_chacha20_poly1305.c, demo_keccak.c): board LEDs, live progress bar,
 * typed input from the terminal, result table.
 *
 * LEDs on the Cmod A7: LD1 = GPIO 0, LD2 = GPIO 1 (1 = on);
 * RGB LED = GPIO 2 blue, 3 red, 4 green (0 = on).
 */
#ifndef DEMO_UTIL_H
#define DEMO_UTIL_H

#include <neorv32.h>
#include <string.h>
#include "bench_util.h"

/* printing helpers are kept as one shared copy (smaller program); none of them runs inside a timed part */
#define NOINLINE __attribute__((noinline, unused))

#define BAUD_RATE      19200
#define INPUT_TIMEOUT  20      /* seconds to wait for a typed message */

/* Put after every timed run: the compiler must really read the input from memory and
   write the result to memory each time (like real data), instead of keeping the input
   in registers or dropping results that are never printed. */
#define MEMORY_BARRIER() __asm__ volatile ("" ::: "memory")

/* ---- LEDs ---- */
#define LED_IDLE  0x1C   /* all off (RGB is off when its bits are 1)  */
#define LED_SW    0x1D   /* LD1 on: software is running                */
#define LED_HW    0x1E   /* LD2 on: hardware is running                */
#define LED_PASS  0x0C   /* RGB green: all checks passed               */
#define LED_FAIL  0x14   /* RGB red: a check failed                    */

static NOINLINE void leds(uint32_t v) {
  neorv32_gpio_port_set(v);
}

/* ---- printing ---- */
static NOINLINE void demo_banner(const char *title) {
  neorv32_uart0_printf("\n=================================================================\n");
  neorv32_uart0_printf(" %s\n", title);
  neorv32_uart0_printf(" NEORV32 RISC-V (rv32imc) on the Cmod A7-35T, %u MHz\n", neorv32_sysinfo_get_clk() / 1000000);
  neorv32_uart0_printf(" Custom crypto instructions (CFU): %s\n",
                       (neorv32_cpu_csr_read(CSR_MXISA) & (1 << CSR_MXISA_XCFU)) ? "yes" : "NO - wrong bitstream!");
  neorv32_uart0_printf("=================================================================\n");
}

static NOINLINE void demo_step(const char *title) {
  neorv32_uart0_printf("\n[%s\n", title);   /* title starts with "1] ..." */
}

/* text between quotes, non-printable bytes shown as '.' */
static NOINLINE void print_text(const uint8_t *p, uint32_t n) {
  neorv32_uart0_putc('"');
  for (uint32_t i = 0; i < n; i++) {
    neorv32_uart0_putc((p[i] >= 32 && p[i] < 127) ? (char)p[i] : '.');
  }
  neorv32_uart0_putc('"');
}

/* hex in lines of 32 bytes (64 characters), so Tera Term never wraps them */
static NOINLINE void hex_lines(const uint8_t *p, uint32_t n) {
  for (uint32_t i = 0; i < n; i += 32) {
    neorv32_uart0_printf("    ");
    print_hex(p + i, (n - i > 32) ? 32 : (int)(n - i));
    neorv32_uart0_printf("\n");
  }
}

static inline const char *pass_fail(int ok) {
  return ok ? "PASS" : "FAIL";
}

/* one live progress line, redrawn in place:  "  SW  [##########..........]  500/1000  836.123 ms" */
static NOINLINE void progress(const char *name, uint32_t done, uint32_t total, uint32_t us) {
  uint32_t filled = done * 20 / total;
  neorv32_uart0_printf("\r  %s [", name);
  for (uint32_t i = 0; i < 20; i++) {
    neorv32_uart0_putc(i < filled ? '#' : '.');
  }
  neorv32_uart0_printf("] %u/%u  ", done, total);
  print_ms(us);
  neorv32_uart0_printf("   ");
}

/* add one timed chunk to a running total */
static inline void meas_add(meas_t *total, meas_t chunk) {
  total->us     += chunk.us;
  total->cycles += chunk.cycles;
}

/* result table row: "  Software       1674.591 ms   20095048 cycles   20095 cycles/run" */
static NOINLINE void print_result(const char *name, meas_t m, uint32_t runs) {
  neorv32_uart0_printf("  %s ", name);
  print_ms(m.us);
  neorv32_uart0_printf("   %u cycles   %u cycles/run\n", m.cycles, m.cycles / runs);
}

static NOINLINE void print_speedup(const char *name, meas_t sw, meas_t hw) {
  /* 32-bit math is enough: the largest value is about 293,000,000 x 10 (Keccak software) < 2^32 */
  uint32_t x10 = (sw.cycles * 10u + hw.cycles / 2) / hw.cycles;   /* speedup x 10, rounded */
  neorv32_uart0_printf("  Speedup %s: %u.%ux faster in hardware\n", name, x10 / 10, x10 % 10);
}

/*
 * Read a line typed in the terminal (echoed, Backspace works, Enter ends it).
 * If nothing is typed within INPUT_TIMEOUT seconds, returns 0 and the caller
 * uses its default text. buf must hold max + 1 bytes.
 */
static NOINLINE uint32_t read_line(char *buf, uint32_t max) {
  uint32_t n = 0;
  uint64_t deadline = neorv32_cpu_get_cycle() + (uint64_t)INPUT_TIMEOUT * neorv32_sysinfo_get_clk();
  neorv32_uart0_printf("  > ");
  while (1) {
    if (neorv32_uart0_char_received()) {
      char c = neorv32_uart0_char_received_get();
      deadline = ~0ULL;                                  /* typing started: wait for Enter */
      if (c == '\r' || c == '\n') {
        break;
      }
      if ((c == 8 || c == 127) && n > 0) {               /* Backspace */
        n--;
        neorv32_uart0_printf("\b \b");
      } else if (c >= 32 && c < 127 && n < max) {
        buf[n++] = c;
        neorv32_uart0_putc(c);
      }
    } else if (neorv32_cpu_get_cycle() > deadline) {
      break;
    }
  }
  buf[n] = 0;
  neorv32_uart0_printf("\n");
  return n;
}

/* wait for Enter (or any key) before running the demo again */
static NOINLINE void wait_for_key(void) {
  neorv32_uart0_printf("\nPress Enter to run the demo again.\n");
  while (neorv32_uart0_char_received()) {               /* drop old keys */
    neorv32_uart0_char_received_get();
  }
  neorv32_uart0_getc();
}

#endif /* DEMO_UTIL_H */
