/*
 * bench_util.h  -  timing and printing helpers shared by the benchmark programs
 *
 * Time is measured with the hardware 1 microsecond counter (CFS) and with the
 * CPU cycle counter at the same time.
 */
#ifndef BENCH_UTIL_H
#define BENCH_UTIL_H

#include <neorv32.h>
#include "crypto_accel.h"   /* US_COUNTER */

typedef struct {
  uint32_t us;      /* time from the 1 us counter */
  uint32_t cycles;  /* CPU clock cycles */
} meas_t;

typedef struct {
  uint32_t us0;
  uint64_t c0;
} bench_timer_t;

static inline void bench_start(bench_timer_t *t) {
  t->us0 = US_COUNTER;
  t->c0  = neorv32_cpu_get_cycle();
}

static inline meas_t bench_stop(const bench_timer_t *t) {
  uint64_t c1  = neorv32_cpu_get_cycle();
  uint32_t us1 = US_COUNTER;
  return (meas_t){ us1 - t->us0, (uint32_t)(c1 - t->c0) };
}

/* 1234567 us -> "1234.567 ms" (the NEORV32 printf has no decimals) */
static inline void print_ms(uint32_t us) {
  uint32_t f = us % 1000;
  neorv32_uart0_printf("%u.%c%c%c ms", us / 1000, '0' + f / 100, '0' + (f / 10) % 10, '0' + f % 10);
}

/* bytes as hex, byte 0 first */
static inline void print_hex(const uint8_t *p, int n) {
  for (int i = 0; i < n; i++) {
    neorv32_uart0_printf("%c%c", "0123456789abcdef"[p[i] >> 4], "0123456789abcdef"[p[i] & 15]);
  }
}

#endif /* BENCH_UTIL_H */
