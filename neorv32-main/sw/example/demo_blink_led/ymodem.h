/*
 * ymodem.h  -  YMODEM file transfer over UART0 (used only by file_crypto.c)
 *
 * YMODEM is the file-transfer protocol built into Tera Term:
 *   File > Transfer > YMODEM > Send     (PC -> board: ym_receive)
 *   File > Transfer > YMODEM > Receive  (board -> PC: ym_send)
 * It sends the file name and exact size first (block 0), then the data in
 * 1024-byte blocks, each checked with a CRC-16; the receiver answers ACK (ok)
 * or NAK (send again). Several files can be sent in one session (batch).
 * No text may be printed while a transfer is running.
 */
#ifndef YMODEM_H
#define YMODEM_H

#include <neorv32.h>
#include <string.h>
#include "crypto_accel.h"          /* US_COUNTER: 1 us counter */

#define YM_SOH  0x01               /* 128-byte block   */
#define YM_STX  0x02               /* 1024-byte block  */
#define YM_EOT  0x04               /* end of file      */
#define YM_ACK  0x06
#define YM_NAK  0x15
#define YM_CAN  0x18               /* cancel           */
#define YM_CRC  'C'                /* "I want CRC-16"  */
#define YM_PAD  0x1A               /* fills the last block (the receiver cuts it off by the size) */

#define YM_OK          0
#define YM_TIMEOUT    -1           /* nothing came */
#define YM_TOO_BIG    -2
#define YM_CANCELLED  -3
#define YM_ERROR      -4

#define YM_MAX_NAME    120

static uint8_t ym_blk[1024];       /* one block */

/* one byte with a timeout, -1 = timeout */
static int ym_getc(uint32_t timeout_us) {
  uint32_t t0 = US_COUNTER;
  while (!neorv32_uart0_char_received()) {
    if (US_COUNTER - t0 > timeout_us) return -1;
  }
  return (uint8_t)neorv32_uart0_char_received_get();
}

static void ym_putc(uint8_t c) { neorv32_uart0_putc((char)c); }

static void ym_cancel(void) {
  for (int i = 0; i < 4; i++) ym_putc(YM_CAN);
  while (ym_getc(500000) >= 0);    /* drop whatever is still coming */
}

/* CRC-16/XMODEM: polynomial 0x1021, start 0 */
static uint16_t ym_crc16(const uint8_t *p, uint32_t n) {
  uint16_t crc = 0;
  while (n--) {
    crc ^= (uint16_t)(*p++) << 8;
    for (int b = 0; b < 8; b++) crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x1021) : (uint16_t)(crc << 1);
  }
  return crc;
}

/* ---------------------------------------------------------------------------
 * receive (PC sends with Tera Term: YMODEM > Send)
 * ------------------------------------------------------------------------- */

/* read the rest of a block after its first byte (SOH or STX); returns the
   block length, 0 = bad block (CRC or number error), -1 = timeout */
static int ym_read_block(int first, uint8_t *blkno) {
  int len = (first == YM_STX) ? 1024 : 128;
  int n = ym_getc(1000000), nn = ym_getc(1000000);
  if (n < 0 || nn < 0) return -1;
  for (int i = 0; i < len; i++) {
    int c = ym_getc(1000000);
    if (c < 0) return -1;
    ym_blk[i] = (uint8_t)c;
  }
  int hi = ym_getc(1000000), lo = ym_getc(1000000);
  if (hi < 0 || lo < 0) return -1;
  if ((uint8_t)n != (uint8_t)~nn) return 0;
  if (ym_crc16(ym_blk, len) != (uint16_t)((hi << 8) | lo)) return 0;
  *blkno = (uint8_t)n;
  return len;
}

/* wait for block 0 (file name + size) while asking with 'C' every 3 s.
   returns 1 = header ok, 0 = empty header (end of batch), <0 = error */
static int ym_read_header(char *name, uint32_t *size, uint32_t wait_s) {
  uint32_t t0 = US_COUNTER;
  while (US_COUNTER - t0 < wait_s * 1000000u) {
    ym_putc(YM_CRC);
    int c = ym_getc(3000000);
    if (c == YM_CAN) return YM_CANCELLED;
    if (c != YM_SOH && c != YM_STX) continue;
    uint8_t no;
    int len = ym_read_block(c, &no);
    if (len <= 0 || no != 0) { ym_putc(YM_NAK); continue; }
    if (ym_blk[0] == 0) { ym_putc(YM_ACK); return 0; }          /* empty name: end of batch */
    int i = 0;
    while (i < len && ym_blk[i] && i < YM_MAX_NAME) { name[i] = (char)ym_blk[i]; i++; }
    name[i] = 0;
    while (i < len && ym_blk[i]) i++;                            /* skip a too long name */
    uint32_t s = 0;
    for (i++; i < len && ym_blk[i] >= '0' && ym_blk[i] <= '9'; i++) s = s * 10 + (ym_blk[i] - '0');
    *size = s;
    return 1;
  }
  return YM_TIMEOUT;
}

/* receive one file into dst (at most max bytes). name gets the file name. */
static int ym_receive(uint8_t *dst, uint32_t max, char *name, uint32_t *size, uint32_t wait_s) {
  int h = ym_read_header(name, size, wait_s);
  if (h <= 0) return (h == 0) ? YM_ERROR : h;
  if (*size > max) { ym_cancel(); return YM_TOO_BIG; }
  ym_putc(YM_ACK);
  ym_putc(YM_CRC);                                               /* start the data */

  uint32_t got = 0;
  uint8_t expect = 1;
  int errors = 0;
  while (1) {
    int c = ym_getc(10000000);
    if (c < 0) { ym_cancel(); return YM_TIMEOUT; }
    if (c == YM_CAN) return YM_CANCELLED;
    if (c == YM_EOT) {                                           /* end of file: NAK, then ACK the 2nd EOT */
      ym_putc(YM_NAK);
      c = ym_getc(3000000);
      ym_putc(YM_ACK);
      break;
    }
    if (c != YM_SOH && c != YM_STX) continue;
    uint8_t no;
    int len = ym_read_block(c, &no);
    if (len <= 0) {
      if (++errors > 10) { ym_cancel(); return YM_ERROR; }
      ym_putc(YM_NAK);
      continue;
    }
    if (no == (uint8_t)(expect - 1)) { ym_putc(YM_ACK); continue; }   /* repeated block */
    if (no != expect) { ym_cancel(); return YM_ERROR; }
    uint32_t take = *size - got;
    if (take > (uint32_t)len) take = len;
    memcpy(dst + got, ym_blk, take);
    got += take;
    expect++;
    errors = 0;
    ym_putc(YM_ACK);
  }
  /* the sender then offers the next file: we take no more (empty header ends it) */
  char dummy[YM_MAX_NAME + 1];
  uint32_t dsize;
  if (ym_read_header(dummy, &dsize, 10) == 1) ym_cancel();       /* a 2nd file was sent: refuse it */
  return (got == *size) ? YM_OK : YM_ERROR;
}

/* ---------------------------------------------------------------------------
 * send (PC receives with Tera Term: YMODEM > Receive)
 * ------------------------------------------------------------------------- */

/* a file to send: name, size, and a function that fills dst with len bytes from offset */
typedef struct {
  const char *name;
  uint32_t    size;
  void      (*read)(uint32_t offset, uint8_t *dst, uint32_t len);
} ym_file_t;

/* send one block and wait for ACK (repeats on NAK); returns 0 ok, <0 error */
static int ym_send_block(uint8_t no, const uint8_t *data, int len) {
  uint16_t crc = ym_crc16(data, len);
  for (int tries = 0; tries < 10; tries++) {
    ym_putc(len == 1024 ? YM_STX : YM_SOH);
    ym_putc(no);
    ym_putc((uint8_t)~no);
    for (int i = 0; i < len; i++) ym_putc(data[i]);
    ym_putc((uint8_t)(crc >> 8));
    ym_putc((uint8_t)crc);
    int c;
    do { c = ym_getc(10000000); } while (c == YM_CRC);          /* ignore extra 'C' */
    if (c == YM_ACK) return 0;
    if (c == YM_CAN) return YM_CANCELLED;
  }
  return YM_ERROR;
}

/* wait until the receiver asks with 'C' */
static int ym_wait_c(uint32_t wait_s) {
  uint32_t t0 = US_COUNTER;
  while (US_COUNTER - t0 < wait_s * 1000000u) {
    int c = ym_getc(1000000);
    if (c == YM_CRC) return 0;
    if (c == YM_CAN) return YM_CANCELLED;
  }
  return YM_TIMEOUT;
}

/* send several files in one session */
static int ym_send(const ym_file_t *files, int count, uint32_t wait_s) {
  int r = ym_wait_c(wait_s);                                     /* Tera Term "Receive" started */
  if (r) return r;
  for (int f = 0; f < count; f++) {
    /* block 0: "name\0size\0" */
    memset(ym_blk, 0, 128);
    uint32_t i = 0;
    for (const char *s = files[f].name; *s && i < YM_MAX_NAME; s++) ym_blk[i++] = (uint8_t)*s;
    i++;
    char num[11];
    int n = 0;
    uint32_t v = files[f].size;
    do { num[n++] = (char)('0' + v % 10); v /= 10; } while (v);
    while (n) ym_blk[i++] = (uint8_t)num[--n];
    if ((r = ym_send_block(0, ym_blk, 128))) return r;
    if ((r = ym_wait_c(10))) return r;
    /* data blocks of 1024 bytes (the last one filled with YM_PAD) */
    uint8_t no = 1;
    for (uint32_t off = 0; off < files[f].size; off += 1024) {
      uint32_t len = files[f].size - off;
      if (len > 1024) len = 1024;
      files[f].read(off, ym_blk, len);
      for (uint32_t k = len; k < 1024; k++) ym_blk[k] = YM_PAD;
      if ((r = ym_send_block(no++, ym_blk, 1024))) return r;
    }
    /* end of file: EOT, (NAK), EOT, ACK */
    int c = 0;
    for (int tries = 0; tries < 10 && c != YM_ACK; tries++) {
      ym_putc(YM_EOT);
      c = ym_getc(5000000);
    }
    if (c != YM_ACK) return YM_ERROR;
    if ((r = ym_wait_c(10))) return r;                           /* ready for the next file */
  }
  memset(ym_blk, 0, 128);                                        /* empty block 0: end of the session */
  return ym_send_block(0, ym_blk, 128);
}

#endif /* YMODEM_H */
