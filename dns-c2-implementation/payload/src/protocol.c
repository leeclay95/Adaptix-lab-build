/*
 * protocol.c - XOR crypto, endian helpers, sleep-jitter, base32 codec
 */
#include <windows.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "protocol.h"

/* ---- Globals ---- */
uint32_t g_sleep_ms   = 5000;
uint8_t  g_jitter_pct = 20;
uint8_t  g_xor_key[4] = {0};
char     g_agent_id[9] = {0};

/* ---- XOR ---- */
void xor_crypt(uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= g_xor_key[i & 3];
    }
}

/* ---- Endian helpers ---- */
uint16_t read_u16le(const uint8_t *b) {
    return (uint16_t)b[0] | ((uint16_t)b[1] << 8);
}

uint32_t read_u32le(const uint8_t *b) {
    return (uint32_t)b[0]
         | ((uint32_t)b[1] <<  8)
         | ((uint32_t)b[2] << 16)
         | ((uint32_t)b[3] << 24);
}

void write_u16le(uint8_t *b, uint16_t v) {
    b[0] = (uint8_t)(v & 0xFF);
    b[1] = (uint8_t)((v >> 8) & 0xFF);
}

void write_u32le(uint8_t *b, uint32_t v) {
    b[0] = (uint8_t)(v & 0xFF);
    b[1] = (uint8_t)((v >>  8) & 0xFF);
    b[2] = (uint8_t)((v >> 16) & 0xFF);
    b[3] = (uint8_t)((v >> 24) & 0xFF);
}

/* ---- Sleep with jitter ---- */
void sleep_jitter(void) {
    if (g_sleep_ms == 0) return;

    uint32_t base  = g_sleep_ms;
    uint32_t swing = (uint32_t)((uint64_t)base * g_jitter_pct / 100);

    /* rand() is 0..RAND_MAX; map to [-swing, +swing] */
    int32_t delta = 0;
    if (swing > 0) {
        /* produce value in [-swing, swing] */
        int r = rand();
        delta = (int32_t)(r % (int)(2 * swing + 1)) - (int32_t)swing;
    }

    int64_t actual = (int64_t)base + delta;
    if (actual < 0) actual = 0;

    Sleep((DWORD)actual);
}

/* ---- Base32 codec (RFC 4648, no padding, uppercase A-Z2-7) ---- */

static const char B32_ALPHA[32] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/*
 * Encode `len` bytes into out_buf (null-terminated).
 * out_size must be >= ceil(len*8/5)+1.
 * Returns number of base32 characters written (not counting the null).
 * Returns -1 if out_size is too small.
 */
int base32_encode(const uint8_t *data, size_t len, char *out_buf, size_t out_size) {
    size_t out_needed = ((len * 8) + 4) / 5; /* ceil(len*8/5) */
    if (out_size < out_needed + 1) return -1;

    size_t bi  = 0; /* bit offset into the input stream */
    size_t out = 0;

    for (size_t i = 0; i < out_needed; i++) {
        /* which byte and bit does this 5-bit group start at? */
        size_t byte_idx = bi / 8;
        int    bit_off  = (int)(bi % 8);

        uint32_t val;
        if (bit_off <= 3) {
            /* fits entirely within one byte */
            val = (data[byte_idx] >> (3 - bit_off)) & 0x1F;
        } else {
            /* spans two bytes */
            uint32_t hi = data[byte_idx];
            uint32_t lo = (byte_idx + 1 < len) ? data[byte_idx + 1] : 0;
            val = ((hi << 8) | lo) >> (11 - bit_off) & 0x1F;
        }
        out_buf[out++] = B32_ALPHA[val & 0x1F];
        bi += 5;
    }

    out_buf[out] = '\0';
    return (int)out;
}

/*
 * Decode a base32 string of str_len chars into out_buf.
 * out_size must be >= floor(str_len*5/8).
 * Returns number of decoded bytes, or -1 on invalid input / buffer too small.
 */
int base32_decode(const char *str, size_t str_len, uint8_t *out_buf, size_t out_size) {
    size_t out_needed = (str_len * 5) / 8;
    if (out_size < out_needed) return -1;

    uint32_t acc   = 0;
    int      bits  = 0;
    size_t   out   = 0;

    for (size_t i = 0; i < str_len; i++) {
        char c = str[i];
        int  v;

        if (c >= 'A' && c <= 'Z') {
            v = c - 'A';
        } else if (c >= 'a' && c <= 'z') {
            v = c - 'a';
        } else if (c >= '2' && c <= '7') {
            v = 26 + (c - '2');
        } else if (c == '=') {
            break; /* padding */
        } else {
            return -1; /* invalid character */
        }

        acc  = (acc << 5) | (uint32_t)v;
        bits += 5;

        if (bits >= 8) {
            bits -= 8;
            out_buf[out++] = (uint8_t)((acc >> bits) & 0xFF);
        }
    }

    return (int)out;
}
