#ifndef DPPASS_PACKET_INSPECT_H
#define DPPASS_PACKET_INSPECT_H

#include <stddef.h>
#include <stdint.h>

#define DP_PACKET_INSPECT_VERSION 1u
#define DP_PACKET_INSPECT_MAX 16384u

/* A recognition hint, not a protocol validator or a verified response. */
enum dp_packet_hint {
    DP_PACKET_UNKNOWN = 0,
    DP_PACKET_TLS_CANDIDATE = 1,
    DP_PACKET_HTTP_CANDIDATE = 2
};

/* Fixed-width results: no borrowed pointers or allocated memory cross ABI.
 * Reserved fields must be zero. No host, URL, or payload is exported. */
struct dp_packet_inspection {
    uint32_t version;
    uint32_t hint;
    uint32_t reserved0;
    uint32_t reserved1;
};

/* 0: inspected; -1: invalid argument or unsupported length.
 * A non-null result is initialized even when the request is rejected.
 * Input and output must refer to separate valid objects. No sockets,
 * mutation of input, global state, or retained pointers. */
int dp_packet_inspect(const uint8_t *data, size_t size,
                      struct dp_packet_inspection *result);

/* Copy and split a complete TLS ClientHello record at a caller-validated
 * offset within its handshake body. Preserves handshake and trailing bytes.
 * Returns 0 on success, -1 on rejection; writes no output on rejection.
 * Input/output must be separate valid objects, with capacity >= size+5.
 * This is a restricted wrapper around upstream part_tls, not a new parser. */
#define DP_TLS_REWRITE_MAX 65536u
int dp_tls_record_split(const uint8_t *data, size_t size, size_t offset,
                        uint8_t *output, size_t capacity);

#endif
