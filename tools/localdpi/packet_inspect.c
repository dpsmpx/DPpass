/* DPpass-owned narrow wrapper around read-only ByeDPI predicates and
 * the explicitly bounded TLS record encoder. The legacy Host parser
 * and HTTP mutation functions are not exposed for arbitrary input. */
#include "packet_inspect.h"
#include "packets.h"
#include <string.h>

int dp_packet_inspect(const uint8_t *data, size_t size,
                      struct dp_packet_inspection *result)
{
    if (!result) return -1;
    *result = (struct dp_packet_inspection){ DP_PACKET_INSPECT_VERSION,
                                           DP_PACKET_UNKNOWN, 0, 0 };
    if (size > DP_PACKET_INSPECT_MAX || (!data && size)) return -1;
    if (!size) return 0;

    /* Upstream is_tls_chello checks at least six bytes, is_http at
     * least sixteen. The extra bounds below are part of our contract. */
    if (size >= 6 && is_tls_chello((const char *)data, size)) {
        result->hint = DP_PACKET_TLS_CANDIDATE;
    } else if (size >= 16 && is_http((const char *)data, size)) {
        result->hint = DP_PACKET_HTTP_CANDIDATE;
    }
    return 0;
}

// The existing Go planner chooses the split; native code only encodes it.
// Bound all lengths before invoking the upstream in-place helper.
int dp_tls_record_split(const uint8_t *data, size_t size, size_t offset,
                        uint8_t *output, size_t capacity)
{
    if (!data || !output || size < 9 || size > DP_TLS_REWRITE_MAX ||
        capacity < size + 5 || data[0] != 22 || data[1] != 3 ||
        data[2] > 4 || data[5] != 1) return -1;
    size_t record = ((size_t)data[3] << 8) | data[4];
    size_t hello = ((size_t)data[6] << 16) | ((size_t)data[7] << 8) | data[8];
    if (record < 12 || record > 16384 || record > size - 5 ||
        hello == 0 || hello > record - 4 || offset <= 4 ||
        offset >= record) return -1;
    memcpy(output, data, size);
    // Every upstream early-return condition is excluded by the checks
    // above; offset fits long and size fits ssize_t on supported hosts.
    return part_tls((char *)output, size + 5, (ssize_t)size, (long)offset) == 5 ? 0 : -1;
}

// The upstream parser is read-only. Limit it to the first complete
// ClientHello message, not trailing records or later handshake messages.
// The range supplied by the caller is a separate validation boundary.
int dp_tls_name_agrees(const uint8_t *data, size_t size,
                       size_t start, size_t end)
{
    if (!data || size < 9 || size > DP_TLS_REWRITE_MAX ||
        data[0] != 22 || data[1] != 3 || data[2] > 4 || data[5] != 1)
        return 0;
    size_t record = ((size_t)data[3] << 8) | data[4];
    size_t hello = ((size_t)data[6] << 16) | ((size_t)data[7] << 8) | data[8];
    if (record < 12 || record > 16384 || record > size - 5 ||
        !hello || hello > record - 4)
        return 0;
    size_t limit = 9 + hello;
    if (start < 9 || start >= end || end > limit)
        return 0;
    char *name = NULL;
    int n = parse_tls((const char *)data, limit, &name);
    // Pointer equality, not subtraction of an untrusted pointer.
    return n > 0 && (size_t)n == end - start &&
           name == (const char *)data + start;
}

int dp_http_host_case_fixture(const uint8_t *data, size_t size,
                              uint8_t *output, size_t capacity)
{
    static const char original[] =
        "POST /self-check HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\nbody";
    static const char expected[] =
        "POST /self-check HTTP/1.1\r\nhOsT: example.com\r\nContent-Length: 4\r\n\r\nbody";
    if (!data || !output || size != sizeof(original)-1 ||
        capacity < size || memcmp(data,original,size) != 0)
        return -1;
    // Upstream parse_http/mod_http have unbounded backward scans on
    // arbitrary input. Only this exact known request may reach them.
    char scratch[sizeof(original)];
    memcpy(scratch,original,sizeof(original));
    if (mod_http(scratch,size,MH_HMIX) != 0 ||
        memcmp(scratch,expected,sizeof(expected)) != 0)
        return -1;
    memcpy(output,scratch,size);
    return 0;
}
