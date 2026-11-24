/* DPpass-owned, deliberately narrow wrapper around read-only ByeDPI
 * predicates. No untrusted input reaches the legacy Host parser or any
 * modifying function in this prototype. */
#include "packet_inspect.h"
#include "packets.h"

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
