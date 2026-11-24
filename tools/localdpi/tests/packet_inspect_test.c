#include "packet_inspect.h"
#include "packets.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void check(const uint8_t *data, size_t len, uint32_t hint)
{
    struct dp_packet_inspection r = {99,99,99,99};
    assert(dp_packet_inspect(data,len,&r)==0);
    assert(r.version==DP_PACKET_INSPECT_VERSION);
    assert(r.hint==hint);
    assert(!r.reserved0 && !r.reserved1);
}

int main(void)
{
    struct dp_packet_inspection r;
    const uint8_t http[]="GET / HTTP/1.1\r\nHost: example.test\r\n\r\n";
    const uint8_t emptyhost[]="GET / HTTP/1.1\r\nHost: \r\n\r\n";
    const uint8_t badhost[]="GET / HTTP/1.1\r\nHost: 123\r\n\r\n";
    check(NULL,0,DP_PACKET_UNKNOWN);
    assert(dp_packet_inspect(NULL,1,&r)==-1);
    assert(r.hint==DP_PACKET_UNKNOWN && r.version==DP_PACKET_INSPECT_VERSION);
    assert(dp_packet_inspect(http,DP_PACKET_INSPECT_MAX+1,&r)==-1);
    assert(dp_packet_inspect(http,sizeof(http)-1,NULL)==-1);
    check(http,sizeof(http)-1,DP_PACKET_HTTP_CANDIDATE);
    /* These malformed Host examples must never reach parse_http. */
    check(emptyhost,sizeof(emptyhost)-1,DP_PACKET_HTTP_CANDIDATE);
    check(badhost,sizeof(badhost)-1,DP_PACKET_HTTP_CANDIDATE);
    check((const uint8_t *)tls_data,sizeof(tls_data),DP_PACKET_TLS_CANDIDATE);
    for (size_t n=0;n<6;++n) check((const uint8_t *)tls_data,n,DP_PACKET_UNKNOWN);
    /* Exact-sized allocations catch reads past the provided span. */
    uint32_t state=0x12345678u;
    for (unsigned i=0;i<8192;++i) {
        size_t n=i%513u;
        uint8_t *b=malloc(n?n:1);
        uint8_t *copy=malloc(n?n:1);
        assert(b && copy);
        for (size_t j=0;j<n;++j) {
            state ^= state<<13; state ^= state>>17; state ^= state<<5;
            b[j]=(uint8_t)state;
        }
        if (i%4==0 && n) {
            size_t k=n<sizeof(http)-1?n:sizeof(http)-1;
            memcpy(b,http,k);
        }
        if (i%4==1 && n) {
            size_t k=n<sizeof(tls_data)?n:sizeof(tls_data);
            memcpy(b,tls_data,k);
        }
        memcpy(copy,b,n);
        assert(dp_packet_inspect(b,n,&r)==0);
        assert(r.version==DP_PACKET_INSPECT_VERSION && r.hint<=DP_PACKET_HTTP_CANDIDATE);
        assert(!r.reserved0 && !r.reserved1);
        assert(memcmp(copy,b,n)==0);
        free(copy); free(b);
    }
    puts("DPpass packet inspection ABI: 8192 bounded fixtures passed");
    return 0;
}
