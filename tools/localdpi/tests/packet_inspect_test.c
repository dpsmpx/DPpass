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
        // Never export a native parser range. Even malformed inputs
        // exercise the bounded comparison with exact-sized allocations.
        if (n >= 10) {
            (void)dp_tls_name_agrees(b,n,9,n);
        }
        assert(memcmp(copy,b,n)==0);
        free(copy); free(b);
    }
    /* Compare the native record encoder against the original handshake
     * bytes, including a second record following the first. */
    uint8_t input[522], out[527], saved[522];
    memcpy(input,tls_data,517);
    memcpy(input+517,"TAIL!",5);
    memcpy(saved,input,sizeof(input));
    for (size_t cut=5;cut<512;++cut) {
        assert(dp_tls_record_split(input,sizeof(input),cut,out,sizeof(out))==0);
        assert(!memcmp(input,saved,sizeof(input)));
        assert(!memcmp(out,input,3));
        assert((((size_t)out[3]<<8)|out[4])==cut);
        assert(!memcmp(out+5,input+5,cut));
        assert(!memcmp(out+5+cut,input,3));
        assert((((size_t)out[8+cut]<<8)|out[9+cut])==512-cut);
        assert(!memcmp(out+10+cut,input+5+cut,sizeof(input)-5-cut));
    }
    const char *fixture_name = "www.wikipedia.org";
    const size_t name_len = strlen(fixture_name);
    size_t name_start = 0;
    for (size_t i=9;i+name_len<=517;++i) {
        if (!memcmp(input+i,fixture_name,name_len)) {name_start=i;break;}
    }
    assert(name_start != 0);
    assert(dp_tls_name_agrees(input,sizeof(input),name_start,name_start+name_len)==1);
    assert(dp_tls_name_agrees(input,517,name_start,name_start+name_len)==1);
    assert(dp_tls_name_agrees(input,sizeof(input),name_start+1,name_start+name_len)==0);
    assert(dp_tls_name_agrees(input,sizeof(input),name_start,name_start+name_len+1)==0);
    assert(dp_tls_name_agrees(NULL,517,name_start,name_start+name_len)==0);
    assert(dp_tls_name_agrees(input,DP_TLS_REWRITE_MAX+1,name_start,name_start+name_len)==0);
    for (size_t n=0;n<517;++n) {
        assert(dp_tls_name_agrees(input,n,name_start,name_start+name_len)==0);
    }
    assert(!memcmp(input,saved,sizeof(input)));
    memset(out,0xA5,sizeof(out));
    assert(dp_tls_record_split(input,8,5,out,sizeof(out))==-1);
    assert(dp_tls_record_split(input,sizeof(input),4,out,sizeof(out))==-1);
    assert(dp_tls_record_split(input,sizeof(input),512,out,sizeof(out))==-1);
    assert(dp_tls_record_split(input,sizeof(input),10,out,sizeof(input))==-1);
    for (size_t i=0;i<sizeof(out);++i) assert(out[i]==0xA5);
    puts("DPpass packet inspection ABI: 8192 bounded fixtures and 507 record splits passed");
    return 0;
}
