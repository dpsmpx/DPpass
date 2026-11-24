/* DPpass host fixtures. No network connections or live traffic. */
#include "packets.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

int main(void)
{
    char *host = NULL;
    uint16_t port = 0;
    const char req[] = "GET / HTTP/1.1\r\nHost: example.test:8080\r\n\r\n";
    const char nohost[] = "GET / HTTP/1.1\r\nAccept: */*\r\n\r\n";
    const char raw[] = "not a supported request";
    const char expected[] = "example.test";

    assert(is_http(req, sizeof(req)-1));
    int n = parse_http(req, sizeof(req)-1, &host, &port);
    assert(n == (int)(sizeof(expected)-1));
    assert(port == 8080);
    assert(memcmp(host, expected, (size_t)n) == 0);
    assert(parse_http(nohost, sizeof(nohost)-1, &host, &port) == 0);
    assert(!is_http(raw, sizeof(raw)-1));

    assert(is_tls_chello(tls_data, sizeof(tls_data)));
    n = parse_tls(tls_data, sizeof(tls_data), &host);
    const char fixture_host[] = "www.wikipedia.org";
    assert(n == (int)(sizeof(fixture_host)-1));
    assert(memcmp(host, fixture_host, (size_t)n) == 0);
    for (size_t i=0; i<=5; ++i) {
        assert(!is_tls_chello(tls_data, i));
        assert(parse_tls(tls_data, i, &host) == 0);
    }
    puts("Pinned ByeDPI packet module: host fixtures passed");
    return 0;
}
