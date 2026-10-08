/* Deterministic parser corpus under ASan/UBSan; no network or PF changes. */
#include "protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned int rng = 0x170103;
static unsigned int next(void)
{
    rng ^= rng << 13; rng ^= rng >> 17; rng ^= rng << 5;
    return rng;
}

static void check(const unsigned char *source, size_t len)
{
    unsigned char *data = malloc(len ? len : 1);
    char host[256];
    const unsigned char *ext = NULL;
    size_t extlen = 0;
    if (!data) exit(2);
    memcpy(data, source, len);
    IsHttp(data, len);
    HttpExtractHost(data, len, host, sizeof(host));
    if (IsHttpReply(data, len))
        HttpReplyLooksLikeDPIRedirect(data, len, "www.example.invalid");
    for (int partial = 0; partial < 2; partial++) {
        IsTLSClientHello(data, len, partial);
        TLSFindExt(data, len, 0, &ext, &extlen, partial);
        TLSHelloExtractHost(data, len, host, sizeof(host), partial);
        TLSHelloExtractHostFromHandshake(data, len, host, sizeof(host), partial);
    }
    for (unsigned int marker = 0; marker <= 7; marker++) {
        for (int offset = -16; offset <= 16; offset += 8) {
            size_t h = HttpPos(marker, offset, data, len);
            size_t t = TLSPos(marker, offset, data, len);
            if ((h && h >= len) || (t && t >= len)) {
                fprintf(stderr, "Out-of-range parser position\n"); exit(3);
            }
        }
    }
    free(data);
}

int main(void)
{
    const unsigned char http[] = "GET / HTTP/1.1\r\nHost: www.example.invalid\r\n\r\n";
    const unsigned char reply[] = "HTTP/1.1 302 Found\r\nLocation: https://other.invalid/x\r\n\r\n";
    unsigned char tls[256] = {0x16, 3, 1, 0, 0, 1, 0, 0, 0, 3, 3};
    const char *name = "www.example.invalid";
    size_t n = strlen(name), pos = 43;
    tls[pos++] = 0; /* session ID */
    tls[pos++] = 0; tls[pos++] = 2; tls[pos++] = 0x13; tls[pos++] = 1;
    tls[pos++] = 1; tls[pos++] = 0; /* compression */
    tls[pos++] = 0; tls[pos++] = (unsigned char)(n + 9);
    tls[pos++] = 0; tls[pos++] = 0; /* SNI extension */
    tls[pos++] = 0; tls[pos++] = (unsigned char)(n + 5);
    tls[pos++] = 0; tls[pos++] = (unsigned char)(n + 3);
    tls[pos++] = 0; tls[pos++] = 0; tls[pos++] = (unsigned char)n;
    memcpy(tls + pos, name, n); pos += n;
    tls[4] = (unsigned char)(pos - 5); tls[8] = (unsigned char)(pos - 9);
    char host[256];
    if (!TLSHelloExtractHost(tls, pos, host, sizeof(host), false) || strcmp(host, name)) {
        fprintf(stderr, "Invalid valid-TLS fixture\n"); return 4;
    }
    if (!TLSHelloExtractHostFromHandshake(tls + 5, pos - 5, host, sizeof(host), false) || strcmp(host, name)) {
        fprintf(stderr, "Invalid valid-TLS-handshake fixture\n"); return 4;
    }
    const unsigned char *seeds[] = {http, reply, tls, tls + 5};
    size_t sizes[] = {sizeof(http) - 1, sizeof(reply) - 1, pos, pos - 5};
    unsigned long count = 0;
    for (size_t s = 0; s < 4; s++) {
        for (size_t len = 0; len <= sizes[s]; len++) {
            check(seeds[s], len); count++;
        }
    }
    unsigned char data[1024];
    for (int i = 0; i < 10000; i++) {
        size_t len = next() % (sizeof(data) + 1);
        for (size_t j = 0; j < len; j++) data[j] = (unsigned char)next();
        if (i % 3 == 0) {
            size_t s = next() % 4;
            len = sizes[s]; memcpy(data, seeds[s], len);
            for (int m = 0; m < 4; m++) data[next() % len] = (unsigned char)next();
        }
        check(data, len); count++;
    }
    printf("PASS: %lu bounded HTTP/TLS parser cases under sanitizers\n", count);
    return 0;
}
