/* Regression for a small socket-address union inside a connection object. */
#include "helpers.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    unsigned char *buffer = malloc(sizeof(sockaddr_in46) + 64);
    if (!buffer) return 2;
    size_t offset = 1;
    while (offset < 32 && (((uintptr_t)(buffer + offset) % __alignof__(sockaddr_in46)) ||
                          !((uintptr_t)(buffer + offset) % __alignof__(struct sockaddr_storage))))
        offset++;
    if (offset == 32) {
        fprintf(stderr, "Cannot create the Darwin alignment regression fixture\n");
        free(buffer); return 3;
    }
    sockaddr_in46 *target = (sockaddr_in46 *)(buffer + offset);
    struct sockaddr_in ip4 = {0};
    ip4.sin_family = AF_INET;
    ip4.sin_port = htons(443);
    ip4.sin_addr.s_addr = htonl(0xc0000201);
    struct sockaddr_in6 ip6 = {0};
    ip6.sin6_family = AF_INET6;
    ip6.sin6_port = htons(8443);
    ip6.sin6_addr.s6_addr[15] = 1;
#ifdef __APPLE__
    ip4.sin_len = sizeof(ip4);
    ip6.sin6_len = sizeof(ip6);
#endif
    const struct sockaddr *sources[] = {(struct sockaddr *)&ip4, (struct sockaddr *)&ip6};
    const size_t sizes[] = {sizeof(ip4), sizeof(ip6)};
    for (int i = 0; i < 2; i++) {
        memset(buffer, 0xa5, sizeof(sockaddr_in46) + 64);
        sa46copy(target, sources[i]);
        if (memcmp(target, sources[i], sizes[i])) {
            fprintf(stderr, "Address bytes changed\n"); free(buffer); return 4;
        }
        for (size_t j = 0; j < sizeof(sockaddr_in46) + 64; j++) {
            if ((j < offset || j >= offset + sizes[i]) && buffer[j] != 0xa5) {
                fprintf(stderr, "Address copy changed surrounding bytes\n"); free(buffer); return 5;
            }
        }
    }
    struct sockaddr unknown = {0};
    unknown.sa_family = AF_UNSPEC;
    memset(target, 0xa5, sizeof(*target));
    sa46copy(target, &unknown);
    for (size_t i = 0; i < sizeof(*target); i++) {
        if (((unsigned char *)target)[i]) {
            fprintf(stderr, "Unknown family was not cleared\n"); free(buffer); return 6;
        }
    }
    free(buffer);
    puts("PASS: IPv4/IPv6 small-union address copies preserve bytes without storage-alignment assumptions");
    return 0;
}
