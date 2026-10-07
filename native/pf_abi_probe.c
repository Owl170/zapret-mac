/* Check the Darwin NAT lookup ABI used by discord_udp.py. */
#include <stddef.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/pfvar.h>

int main(void) {
    printf("{\"size\":%zu,\"request\":%lu,\"sport\":%zu,\"dport\":%zu,\"rdport\":%zu,\"af\":%zu}\n",
        sizeof(struct pfioc_natlook), (unsigned long)DIOCNATLOOK,
        offsetof(struct pfioc_natlook, sxport), offsetof(struct pfioc_natlook, dxport),
        offsetof(struct pfioc_natlook, rdxport), offsetof(struct pfioc_natlook, af));
    return 0;
}
