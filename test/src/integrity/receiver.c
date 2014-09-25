#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include "sha1.h"
#include "config.h"
#include "util.h"

static struct packet_t pkt;

int main(int argc, char *argv[])
{
    for ( ;; ) {
        memset((void *)&pkt, 0, sizeof(struct packet_t));
        if (fread((void *)&pkt, sizeof(struct packet_t), 1, stdin) != 1) {
            fprintf(stderr, "%6ld: Error reading packet.\n", pkt.seq);
            return 1;
        }

        fprintf(stderr, "%6ld: ", pkt.seq); print_hash(pkt.hash); fputc('\n', stderr);
        verify(&pkt);
    }
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
