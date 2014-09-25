#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include "sha1.h"
#include "config.h"
#include "util.h"

#define COUNT   1000

static struct packet_t pkt;

int main(int argc, char *argv[])
{
    sha1 ctx;

    long count = COUNT;
    char *count_env = getenv("COUNT");
    if (count_env != NULL) count = atol(count_env);

    for (pkt.seq = 0; pkt.seq < count; pkt.seq++) {
        fill(&pkt);
        memcpy(pkt.hash, hash(&pkt, &ctx), SHA1_HASH_LENGTH);
        if (fwrite((void *)&pkt, sizeof(struct packet_t), 1, stdout) != 1) {
            fprintf(stderr, "%6ld: Error writing packet.\n", pkt.seq);
            return 1;
        }

        fprintf(stderr, "%6ld: ", pkt.seq); print_hash(pkt.hash); fputc('\n', stderr);
    }
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
