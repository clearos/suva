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

extern FILE *logfile;
extern const char *device_id;

int main(int argc, char *argv[])
{
    sha1 ctx;

    logfile = fopen(LOG_FILE, "a+");
    if (!logfile) {
        fprintf(stderr,
            "Error opening log file: %s: %s\n", LOG_FILE, strerror(errno));
        return 1;
    }

    if (getenv("") == NULL)
        device_id = "<UNKNOWN>";
    else
        device_id = getenv("");

    long count = COUNT;
    char *count_env = getenv("COUNT");
    if (count_env != NULL) count = atol(count_env);

    for (pkt.seq = 0; pkt.seq < count; pkt.seq++) {
        fill(&pkt);
        memcpy(pkt.hash, hash(&pkt, &ctx), SHA1_HASH_LENGTH);
        if (fwrite((void *)&pkt, sizeof(struct packet_t), 1, stdout) != 1) {
            fprintf(logfile, "%s: %6ld: Error writing packet.\n", device_id, pkt.seq);
            return 1;
        }

        fprintf(logfile, "%s: %6ld: ", device_id, pkt.seq);
        print_hash(pkt.hash);
        fputc('\n', logfile);
    }

    return 0;
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
