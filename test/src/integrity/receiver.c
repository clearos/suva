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

extern FILE *logfile;
extern const char *device_id;

int main(int argc, char *argv[])
{
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

    for ( ;; ) {
        memset((void *)&pkt, 0, sizeof(struct packet_t));
        if (fread((void *)&pkt, sizeof(struct packet_t), 1, stdin) != 1) {
            fprintf(logfile, "%s: %6ld: Error reading packet.\n", device_id, pkt.seq);
            return 1;
        }

        fprintf(logfile, "%s: %6ld: ", device_id, pkt.seq);
        print_hash(pkt.hash);
        fputc('\n', logfile);

        verify(&pkt);
/*
        pkt.hash[3] = 0xFF;
        fprintf(logfile, "%s: %6ld: ", device_id, pkt.seq);
        print_hash(pkt.hash);
        fputc('\n', logfile);
        verify(&pkt);
*/
    }

    return 0;
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
