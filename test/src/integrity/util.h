#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include "sha1.h"
#include "config.h"

#define LOG_FILE    "/tmp/suva-integrity.log"

void fill(struct packet_t *pkt);
uint8_t *hash(struct packet_t *pkt, sha1 *ctx);
void verify(struct packet_t *pkt);
void print_hash(const uint8_t *sha1_hash);

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
