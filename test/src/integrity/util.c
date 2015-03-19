#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include "sha1.h"
#include "config.h"

void fill(struct packet_t *pkt)
{
//    uint8_t c = (uint8_t)pkt->seq;
//    for (int i = 0; i < BLOCKSIZE; i++) pkt->data[i] = c++;
    uint8_t c = 0xFF;
    memset(pkt->data, c, BLOCKSIZE);
}

uint8_t *hash(struct packet_t *pkt, sha1 *ctx)
{
    sha1_init(ctx);
    sha1_write(ctx, pkt->data, BLOCKSIZE);
    return sha1_result(ctx);
}

void verify(struct packet_t *pkt)
{
    sha1 ctx;
    uint8_t *sha1_hash = hash(pkt, &ctx);
#if 0
    char sha1_fingerprint[2][SHA1_HASH_LENGTH * 2 + 1];

    char *p = sha1_fingerprint[0];
    for (int i = 0; i < SHA1_HASH_LENGTH; i++, p += 2)
        sprintf(p, "%02x", sha1_hash[i]);
    char *p = sha1_fingerprint[1];
    for (int i = 0; i < SHA1_HASH_LENGTH; i++, p += 2)
        sprintf(p, "%02x", sha1_hash[i]);
#endif
    if (memcmp(sha1_hash, pkt->hash, SHA1_HASH_LENGTH))
        fprintf(stderr, "%6ld: Corrupt data.\n", pkt->seq);
}

void print_hash(const uint8_t *sha1_hash)
{
    for (int i = 0; i < SHA1_HASH_LENGTH; i++)
        fprintf(stderr, "%02x", sha1_hash[i]);
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
