#ifndef _CONFIG_H
#define _CONFIG_H

#define BLOCKSIZE   8192

struct packet_t
{
    long seq;
    uint8_t data[BLOCKSIZE];
    uint8_t hash[SHA1_HASH_LENGTH];
};

#endif // _CONFIG_H

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
