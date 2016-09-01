///////////////////////////////////////////////////////////////////////////////
//
// SUVA version 3
// Copyright (C) 2001-2012 ClearCenter
//
///////////////////////////////////////////////////////////////////////////////
//
// This project uses OpenSSL (http://openssl.org) for RSA, PEM, AES, RNG, DSO,
// and MD5 support.
//
///////////////////////////////////////////////////////////////////////////////
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the
// Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful, but 
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program; if not, write to the Free Software Foundation, Inc.,
// 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
//
///////////////////////////////////////////////////////////////////////////////

#ifndef _SVKEYPOLL_H
#define _SVKEYPOLL_H

class svExKeyPollInvalidOrg : public runtime_error
{
public:
    explicit svExKeyPollInvalidOrg(const string &org)
        : runtime_error(org) { };
    virtual ~svExKeyPollInvalidOrg() throw() { };
};

class svExKeyPollNoKeyServers : public runtime_error
{
public:
    explicit svExKeyPollNoKeyServers(const string &org)
        : runtime_error(org) { };
    virtual ~svExKeyPollNoKeyServers() throw() { };
};

class svExKeyPollTestFailure : public runtime_error
{
public:
    explicit svExKeyPollTestFailure(const string &org)
        : runtime_error(org) { };
    virtual ~svExKeyPollTestFailure() throw() { };
};

class svKeyPollResult : public svObject
{
public:
    svKeyPollResult(uint8_t *digest, RSA *key);
    virtual ~svKeyPollResult();

    bool operator!=(uint8_t *digest)
    {
        if (memcmp(this->digest, digest, MD5_DIGEST_LENGTH))
            return true;
        return false;
    };

    void AddPoint(void) { score++; };

    uint32_t GetScore(void) { return score; };
    RSA *GetKey(void) { RSA *pk = key; key = NULL; return pk; };

protected:
    uint32_t score;
    uint8_t digest[MD5_DIGEST_LENGTH];
    RSA *key;
};

class svThreadKeyPoll : public svThread
{
public:
    svThreadKeyPoll(const string &org, bool test_run = false);
    virtual ~svThreadKeyPoll();

    virtual void *Entry(void);

    void AddClient(svEventClient *c);
    void BroadcastResult(svEventKeyPollResult *result);

protected:
    string dev;
    string org;
    string key_dir;
    uint32_t ttl;
    uint32_t threshold;
    vector<svSocket *> skt;
    uint32_t skt_count;
    map<svEventClient *, svObject *> client;
    uint8_t pkt_buffer[_SUVA_MAX_PACKET_SIZE];
    vector<svKeyPollResult *> poll_result;
    bool test_run;

    void AddPollResult(uint8_t *payload, size_t length);
};

#endif // _SVKEYPOLL_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
