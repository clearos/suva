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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <iostream>
#include <stdexcept>
#include <sstream>
#include <map>
#include <vector>

#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <expat.h>
#include <pthread.h>

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

#include <openssl/aes.h>
#include <openssl/rsa.h>

#include "svutil.h"
#include "svoutput.h"
#include "svobject.h"
#include "svconf.h"
#include "svcrypto.h"
#include "svpacket.h"

svPacket::svPacket(uint8_t *buffer)
    : svObject("svPacket"), buffer(buffer), crypto(NULL)
{
    memset((void *)&header, 0, _SUVA_PKT_HEADER_SIZE);
}

svPacket::svPacket(uint8_t *buffer,
    svPacketId pid, uint8_t pa1, uint8_t pa2, uint16_t length)
    : svObject("svPacket"), buffer(buffer), crypto(NULL)
{
    memset((void *)&header, 0, _SUVA_PKT_HEADER_SIZE);
    header.pid = (uint8_t)pid;
    header.pa1 = pa1;
    header.pa2 = pa2,
    header.length = length;
}

void svPacket::SyncReadHeader(void)
{
    memcpy((void *)&header, (void *)buffer, _SUVA_PKT_HEADER_SIZE);
}

void svPacket::SyncWriteHeader(void)
{
    memcpy((void *)buffer, (void *)&header, _SUVA_PKT_HEADER_SIZE);
}

void svPacket::Encrypt(void)
{
    if (crypto && header.length) {
        crypto->AESCryptPacket(svAES_ENCRYPT, (*this));
        SyncWriteHeader();
    }
}

void svPacket::Decrypt(void)
{
    if (crypto && header.length) {
        crypto->AESCryptPacket(svAES_DECRYPT, (*this));
        SyncWriteHeader();
    }
}

svPacketOpen::svPacketOpen(uint8_t *buffer)
    : svPacket(buffer, PKT_ID_OPEN, 0, 0, 0) { }

void svPacketOpen::SyncRead(void)
{
//  svPacket::SyncRead();

    uint8_t *ptr = buffer + _SUVA_PKT_HEADER_SIZE;
    if (ver_major == 2 && ver_minor == 0) ptr += sizeof(uint16_t);
    struct pkt_session_t *session = (struct pkt_session_t *)ptr;
    ptr += sizeof(struct pkt_session_t);

    svLegalizeString(session_name,
        (const char *)ptr, session->session_length);
}

void svPacketOpen::SyncWrite(void)
{
    struct pkt_session_t session;
    memset(&session, 0, sizeof(pkt_session_t));
    session.session_length = session_name.size();
    header.length =
        sizeof(pkt_session_t) + session.session_length;
    if (ver_major == 2 && ver_minor == 0)
        header.length += sizeof(uint16_t);

    svPacket::SyncWrite();

    uint8_t *ptr = buffer + _SUVA_PKT_HEADER_SIZE;
    if (ver_major == 2 && ver_minor == 0) ptr += sizeof(uint16_t);
    memcpy((void *)ptr,
        (void *)&session, sizeof(struct pkt_session_t));
    ptr += sizeof(struct pkt_session_t);
    memcpy(ptr, session_name.c_str(), session.session_length);
}

svPacketPool::svPacketPool(uint8_t *buffer)
    : svPacket(buffer, PKT_ID_POOL, 0, 0, 0) { }

void svPacketPool::SyncRead(void)
{
    uint8_t *ptr = buffer + _SUVA_PKT_HEADER_SIZE;
    struct pkt_session_t *session = (struct pkt_session_t *)ptr;
    ptr += sizeof(struct pkt_session_t);

    svLegalizeString(pool_name,
        (const char *)ptr, session->session_length);
}

void svPacketPool::SyncWrite(void)
{
    struct pkt_session_t session;
    memset(&session, 0, sizeof(pkt_session_t));
    session.session_length = pool_name.size();
    header.length =
        sizeof(pkt_session_t) + session.session_length;

    svPacket::SyncWrite();

    uint8_t *ptr = buffer + _SUVA_PKT_HEADER_SIZE;
    memcpy((void *)ptr,
        (void *)&session, sizeof(struct pkt_session_t));
    ptr += sizeof(struct pkt_session_t);
    memcpy(ptr, pool_name.c_str(), session.session_length);
}

svPacketAuth::svPacketAuth(uint8_t *buffer)
    : svPacket(buffer, PKT_ID_AUTH, 0, 0, 0) { }

void svPacketAuth::SyncRead(void)
{
    svPacket::SyncRead();
}

void svPacketAuth::SyncWrite(void)
{
    svPacket::SyncWrite();
}

svPacketAuthVersion::svPacketAuthVersion(uint8_t *buffer)
    : svPacketAuth(buffer)
{
    header.pa1 = (uint8_t)PKT_ARG_AUTH_VER;
    memset(&id, 0, sizeof(struct pkt_id_t));
    memset(&version, 0, sizeof(struct pkt_version_t));
}

bool svPacketAuthVersion::IsValid(void)
{
    if (header.pid != PKT_ID_AUTH ||
        header.pa1 != PKT_ARG_AUTH_VER) return false;
    if (header.length >
        sizeof(struct pkt_id_t) + sizeof(struct pkt_version_t) +
        (_SUVA_MAX_NAME_LEN * 2)) return false;
    return true;
}

void svPacketAuthVersion::SyncRead(void)
{
    uint8_t *ptr = buffer + _SUVA_PKT_HEADER_SIZE;
    memcpy((void *)&id, (void *)ptr, sizeof(struct pkt_id_t));
    ptr += sizeof(struct pkt_id_t);
    memcpy((void *)&version, (void *)ptr, sizeof(struct pkt_version_t));
    ptr += sizeof(struct pkt_version_t);

    svLegalizeString(dev, (const char *)ptr, id.dev_length);
    ptr += id.dev_length;
    svLegalizeString(org, (const char *)ptr, id.org_length);
}

void svPacketAuthVersion::SyncWrite(void)
{
    header.length =
        sizeof(pkt_id_t) + sizeof(pkt_version_t) +
        id.dev_length + id.org_length;

    svPacketAuth::SyncWrite();

    uint8_t *ptr = buffer + _SUVA_PKT_HEADER_SIZE;

    memcpy((void *)ptr, (void *)&id, sizeof(struct pkt_id_t));
    ptr += sizeof(struct pkt_id_t);
    memcpy((void *)ptr, (void *)&version, sizeof(struct pkt_version_t));
    ptr += sizeof(struct pkt_version_t);

    memcpy(ptr, dev.c_str(), id.dev_length);
    ptr += id.dev_length;
    memcpy(ptr, org.c_str(), id.org_length);
}

void svPacketAuthVersion::SetDevice(const string &dev)
{
    if (dev.size() > _SUVA_MAX_NAME_LEN)
        id.dev_length = _SUVA_MAX_NAME_LEN;
    else id.dev_length = (uint8_t)dev.size();
    this->dev = dev;
}

void svPacketAuthVersion::SetOrganization(const string &org)
{
    if (org.size() > _SUVA_MAX_NAME_LEN)
        id.org_length = _SUVA_MAX_NAME_LEN;
    else id.org_length = (uint8_t)org.size();
    this->org = org;
}

svAESKeySize svPacketAuthVersion::GetAESKeySize(void)
{
    switch (header.pa2) {
    case svKS_AES_128:
        return svKS_AES_128;
    case svKS_AES_192:
        return svKS_AES_192;
    case svKS_AES_256:
        return svKS_AES_256;
    }
    return svKS_AES_NULL;
}

void svPacketAuthVersion::SetAESKeySize(svAESKeySize size)
{
    switch (size) {
    case svKS_AES_128:
        header.pa2 = (uint8_t)svKS_AES_128;
        break;
    case svKS_AES_192:
        header.pa2 = (uint8_t)svKS_AES_192;
        break;
    case svKS_AES_256:
        header.pa2 = (uint8_t)svKS_AES_256;
        break;
    default:
        header.pa2 = (uint8_t)svKS_AES_NULL;
        break;
    }
}

svPacketAuthKeyPoll::svPacketAuthKeyPoll(uint8_t *buffer)
    : svPacketAuthVersion(buffer)
{
    header.pa2 = (uint8_t)PKT_ARG_AUTH_KEYPOLL;
}

void svPacketAuthKeyPoll ::SyncRead(void)
{
    svPacketAuthVersion::SyncRead();
}

void svPacketAuthKeyPoll::SyncWrite(void)
{
    svPacketAuthVersion::SyncWrite();
}

svPacketAuthKeySync::svPacketAuthKeySync(uint8_t *buffer)
    : svPacket(buffer, PKT_ID_AUTH, PKT_ARG_AUTH_SYNC, 0, 0) { }

bool svPacketAuthKeySync::IsValid(void)
{
    if (header.pid == PKT_ID_AUTH && header.pa1 == PKT_ARG_AUTH_SYNC &&
        header.length <= 1024) return true;
    return false;
}

svPacketAuthKeyAck::svPacketAuthKeyAck(uint8_t *buffer)
    : svPacket(buffer, PKT_ID_AUTH, PKT_ARG_AUTH_ACK, 0, 0) { }

bool svPacketAuthKeyAck::IsValid(void)
{
    if (header.pid == PKT_ID_AUTH && header.pa1 == PKT_ARG_AUTH_ACK)
        return true;
    return false;
}

svPacketSessionKey::svPacketSessionKey(uint8_t *buffer,
    svPacketKeySyncMode mode)
    : svPacket(buffer, PKT_ID_KEY, (uint8_t)mode, 0, 0) { }

bool svPacketSessionKey::IsValid(void)
{
    if (header.pid == PKT_ID_KEY) return true;
    return false;
}

void svPacketSessionKey::SyncRead(void)
{
    svPacket::SyncRead();
}

void svPacketSessionKey::SyncWrite(void)
{
    svPacket::SyncWrite();
}

svPacketSessionKeySync::svPacketSessionKeySync(uint8_t *buffer)
    : svPacketSessionKey(buffer, PKT_ARG_KEY_SYNC) { }

void svPacketSessionKeySync::SyncRead(void)
{
    svPacketSessionKey::SyncRead();
}

void svPacketSessionKeySync::SyncWrite(void)
{
    svPacketSessionKey::SyncWrite();
}

svPacketSessionKeyAck::svPacketSessionKeyAck(uint8_t *buffer)
    : svPacketSessionKey(buffer, PKT_ARG_KEY_ACK) { }

void svPacketSessionKeyAck::SyncRead(void)
{
    svPacketSessionKey::SyncRead();
}

void svPacketSessionKeyAck::SyncWrite(void)
{
    svPacketSessionKey::SyncWrite();
}

svPacketData::svPacketData(uint8_t *buffer)
    : svPacket(buffer, PKT_ID_DATA, 0, 0, 0) { }

void svPacketData::SyncRead(void)
{
    svPacket::SyncRead();
}

void svPacketData::SyncWrite(void)
{
    svPacket::SyncWrite();
}

svPacketHangup::svPacketHangup(uint8_t *buffer)
    : svPacket(buffer, PKT_ID_HANGUP, 0, 0, 0) { }

void svPacketHangup::SyncRead(void)
{
    svPacket::SyncRead();
}

void svPacketHangup::SyncWrite(void)
{
    svPacket::SyncWrite();
}

svPacketError::svPacketError(uint8_t *buffer)
    : svPacket(buffer, PKT_ID_ERROR, 0, 0, 0) { }

void svPacketError::SyncRead(void)
{
    svPacket::SyncRead();
}

void svPacketError::SyncWrite(void)
{
    svPacket::SyncWrite();
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
