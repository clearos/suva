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

#ifndef _SVPACKET_H
#define _SVPACKET_H

using namespace std;

enum svPacketId
{
	PKT_ID_OPEN = 0x01,
	PKT_ID_AUTH = 0x02,

	// Unused: PKT_ID_POLL
	PKT_ID_RES0 = 0x03,

	PKT_ID_KEY = 0x04,
	PKT_ID_DATA = 0x05,

	// Unused/reserved
	PKT_ID_RES1 = 0x06,
	PKT_ID_RES2 = 0x07,

	PKT_ID_HANGUP = 0x08,
	PKT_ID_POOL = 0x09,

	PKT_ID_ERROR = 0xff
};

enum svPacketAuthId
{
	PKT_ARG_AUTH_VER = 0x01,
	PKT_ARG_AUTH_SYNC = 0x02,
	PKT_ARG_AUTH_ACK = 0x03,
	PKT_ARG_AUTH_KEY = 0x04,
	PKT_ARG_AUTH_KEYPOLL = 0x05
};

enum svPacketKeySyncMode
{
	PKT_ARG_KEY_NULL = 0x00,
	PKT_ARG_KEY_SYNC = 0x01,
	PKT_ARG_KEY_ACK	= 0x02
};

// Packet header
struct suva_packet_t
{
	// Packet ID
	uint8_t pid;
	// Packet arg 1
	uint8_t pa1;
	// Packet arg 2
	uint8_t pa2;
	// Payload pad length
	uint8_t pad;
	// Payload length
	uint16_t length;
};

// ID packet
struct pkt_id_t
{
	// Device name length
	uint8_t dev_length;
	// Organization length
	uint8_t org_length;
};

// Session packet
struct pkt_session_t
{
	// Session hostname
	uint8_t host_length;
	// Session name length
	uint8_t session_length;
};

// Version flags
#define PKT_VER_FLAG_LZOCOMP	0x01
#define PKT_VER_FLAG_POOL		0x02

// Version packet
struct pkt_version_t
{
	// Major bits
	uint8_t major;
	// Minor bits
	uint8_t minor;
	// Reserved
	uint8_t reserved;
	// Capability flags
	uint8_t flags;
};

#define _SUVA_MAX_PAYLOAD		8192
#define _SUVA_PKT_HEADER_SIZE	sizeof(struct suva_packet_t)
#define _SUVA_MAX_PACKET_SIZE	(_SUVA_MAX_PAYLOAD + _SUVA_PKT_HEADER_SIZE)

class svPacket : public svObject
{
public:
	svPacket(uint8_t *buffer);
	svPacket(uint8_t *buffer,
		svPacketId pid, uint8_t pa1, uint8_t pa2, uint16_t length);

	void SyncReadHeader(void);
	virtual void SyncRead(void) { SyncReadHeader(); };
	void SyncWriteHeader(void);
	virtual void SyncWrite(void) { SyncWriteHeader(); };

	virtual bool IsValid(void) { return true; };

	svPacketId GetId(void) { return (svPacketId)header.pid; };
	void SetId(svPacketId id) { header.pid = (uint8_t)id; };

	uint8_t GetArg1(void) { return header.pa1; };
	void SetArg1(uint8_t arg) { header.pa1 = arg; };

	uint8_t GetArg2(void) { return header.pa2; };
	void SetArg2(uint8_t arg) { header.pa2 = arg; };

	uint8_t GetPad(void) { return header.pad; };
	void SetPad(uint8_t pad) { header.pad = pad; };

	uint16_t GetPayloadLength(void) { return header.length; };
	void SetPayloadLength(uint16_t length) { header.length = length; };

	ssize_t GetPacketLength(void)
	{
		return _SUVA_PKT_HEADER_SIZE + header.length;
	};

	uint8_t *GetBuffer(void) { return buffer; };
	void SetBuffer(uint8_t *buffer) { this->buffer = buffer; };

	uint8_t *GetPayload(void)
	{
		return buffer + _SUVA_PKT_HEADER_SIZE;
	};

	void SetCrypto(svCrypto *crypto) { this->crypto = crypto; };
	void Encrypt(void);
	void Decrypt(void);

protected:
	uint8_t *buffer;
	struct suva_packet_t header;
	svCrypto *crypto;
};

class svPacketOpen : public svPacket
{
public:
	svPacketOpen(uint8_t *buffer);

	virtual void SyncRead(void);
	virtual void SyncWrite(void);

	void SetName(const string &name)
	{
		this->session_name = name;
	};
	void SetVersion(const struct pkt_version_t &version)
	{
		ver_major = version.major;
		ver_minor = version.minor;
	};
	const string &GetName(void) const { return session_name; };

protected:
	string session_name;
	uint32_t ver_major;
	uint32_t ver_minor;
};

class svPacketPool : public svPacket
{
public:
	svPacketPool(uint8_t *buffer);

	virtual void SyncRead(void);
	virtual void SyncWrite(void);

	void SetName(const string &name)
	{
		this->pool_name = name;
	};
	const string &GetName(void) const { return pool_name; };

protected:
	string pool_name;
};

class svPacketAuth : public svPacket
{
public:
	svPacketAuth(uint8_t *buffer);

	virtual void SyncRead(void);
	virtual void SyncWrite(void);
};

class svPacketAuthVersion : public svPacketAuth
{
public:
	svPacketAuthVersion(uint8_t *buffer);

	virtual void SyncRead(void);
	virtual void SyncWrite(void);

	virtual bool IsValid(void);

	const string &GetDevice(void) const { return dev; };
	void SetDevice(const string &dev);

	const string &GetOrganization(void) const { return org; };
	void SetOrganization(const string &org);

	svAESKeySize GetAESKeySize(void);
	void SetAESKeySize(svAESKeySize size);

	uint32_t GetVersionMajor(void) { return (uint32_t)version.major; };
	void SetVersionMajor(uint32_t v) { version.major = (uint8_t)v; };

	uint32_t GetVersionMinor(void) { return (uint32_t)version.minor; };
	void SetVersionMinor(uint32_t v) { version.minor = (uint8_t)v; };
	void SetVersion(uint32_t v1, uint32_t v2)
	{
		version.major = (uint8_t)v1;
		version.minor = (uint8_t)v2;
	};

	uint32_t GetVersionFlags(void) { return (uint32_t)version.flags; };
	void SetVersionFlags(uint32_t flags) { version.flags = (uint8_t)flags; };

protected:
	string dev;
	string org;
	struct pkt_id_t id;
	struct pkt_version_t version;
};

class svPacketAuthKeyPoll : public svPacketAuthVersion
{
public:
	svPacketAuthKeyPoll(uint8_t *buffer);

	virtual void SyncRead(void);
	virtual void SyncWrite(void);
};

class svPacketAuthKeySync : public svPacket
{
public:
	svPacketAuthKeySync(uint8_t *buffer);

	bool IsValid(void);
};

class svPacketAuthKeyAck : public svPacket
{
public:
	svPacketAuthKeyAck(uint8_t *buffer);

	bool IsValid(void);
};

class svPacketSessionKey : public svPacket
{
public:
	svPacketSessionKey(uint8_t *buffer,
		svPacketKeySyncMode mode = PKT_ARG_KEY_NULL);

	virtual void SyncRead(void);
	virtual void SyncWrite(void);

	bool IsValid(void);
};

class svPacketSessionKeySync : public svPacketSessionKey
{
public:
	svPacketSessionKeySync(uint8_t *buffer);

	virtual void SyncRead(void);
	virtual void SyncWrite(void);
};

class svPacketSessionKeyAck: public svPacketSessionKey
{
public:
	svPacketSessionKeyAck(uint8_t *buffer);

	virtual void SyncRead(void);
	virtual void SyncWrite(void);
};

class svPacketData : public svPacket
{
public:
	svPacketData(uint8_t *buffer);

	virtual void SyncRead(void);
	virtual void SyncWrite(void);
};

class svPacketHangup : public svPacket
{
public:
	svPacketHangup(uint8_t *buffer);

	virtual void SyncRead(void);
	virtual void SyncWrite(void);
};

class svPacketError : public svPacket
{
public:
	svPacketError(uint8_t *buffer);

	virtual void SyncRead(void);
	virtual void SyncWrite(void);
};

#endif // _SVPACKET_H
// vi: ts=4
