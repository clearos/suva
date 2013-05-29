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

#ifndef _SVSESSION_H
#define _SVSESSION_H

using namespace std;

class svExSessionKeyPollFailed : public runtime_error
{
public:
	explicit svExSessionKeyPollFailed(const string &org)
		: runtime_error(org + ": Key poll failed") { };
	virtual ~svExSessionKeyPollFailed() throw() { };
};

class svExSessionKeyRingRequestFailed : public runtime_error
{
public:
	explicit svExSessionKeyRingRequestFailed(const string &org)
		: runtime_error(org + ": Key ring request failed") { };
	virtual ~svExSessionKeyRingRequestFailed() throw() { };
};

class svExSessionHostKeyRequestFailed : public runtime_error
{
public:
	explicit svExSessionHostKeyRequestFailed(
		const string &dev, const string &org)
		: runtime_error(dev + " [" + org + "]: " +
		"Host key request failed") { };
	virtual ~svExSessionHostKeyRequestFailed() throw() { };
};

class svExSessionKeyPollRequest : public runtime_error
{
public:
	explicit svExSessionKeyPollRequest(const string &org)
		: runtime_error(org + ": Unhandled key poll request") { };
	virtual ~svExSessionKeyPollRequest() throw() { };
};

class svExSessionUnexpectedEvent : public runtime_error
{
public:
	explicit svExSessionUnexpectedEvent(svEventId expect, svEventId recv)
		: runtime_error("Unexpected event"), expect(expect), recv(recv) { };
	virtual ~svExSessionUnexpectedEvent() throw() { };
	svEventId GetExpected(void) { return expect; };
	svEventId GetReceived(void) { return recv; };
protected:
	svEventId expect;
	svEventId recv;
};

class svExSessionInvalidPacket : public runtime_error
{
public:
	explicit svExSessionInvalidPacket(svSocket *skt)
		: runtime_error("Invalid packet"), skt(skt) { };
	virtual ~svExSessionInvalidPacket() throw() { };
	svSocket *GetSocket(void);
protected:
	svSocket *skt;
};

class svExSessionInvalidOrganization : public runtime_error
{
public:
	explicit svExSessionInvalidOrganization(const string &org)
		: runtime_error(org) { };
	virtual ~svExSessionInvalidOrganization() throw() { };
};

class svExSessionInvalidPlugin : public runtime_error
{
public:
	explicit svExSessionInvalidPlugin(const string &plugin)
		: runtime_error(plugin) { };
	virtual ~svExSessionInvalidPlugin() throw() { };
};

class svExSessionInvalidSession : public runtime_error
{
public:
	explicit svExSessionInvalidSession(const string &session)
		: runtime_error(session) { };
	virtual ~svExSessionInvalidSession() throw() { };
};

class svExSessionInvalidSessionType : public runtime_error
{
public:
	explicit svExSessionInvalidSessionType(const string &type)
		: runtime_error(type) { };
	virtual ~svExSessionInvalidSessionType() throw() { };
};

class svExSessionInvalidVersion : public runtime_error
{
public:
	explicit svExSessionInvalidVersion()
		: runtime_error("Invalid verison") { };
	virtual ~svExSessionInvalidVersion() throw() { };
};

class svExSessionOrganizationMismatch : public runtime_error
{
public:
	explicit svExSessionOrganizationMismatch(const string &org)
		: runtime_error(org) { };
	virtual ~svExSessionOrganizationMismatch() throw() { };
};

class svExSessionAuthFailure : public runtime_error
{
public:
	explicit svExSessionAuthFailure(const string &what)
		: runtime_error(what) { };
	virtual ~svExSessionAuthFailure() throw() { };
};

class svExSessionUnsupported : public runtime_error
{
public:
	explicit svExSessionUnsupported(const string &what)
		: runtime_error(what) { };
	virtual ~svExSessionUnsupported() throw() { };
};

class svSocket;
class svSession : public svThread
{
public:
	svSession(svConfSessionType type);
	virtual ~svSession();

	virtual void *Entry(void) = 0;

	ssize_t FrontDoorWrite(const void *buffer, size_t length);
	const string &GetOrganization(void) const { return org; };

	svConfSessionType GetType(void) const { return type; };

protected:
	svConfSessionType type;
	svSocket *skt_stl;
	svSocket *skt_raw;
	svCrypto *crypto;
	svPluginFrontDoor *sfd;
	svExec *app;
	uint8_t pkt_buffer[_SUVA_MAX_PACKET_SIZE];
	uint8_t *pkt_payload;
	size_t pkt_payload_size;
	string device_local;
	string device_remote;
	string device_hostkey;
	string org;
	struct pkt_version_t rversion;
	uint32_t key_sync;
	struct timeval tv;
	struct timeval tv_key_change;
	uint32_t retry_interval;

	void Exit(void);
	svEvent *EventRequest(svEvent *request, svEventId reply);
	void VersionExchange(
		svPacketAuthVersion &pkt_ver_local,
		svPacketAuthVersion &pkt_ver_remote);
	virtual void KeyChange(void) = 0;
	virtual void Authenticate(void) = 0;
	virtual void UpdateTimer(void) = 0;
	void SessionAccept(void);
	void SessionConnect(void);
	void SessionRun(void);

	void VpnAccept(void);
	void VpnConnect(void);
};

class svSessionClient : public svSession
{
public:
	svSessionClient(svConfSessionType type);
	virtual ~svSessionClient();

	virtual void *Entry(void) = 0;

protected:
	uint32_t key_ttl;

	void KeyChange(void);
	void Authenticate(void);
	void UpdateTimer(void);
};

class svSessionClientConnect : public svSessionClient
{
public:
	svSessionClientConnect(svSocket *skt_raw,
		const svConfSessionTunnel &conf);
	svSessionClientConnect(svSocket *skt_raw,
		const svConfFrontDoor &conf);
	svSessionClientConnect(const string &org,
		const svConfSessionVpn &conf);
	virtual ~svSessionClientConnect();

	virtual void *Entry(void);
};

class svSessionClientAccept : public svSessionClient
{
public:
	svSessionClientAccept(svSocket *skt_stl);
	svSessionClientAccept(const string &org,
		const svConfSessionPool &conf);
	virtual ~svSessionClientAccept();

	virtual void *Entry(void);

protected:
	void PoolConnect(void);
};

class svSessionServer : public svSession
{
public:
	svSessionServer(svConfSessionType type);
	virtual ~svSessionServer();

	virtual void *Entry(void) = 0;

protected:
	uint32_t session_ttl;
	vector<RSA *> key_ring;

	void KeyChange(void);
	void Authenticate(void);
	void UpdateTimer(void);
};

class svSessionServerConnect : public svSessionServer
{
public:
	svSessionServerConnect(svSocket *skt_raw,
		const svConfSessionTunnel &conf);
	svSessionServerConnect(svSocket *skt_raw,
		const svConfFrontDoor &conf);
	svSessionServerConnect(const svConfSessionVpn &conf);
	virtual ~svSessionServerConnect();

	virtual void *Entry(void);
};

class svSessionServerAccept : public svSessionServer
{
public:
	svSessionServerAccept(svSocket *skt_stl);
	virtual ~svSessionServerAccept();

	virtual void *Entry(void);
};

#endif // _SVSESSION_H
// vi: ts=4
