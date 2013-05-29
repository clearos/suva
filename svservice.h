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

#ifndef _SVSERVICE_H
#define _SVSERVICE_H

using namespace std;

class svExServiceSystemCall : public runtime_error
{
public:
	explicit svExServiceSystemCall(
		const string &call, const string &what)
		: runtime_error(call + ": " + what) { };
	virtual ~svExServiceSystemCall() throw() { };
};

class svExServiceUnknownDescriptor : public runtime_error
{
public:
	explicit svExServiceUnknownDescriptor(const string &what)
		: runtime_error(what) { };
	virtual ~svExServiceUnknownDescriptor() throw() { };
};

class svService : public svEventClient
{
public:
	svService(const string &name, svConf *conf);
	virtual ~svService();

	static svConf *GetConf(void) { return conf; };

	virtual void Start(void) = 0;

	virtual void HandleStateRequest(void);

protected:
	svThreadSignal *thread_signal;
	vector<svSession *> session;
	vector<svSocket *> skt_listen;
	vector<svSocket *> skt_client;
	svSocketSet skt_set;
	map<string, map<string, svSession *> > vpn_client;

	static svConf *conf;

	void Daemonize(void);
	void StartSignalHandler(void);
	void SaveProcessId(void);
	void ProcessEvent(svEvent *event);
	void SwitchUserGroup(void);
	void CreateSockets(void);
	void SelectSockets(void);
	virtual void ClientSocketRead(svSocket *skt);

	virtual void CreateSessionConnect(svSocket *skt,
		svConfFrontDoor *sfd) = 0;
	virtual void CreateSessionConnect(svSocket *skt,
		svConfSessionTunnel *tunnel) = 0;
	virtual void CreateSessionAccept(svSocket *skt) = 0;

	void CreateSession(svSession *s);
	virtual void DestroySession(svSession *s);

	void CreateVpnClientThreads(void);
};

#endif // _SVSERVICE_H
// vi: ts=4
