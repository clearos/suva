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

#ifndef _SVCLIENT_H
#define _SVCLIENT_H

using namespace std;

#ifdef __WIN32__
class svExConfScmOpen : public runtime_error
{
public:
	explicit svExConfScmOpen(int errid)
		: runtime_error("Error opening service control manager"),
		errid(errid) { };
	virtual ~svExConfScmOpen() throw() { };
	int errid;
};

class svExConfCreateService : public runtime_error
{
public:
	explicit svExConfCreateService(int errid)
		: runtime_error("Error creating service"), errid(errid) { };
	virtual ~svExConfCreateService() throw() { };
	int errid;
};

class svExConfCreateRegKey : public runtime_error
{
public:
	explicit svExConfCreateRegKey(int errid)
		: runtime_error("Error creating/modifying registry key/value"),
		errid(errid) { };
	virtual ~svExConfCreateRegKey() throw() { };
	int errid;
};

class svExConfServiceRegisterRequest : public runtime_error
{
public:
	explicit svExConfServiceRegisterRequest()
		: runtime_error("Service register request") { };
	virtual ~svExConfServiceRegisterRequest() throw() { };
};

class svExConfServiceUnregisterRequest : public runtime_error
{
public:
	explicit svExConfServiceUnregisterRequest()
		: runtime_error("Service unregister request") { };
	virtual ~svExConfServiceUnregisterRequest() throw() { };
};
#endif

class svConfClient : public svConf
{
public:
	svConfClient(int argc, char *argv[]) :
		svConf(argc, argv) { Load(); };
	virtual void Usage(bool version = false);
#ifdef __WIN32__
	virtual void ParseOptions(void);
#endif

protected:
	void RegisterService(const char *name,
		const char *display_name, const char *description);
};

class svClient : public svService
{
public:
	svClient(svConf *conf);
	virtual ~svClient();

	void Start(void);

	virtual void HandleStateRequest(void);

protected:
	map<string, svThreadKeyPoll *> key_poll;
	map<string, svPublicRSAKey *> public_key;
	map<string, map<string, svSession *> > pool_client;

	void CreateSessionConnect(svSocket *skt,
		svConfFrontDoor *sfd);
	void CreateSessionConnect(svSocket *skt,
		svConfSessionTunnel *tunnel);
	void CreateSessionAccept(svSocket *skt);
	void CreatePoolClientThreads(void);

	void KeyPollRequest(svEventKeyPollRequest *request);
	void KeyPollResult(svEventKeyPollResult *result);
	void PoolClientDelete(svEventPoolClientDelete *event);
};

#endif // _SVCLIENT_H
// vi: ts=4
