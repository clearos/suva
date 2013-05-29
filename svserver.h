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

#ifndef _SVSERVER_H
#define _SVSERVER_H

using namespace std;

class svConfServer : public svConf
{
public:
	svConfServer(int argc, char *argv[]) :
		svConf(argc, argv) { Load(); };
	virtual void Usage(bool version = false);
	virtual void Save(bool client = true) { svConf::Save(false); };
};

class svServer : public svService
{
public:
	svServer(svConf *conf);
	~svServer();

	void Start(void);

protected:
	map<string, svKeyRing *> key_ring;
	map<string, svThreadStorage *> storage;
	map<string, map<string, vector<svPoolClient *> > > pool;

	void LoadKeyRing(void);
	void CreateStorageThreads(void);
	virtual void ClientSocketRead(svSocket *skt);

	void CreateSessionConnect(svSocket *skt,
		svConfFrontDoor *sfd);
	void CreateSessionConnect(svSocket *skt,
		svConfSessionTunnel *tunnel);
	void CreateSessionAccept(svSocket *skt);

	void KeyRingRequest(svEventKeyRingRequest *request);
	void HostKeyRequest(svEventHostKeyRequest *request);
	void HostKeyResult(svEventHostKeyResult *result);

	void PoolClientSave(svEventPoolClientSave *event);
	void PoolClientLoad(svEventPoolClientLoad *event);
};

#endif // _SVSERVER_H
// vi: ts=4
