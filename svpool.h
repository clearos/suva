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

#ifndef _SVPOOL_H
#define _SVPOOL_H

using namespace std;

class svPoolClient : public svObject
{
public:
	svPoolClient(svSocket *skt,
		const string &name, const string &device, const string &org);
	virtual ~svPoolClient();

	svSocket *GetSocket(bool remove = false);
	const string &GetDevice(void) const { return device; };
	const string &GetOrganization(void) const { return org; };

	void SetSocket(svSocket *skt) { this->skt = skt; };

protected:
	svSocket *skt;
	string device;
	string org;
	struct timeval tv;
};

#endif // _SVPOOL_H
// vi: ts=4
