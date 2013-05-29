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
#include <string>
#include <iostream>
#include <stdexcept>
#include <sstream>
#include <map>
#include <vector>

#include <sys/time.h>

#include <unistd.h>
#include <string.h>
#include <expat.h>
#include <pthread.h>

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#include <openssl/dso.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>

#include "svoutput.h"
#include "svobject.h"
#include "svconf.h"
#include "svcrypto.h"
#include "svpacket.h"
#include "svsocket.h"
#include "svutil.h"
#include "svpool.h"

svPoolClient::svPoolClient(svSocket *skt,
	const string &name, const string &device, const string &org)
	: svObject(name), skt(skt), device(device), org(org)
{
	gettimeofday(&tv, NULL);
}

svPoolClient::~svPoolClient()
{
	if (skt) delete skt;
}

svSocket *svPoolClient::GetSocket(bool remove)
{
	if (!remove) return skt;
	svSocket *s = skt; skt = NULL;
	return s;
}

// vi: ts=4
