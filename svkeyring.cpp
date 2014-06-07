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
#include <algorithm>
#include <queue>

#include <sys/types.h>
#include <sys/time.h>

#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
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
#include <openssl/pem.h>

#include "svoutput.h"
#include "svobject.h"
#include "svconf.h"
#include "svcrypto.h"
#include "svpacket.h"
#include "svsocket.h"
#include "svutil.h"
#include "svkeyring.h"

#ifndef __ANDROID__
extern int errno;
#endif

static bool svRSAKeySort(svRSAKey *a, svRSAKey *b)
{
    return (a->GetLastModified() > b->GetLastModified());
}

svKeyRing::svKeyRing(const string &key_dir)
    : svObject("svKeyRing")
{
    Load(key_dir);
}

svKeyRing::~svKeyRing()
{
    Clear();
}

void svKeyRing::Load(const string &key_dir)
{
    Clear();

    if (chdir(key_dir.c_str()) == -1)
        throw svExKeyRingChangeDirectory(key_dir, strerror(errno));

    DIR *dir;
    if (!(dir = opendir(key_dir.c_str())))
        throw svExKeyRingOpenDirectory(key_dir, strerror(errno));

    vector<string> pem;

    struct dirent *de;
    while ((de = readdir(dir))) {
        string d_name = de->d_name;
        size_t pos;
        if ((pos = d_name.find_last_of('.')) == string::npos)
            continue;
        if (d_name.substr(pos) != ".pem") continue;
        pem.push_back(d_name);
    }
    closedir(dir);

    for (vector<string>::iterator i = pem.begin();
        i != pem.end(); i++) {
        svRSAKey *key = NULL;
        try {
            key = new svRSAKey((*i));
        } catch (runtime_error &e) {
            svError("%s: %s", name.c_str(), e.what());
            continue;
        }
        if (key && key->GetType() == svRSA_TYPE_PUBLIC)
            key_public.push_back(key);
        else if (key && key->GetType() == svRSA_TYPE_PRIVATE)
            key_private.push_back(key);
    }

    sort(key_public.begin(), key_public.end(), svRSAKeySort);
    sort(key_private.begin(), key_private.end(), svRSAKeySort);
}

void svKeyRing::Copy(svRSAKeyType type, vector<RSA *> &key_ring)
{
    switch (type) {
    case svRSA_TYPE_PUBLIC:
        for (vector<svRSAKey *>::iterator i = key_public.begin();
            i != key_public.end(); i++)
            key_ring.push_back((*i)->Duplicate());
        break;

    case svRSA_TYPE_PRIVATE:
        for (vector<svRSAKey *>::iterator i = key_private.begin();
            i != key_private.end(); i++)
            key_ring.push_back((*i)->Duplicate());
        break;
    default:
        break;
    }
}

uint32_t svKeyRing::GetCount(svRSAKeyType type)
{
    switch (type) {
    case svRSA_TYPE_PUBLIC:
        return key_public.size();
    case svRSA_TYPE_PRIVATE:
        return key_private.size();
    default:
        return key_public.size() + key_private.size();
    }
}

void svKeyRing::Clear(void)
{
    for (vector<svRSAKey *>::iterator i = key_public.begin();
        i != key_public.end(); i++) {
        delete (*i);
    }
    key_public.clear();
    for (vector<svRSAKey *>::iterator i = key_private.begin();
        i != key_private.end(); i++) {
        delete (*i);
    }
    key_private.clear();
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
