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

#ifndef _SVKEYRING_H
#define _SVKEYRING_H

using namespace std;

class svExKeyRingChangeDirectory : public runtime_error
{
public:
    explicit svExKeyRingChangeDirectory(
        const string &key_dir, const string &what)
        : runtime_error(key_dir + ": " + what) { };
    virtual ~svExKeyRingChangeDirectory() throw() { };
};

class svExKeyRingOpenDirectory : public runtime_error
{
public:
    explicit svExKeyRingOpenDirectory(
        const string &key_dir, const string &what)
        : runtime_error(key_dir + ": " + what) { };
    virtual ~svExKeyRingOpenDirectory() throw() { };
};

class svKeyRing : public svObject
{
public:
    svKeyRing(const string &key_dir);
    virtual ~svKeyRing();

    void Load(const string &key_dir);
    void Copy(svRSAKeyType type, vector<RSA *> &key_ring);
    uint32_t GetCount(svRSAKeyType type = svRSA_TYPE_NULL);

protected:
    vector<svRSAKey *> key_public;
    vector<svRSAKey *> key_private;

    void Clear(void);
};

#endif // _SVKEYRING_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
