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

#ifndef _SVUTIL_H
#define _SVUTIL_H

using namespace std;

void svLegalizeString(string &dst, const char *src, size_t src_len);
void svHexDump(FILE *fh, const void *data, uint32_t length);
void svBacktrace(void);
long svGetPageSize(void);

#ifdef HAVE_USLEEP
#define svDelay(d)  usleep(d * 1000)
#else
int svDelay(int ms);
#endif

class svMutexLocker
{
public:
    svMutexLocker(pthread_mutex_t *mutex)
        : mutex(mutex) { pthread_mutex_lock(mutex); };

    virtual ~svMutexLocker() { pthread_mutex_unlock(mutex); };

protected:
    pthread_mutex_t *mutex;
};

#endif // _SVUTIL_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
