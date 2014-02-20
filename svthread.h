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

#ifndef _SVTHREAD_H
#define _SVTHREAD_H

#ifndef _SUVA_STACK_SIZE
#define _SUVA_STACK_SIZE        32768
#endif

using namespace std;

class svExThread : public runtime_error
{
public:
    explicit svExThread(const string &name, const string &func, const string &what)
        : runtime_error(name + ": " + func + ": " + what) { };
    virtual ~svExThread() throw() { };
};

class svThread : public svEventClient
{
public:
    svThread(const string &name,
        size_t stack_size = _SUVA_STACK_SIZE);
    virtual ~svThread() { };

    pthread_t GetId(void) { return id; };
    pid_t GetThreadId(void) { return tid; };
    void SetThreadId(pid_t tid) { this->tid = tid; };

    virtual void Start(void);
    virtual void *Entry(void) = 0;

protected:
    pid_t tid;
    pthread_t id;
    pthread_attr_t attr;

    void Join(void);
};

#endif // _SVTHREAD_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
