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
#include <queue>

#include <sys/time.h>

#ifndef __WIN32__
#include <sys/syscall.h>
#endif

#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <expat.h>
#include <string.h>
#include <pthread.h>

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/dso.h>

#include "svoutput.h"
#include "svobject.h"
#include "svconf.h"
#include "svcrypto.h"
#include "svpacket.h"
#include "svsocket.h"
#include "svplugin.h"
#include "svkeyring.h"
#include "svpool.h"
#include "svevent.h"
#include "svthread.h"

#ifndef __ANDROID__
extern int errno;
#endif

static void *sv_thread_entry(void *param)
{
    svThread *thread = (svThread *)param;
#if defined(__linux__) && !defined(__ANDROID__)
    pid_t tid = (pid_t)syscall(SYS_gettid);
    //pid_t tid = __sync_fetch_and_add(&__tid_base, 1);
    thread->SetThreadId(tid);
#endif
    return thread->Entry();
}

svThread::svThread(const string &name, size_t stack_size)
    : svEventClient(name)
{
    int rc;
    if ((rc = pthread_attr_init(&attr)) != 0)
        throw svExThread(name, "pthread_attr_init", strerror(rc));
    if ((rc = pthread_attr_setstacksize(&attr, stack_size)) != 0)
        throw svExThread(name, "pthread_attr_setstacksize", strerror(rc));
#ifndef __WIN32__
    id = 0;
#endif
}

void svThread::Start(void)
{
    int rc;
    if ((rc = pthread_create(&id, &attr, &sv_thread_entry, (void *)this)) != 0)
        throw svExThread(name, "pthread_create", strerror(rc));
}

void svThread::Join(void)
{
    int rc;
    if ((rc = pthread_attr_destroy(&attr)) != 0)
        svError("%s: pthread_attr_destroy: %s", name.c_str(), strerror(rc));
#ifndef __WIN32__
    if (id != 0 && (rc = pthread_join(id, NULL)) != 0)
        svError("%s: pthread_join: %s", name.c_str(), strerror(rc));
#else
    if ((rc = pthread_join(id, NULL)) != 0)
        svError("%s: pthread_join: %s", name.c_str(), strerror(rc));
#endif
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
