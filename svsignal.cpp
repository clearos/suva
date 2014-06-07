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

#include <sys/types.h>
#include <sys/time.h>

#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <expat.h>
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
#include "svexec.h"
#include "svthread.h"
#include "svsession.h"
#include "svsignal.h"


svThreadSignal::svThreadSignal(const sigset_t &signal_set)
    : svThread("svThreadSignal"), signal_set(signal_set) { }

svThreadSignal::~svThreadSignal()
{
    pthread_kill(id, SIGTERM);

    Join();
}

void *svThreadSignal::Entry(void)
{
    pid_t pid;
    int rc, sig, status;

#ifndef __WIN32__
    for ( ;; ) {
        rc = sigwait(&signal_set, &sig);
        if (rc != 0) {
            svError("%s: sigwait: %s", name.c_str(), strerror(rc));
            break;
        }
        svDebug("%s: %s", name.c_str(), strsignal(sig));
        switch (sig) {
        case SIGINT:
        case SIGTERM:
            svEventServer::GetInstance()->Dispatch(new svEventQuit);
            return NULL;
        case SIGHUP:
            svEventServer::GetInstance()->Dispatch(
                new svEventConfReload(NULL));
            break;
        case SIGUSR1:
            svOutput::ToggleDebug();
            break;
        case SIGUSR2:
            svEventServer::GetInstance()->Dispatch(
                new svEventStateRequest());
            break;
        case SIGCHLD:
            while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
                svEventServer::GetInstance()->Dispatch(
                    new svEventChildExit(pid, status));
            }
            break;
        }
    }
#endif
    return NULL;
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
