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

#include <sys/types.h>
#include <sys/time.h>

#ifdef HAVE_SYS_SIGNAL_H
#include <sys/signal.h>
#endif

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <expat.h>
#include <signal.h>
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
#include "svpool.h"
#include "svevent.h"
#include "svthread.h"
#include "svutil.h"
#include "svexec.h"

#ifndef __ANDROID__
extern int errno;
#endif

svExec::svExec(const svConfSessionApp &conf_app,
    const string &dev, const string &org, const string &session,
    const string &remote_host)
    : svEventClient("svExec"), pid(-1), skt(NULL), exited(false)
{
    name = conf_app.GetName();
    path = conf_app.GetPath();
    args = conf_app.GetArgs();

    argv = new char *[args.size() + 2];
    argv[0] = strdup(path.c_str());
    for (uint32_t i = 0; i < args.size(); i++)
        argv[i + 1] = strdup(args[i].c_str());
    argv[args.size() + 1] = NULL;

    envp = new char *[4 + 1];
    ostringstream os;
    os << "SUVA_DEVICE=" << dev;
    envp[0] = strdup(os.str().c_str());
    os.str("");
    os << "SUVA_ORGANIZATION=" << org;
    envp[1] = strdup(os.str().c_str());
    os.str("");
    os << "SUVA_SESSION=" << session;
    envp[2] = strdup(os.str().c_str());
    os.str("");
    os << "SUVA_REMOTE_HOST=" << remote_host;
    envp[3] = strdup(os.str().c_str());
    envp[4] = NULL;

    conf_app.GetDescriptors(fd_read, fd_write);
}

svExec::~svExec()
{
#if defined(__WIN32__) || defined(__ANDROID__)
    if (skt) delete skt;
    if (pid != -1) Terminate();
#endif
    for (uint32_t i = 0; argv[i] && i < args.size() + 2; i++)
        free(argv[i]);
    delete [] argv;
    for (uint32_t i = 0; envp[i] && i < 4 + 1; i++)
        free(envp[i]);
    delete [] envp;
}

svSocket *svExec::Execute(void)
{
#if defined(__WIN32__) || defined(__ANDROID__)
    return NULL;
#else
    int sp[2];
    int fd_null = -1;
    long max_fd = sysconf(_SC_OPEN_MAX);
    if (max_fd == -1) max_fd = FD_SETSIZE;

    skt = new svSocketPair();
    skt->GetDescriptor(sp);

    switch ((pid = fork())) {
    case 0:
        if ((fd_null = open("/dev/null", O_RDWR)) == -1) {
            syslog(LOG_ERR,
                "open: %s: %s.", "/dev/null", strerror(errno));
            exit(-1);
        }
        if (dup2(fd_null, STDIN_FILENO) == -1) exit(-1);
        if (dup2(fd_null, STDOUT_FILENO) == -1) exit(-1);
        if (dup2(fd_null, STDERR_FILENO) == -1) exit(-1);
        if (dup2(sp[1], fd_read) == -1) exit(-1);
        if (fd_read != fd_write &&
            dup2(sp[1], fd_write) == -1) exit(-1);
        sigset_t signal_set;
        sigfillset(&signal_set);
        pthread_sigmask(SIG_UNBLOCK, &signal_set, NULL);
        for (long i = 0; i < max_fd; i++) {
            if (i == fd_read || i == fd_write ||
                i == STDIN_FILENO || i == STDOUT_FILENO ||
                i == STDERR_FILENO) continue;
            close(i);
        }
        setsid();
        execve(path.c_str(), argv, envp);
        syslog(LOG_ERR, "execl: %s: %s",
            path.c_str(), strerror(errno));
        exit(-1);

    case -1:
        throw svExExecFork();
    }

    svSocket *rc = skt;
    skt = NULL;

    return rc;
#endif
}

void svExec::Exited(int status)
{
#if !defined(__WIN32__) && !defined(__ANDROID__)
    pid = -1;
    exited = true;
    if (WIFEXITED(status)) {
        svLog("%s: Exited with code: %d",
            name.c_str(), WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        svLog("%s: Exited by signal: %s",
            name.c_str(), strsignal(WTERMSIG(status)));
    }
    else svError("%s: Did not exit normally");
#endif
}

void svExec::Terminate(void)
{
#if !defined(__WIN32__) && !defined(__ANDROID__)
    if (pid == -1) return;
    if (skt) {
        delete skt;
        skt = NULL;
    }

    struct timeval tv_now, tv_timeout;
    gettimeofday(&tv_timeout, NULL);
    tv_timeout.tv_sec += _SUVA_APP_WAIT;

    svEvent *event;
    for ( ;; ) {
        while ((event = PopWaitEvent(1000))) {
            switch (event->GetId()) {
            case svEVT_QUIT:
                return;

            case svEVT_CHILD_EXIT:
                svEventChildExit *event_child;
                event_child = (svEventChildExit *)event;
                if (event_child->GetPid() != pid)
                    break;
                Exited(event_child->GetStatus());
                delete event_child;
                return;

            default:
                break;
            }

            delete event;
        }

        gettimeofday(&tv_now, NULL);
        if (tv_now.tv_sec > tv_timeout.tv_sec) {
            kill(pid, SIGTERM);
            svError("%s: Timed-out waiting on application to exit: %d",
                name.c_str(), pid);
            break;
        }
    }
#endif
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
