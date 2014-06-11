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
#include <iostream>
#include <iomanip>
#include <string>
#include <sstream>
#include <stdexcept>
#include <vector>
#include <map>

#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <expat.h>

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#include <sys/time.h>

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
#include "svservice.h"

#ifndef __ANDROID__
extern int errno;
#endif

svConf *svService::conf = NULL;

svService::svService(const string &name, svConf *conf)
    : svEventClient(name), thread_signal(NULL)
{
    svService::conf = conf;
    svOutput::OpenSyslog(name.c_str(),
        conf->GetLogFacility(), conf->GetDebug());
    string log_file = conf->GetLogFile();
    if (log_file.size())
        svOutput::OpenLogFile(log_file);

    svCrypto::Initialize();
    svSocket::Initialize();
}

svService::~svService()
{
    for (vector<svSocket *>::iterator i = skt_listen.begin();
        i != skt_listen.end(); i++) delete (*i);
    skt_listen.clear();

    for (vector<svSession *>::iterator i = session.begin();
        i != session.end(); i++) {
        //svEventQueue::Push(new svEventSessionQuit((*i)));
        delete (*i);
    }

    if (thread_signal) delete thread_signal;

    string pid_file(conf->GetPidFile());
    if (pid_file.size()) unlink(pid_file.c_str());

    if (conf) delete conf;

    svSocket::Uninitialize();
    svCrypto::Uninitialize();
}

void svService::HandleStateRequest(void)
{
    svDebug("%s: sessions: %ld", name.c_str(), session.size());

    map<string, map<string, svSession *> >::iterator vci;
    for (vci = vpn_client.begin(); vci != vpn_client.end(); vci++) {
        svDebug("%s: VPN clients: %s: %ld",
            name.c_str(), vci->first.c_str(), vci->second.size());
    }

    for (vector<svSocket *>::iterator i = skt_listen.begin();
        i != skt_listen.end(); i++) (*i)->DumpState();
}

void svService::Daemonize(void)
{
#ifndef __WIN32__
    if (!conf->GetDebug() && daemon(1, 0) != 0)
        throw svExServiceSystemCall("daemon", strerror(errno));
#endif
}

void svService::StartSignalHandler(void)
{
#ifndef __WIN32__
    int rc;
    sigset_t signal_set;
    sigfillset(&signal_set);
    sigdelset(&signal_set, SIGPROF);

    if ((rc = pthread_sigmask(SIG_BLOCK, &signal_set, NULL)) != 0)
        throw svExServiceSystemCall("pthread_sigmask", strerror(rc));

    sigemptyset(&signal_set);
    sigaddset(&signal_set, SIGINT);
    sigaddset(&signal_set, SIGHUP);
    sigaddset(&signal_set, SIGTERM);
    sigaddset(&signal_set, SIGPIPE);
    sigaddset(&signal_set, SIGCHLD);
    sigaddset(&signal_set, SIGALRM);
    sigaddset(&signal_set, SIGUSR1);
    sigaddset(&signal_set, SIGUSR2);

    thread_signal = new svThreadSignal(signal_set);
    thread_signal->SetDefaultDest(this);
    thread_signal->Start();
#endif
}

void svService::SaveProcessId(void)
{
#ifndef __WIN32__
    string pid_file(conf->GetPidFile());
    FILE *h_pid = fopen(pid_file.c_str(), "w+");
    if (!h_pid)
        svError("%s: %s", pid_file.c_str(), strerror(errno));
    else {
        fprintf(h_pid, "%d\n", getpid());
        fclose(h_pid);
    }
#endif
}

void svService::ProcessEvent(svEvent *event)
{
    switch (event->GetId()) {
    case svEVT_SESSION_EXIT:
        DestroySession((svSession *)event->GetSource());
        break;
    case svEVT_CONF_RELOAD:
        break;
    default:
        break;
    }
}

void svService::SwitchUserGroup(void)
{
#ifndef __WIN32__
    uid_t uid;
    gid_t gid;
    conf->GetUidGid(uid, gid);
    if (gid != getegid()) {
        if (setegid(gid) < 0) {
            svError("%s: setegid(%d): %s",
                name.c_str(), gid, strerror(errno));
        }
        else {
            svDebug("%s: Set effective GID to %d",
                name.c_str(), gid);
        }
    }
    if (uid != geteuid()) {
        if (seteuid(uid) < 0) {
            svError("%s: seteuid(%d): %s",
                name.c_str(), uid, strerror(errno));
        }
        else {
            svDebug("%s: Set effective UID to %d: %s",
                name.c_str(), uid, strerror(errno));
        }
    }
#endif
}

void svService::CreateSockets(void)
{
    for (vector<svSocket *>::iterator i = skt_listen.begin();
        i != skt_listen.end(); i++) delete (*i);
    skt_listen.clear();

    vector<svConfSocket *> stl_port = conf->GetSTLPorts();
    for (vector<svConfSocket *>::iterator i = stl_port.begin();
        i != stl_port.end(); i++) {
        svSocket *skt = NULL;
        try {
            skt = svSocket::Create(*(*i));
            skt_listen.push_back(skt);
        } catch (exception &e) {
            svError("%s: Error creating socket: %s",
                name.c_str(), e.what());
            if (skt) delete skt;
        }
    }

    map<string, svConfFrontDoor *> fd = conf->GetFrontDoors();
    for (map<string, svConfFrontDoor *>::iterator i = fd.begin();
        i != fd.end(); i++) {
        svSocket *skt = NULL;
        try {
            skt = svSocket::Create(i->second->GetConfSocket());
            skt->SetRaw();
            skt->SetFrontDoor();
            skt->SetSession(i->first);
            skt_listen.push_back(skt);
        } catch (exception &e) {
            svError("%s: Error creating socket: %s",
                name.c_str(), e.what());
            if (skt) delete skt;
        }
    }

    map<string, svConfOrganization *> org;
    org = conf->GetOrganizations();
    map<string, svConfOrganization *>::iterator oi;
    for (oi = org.begin(); oi != org.end(); oi++) {
        map<string, svConfSession *> s;
        s = oi->second->GetSessions();
        map<string, svConfSession *>::iterator si;
        for (si = s.begin(); si != s.end(); si++) {
            if (si->second->GetType() != svSE_TUNNEL) continue;
            svConfSessionTunnel tunnel(
                (const svConfSessionTunnel &)*si->second);
            svConfSocket skt_conf(tunnel.GetConfSocketListen());
            if (skt_conf.GetMode() != svSM_LISTEN) continue;
            svSocket *skt = NULL;
            try {
                skt = svSocket::Create(skt_conf);
                skt->SetRaw();
                skt->SetSession(si->first);
                skt->SetOrganization(oi->first);
                skt_listen.push_back(skt);
            } catch (exception &e) {
                svError("%s: Error creating socket: %s",
                    name.c_str(), e.what());
                if (skt) delete skt;
            }
        }
    }

    skt_set.Reset();
    for (vector<svSocket *>::iterator i = skt_listen.begin();
        i != skt_listen.end(); i++) skt_set.SelectForRead((*i));
}

void svService::SelectSockets(void)
{
    int rc;
    while ((rc = skt_set.Select(_SUVA_DEFAULT_DELAY)) > 0) {
        vector<svSocket *>::iterator i = skt_listen.begin();
        while (rc > 0 && i != skt_listen.end()) {
            if (!skt_set.IsReadyForRead((*i))) {
                i++;
                continue;
            }

            rc--;

            svSocket *skt_accept = NULL;
            try {
                skt_accept = (*i)->Accept();
            } catch (svExSocketSyscall &e) {
                svError("%s: Error accepting connection: %s",
                    name.c_str(), e.what());
                skt_set.RemoveForRead((*i));
                delete (*i);
                skt_listen.erase(i);
                i = skt_listen.begin();
                continue;
            }

            if (skt_accept->IsFrontDoor()) {
                svConfFrontDoor *sfd =
                    conf->GetFrontDoor(skt_accept->GetSession());
                if (!sfd) {
                    svError("%s: Front door not found: %s",
                        name.c_str(), skt_accept->GetSession().c_str());
                    delete skt_accept;
                }
                else {
                    try {
                        CreateSessionConnect(skt_accept, sfd);
                    } catch (runtime_error &e) {
                        svError("%s: %s", name.c_str(), e.what());
                        delete skt_accept;
                    }
                }
            }
            else if (skt_accept->IsRaw()) {
                svConfOrganization *org =
                    conf->GetOrganization(skt_accept->GetOrganization());
                svConfSessionTunnel *tunnel = NULL;
                if (org) {
                    tunnel = (svConfSessionTunnel *)org->GetSession(
                        skt_accept->GetSession());
                    if (tunnel && tunnel->GetType() != svSE_TUNNEL)
                        tunnel = NULL;
                }
                if (!org || !tunnel) {
                    svError("%s: Tunnel session not found: %s",
                        name.c_str(), skt_accept->GetSession().c_str());
                    delete skt_accept;
                }
                else {
                    try {
                        CreateSessionConnect(skt_accept, tunnel);
                    } catch (runtime_error &e) {
                        svError("%s: %s", name.c_str(), e.what());
                        delete skt_accept;
                    }
                }
            }
            else {
                try {
                    CreateSessionAccept(skt_accept);
                } catch (runtime_error &e) {
                    svError("%s: %s", name.c_str(), e.what());
                    delete skt_accept;
                }
            }
            i++;
        }

        i = skt_client.begin();
        while (rc > 0 && i != skt_client.end()) {
            if (!skt_set.IsReadyForRead((*i))) {
                i++;
                continue;
            }

            rc--;

            try {
                svDebug("%s: clients: %d",
                    name.c_str(), skt_client.size());
                ClientSocketRead((*i));
            } catch (runtime_error &e) {
                skt_set.RemoveForRead((*i));
                delete (*i);
                skt_client.erase(i);
                i = skt_client.begin();
                svDebug("%s: clients after exception: %d",
                    name.c_str(), skt_client.size());
                continue;
            }

            i++;
        }

        if (rc > 0) {
            throw svExServiceUnknownDescriptor(
                "Event on unknown descriptor");
        }
    }
}

void svService::ClientSocketRead(svSocket *skt)
{
    throw svExSocketHangup();
}

void svService::CreateSession(svSession *s)
{
#if 0
    for (vector<svSession *>::iterator i = session.begin();
        i != session.end(); i++) {
        svDebug("%s: %s [%s]", name.c_str(), (*i)->GetName().c_str(),
            (*i)->GetOrganization().c_str());
    }
    svDebug("%s: %s [%s]", name.c_str(), s->GetName().c_str(),
        s->GetOrganization().c_str());
#endif
    session.push_back(s);
    s->SetDefaultDest(this);
    s->Start();
}

void svService::DestroySession(svSession *s)
{
    if (s->GetType() != svSE_VPN) {
        for (vector<svSession *>::iterator i = session.begin();
            i != session.end(); i++) {
            if (s != (*i)) continue;
            session.erase(i);
            break;
        }
    
        delete s;
    }
    else {
        map<string, map<string, svSession *> >::iterator vci;
        vci = vpn_client.find(s->GetOrganization());
        if (vci != vpn_client.end()) {
            for (map<string, svSession *>::iterator i = vci->second.begin();
                i != vci->second.end(); i++) {
                if (s != i->second) continue;
                vci->second.erase(i);
                break;
            }
        }

        delete s;
        CreateVpnClientThreads();
    }
}

void svService::CreateVpnClientThreads(void)
{
    map<string, svConfOrganization *> org;
    org = conf->GetOrganizations();
    map<string, svConfOrganization *>::iterator oi;

    for (oi = org.begin(); oi != org.end(); oi++) {
        map<string, map<string, svSession *> >::iterator vci;
        vci = vpn_client.find(oi->first);

        map<string, svConfSession *> conf_session = oi->second->GetSessions();
        map<string, svConfSession *>::iterator si;

        for (si = conf_session.begin(); si != conf_session.end(); si++) {
            if (si->second->GetType() != svSE_VPN) continue;
            if (vci != vpn_client.end() &&
                vci->second.find(si->second->GetName()) != vci->second.end()) continue;
            svConfSessionVpn *conf_vpn = (svConfSessionVpn *)
                si->second;
            svConfSocket skt_connect(conf_vpn->GetConfSocketConnect());
            if (skt_connect.GetMode() == svSM_NULL) continue;

            svSessionClientConnect *client = NULL;
            try {
                client = new svSessionClientConnect(
                    oi->first,
                    *((svConfSessionVpn *)si->second));
                vpn_client[oi->first][si->second->GetName()] = client;
                client->Start();
                client->SetDefaultDest(this);
                svLog("Creating VPN session: %s", si->second->GetName().c_str());
            } catch (runtime_error &e) {
                svLog("Failed VPN session: %s", si->second->GetName().c_str());
                svError("%s: %s: Error starting VPN session: %s: %s",
                    name.c_str(), oi->first.c_str(),
                    si->second->GetName().c_str(), e.what());
            }
        }
    }
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
