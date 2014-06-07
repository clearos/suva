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
#include <exception>
#include <stdexcept>
#include <vector>
#include <map>
#include <queue>

#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <signal.h>
#include <pthread.h>
#include <expat.h>
#include <netdb.h>

#include <sys/time.h>

#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/dso.h>

#include "svutil.h"
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
#include "svkeyring.h"
#include "svstorage.h"
#include "svserver.h"

int main(int argc, char *argv[])
{
    int rc = 0;
    svEventServer *evt_server = NULL;
    svConfServer *conf = NULL;
    svServer *server = NULL;
    svOutput output;

    try {
        conf = new svConfServer(argc, argv);
        evt_server = new svEventServer();
        server = new svServer(conf);
        server->Start();
    } catch (svExConfUsageRequest &e) {
    } catch (svExConfSaveRequest &e) {
    } catch (svExConfOpen &e) {
        svError(e.what());
        rc = 1;
    } catch (svExConfParse &e) {
        svError("%s: row: %d, col: %d, byte: 0x%02x",
            e.what(), e.row, e.col, e.byte);
        rc = 1;
    } catch (runtime_error &e) {
        svError("Run-time exception: %s", e.what());
        rc = 1;
    } catch (exception &e) {
        svError("Uncaught exception: %s", e.what());
        rc = 1;
    }

    if (server) delete server;
    else if (conf) delete conf;
    if (evt_server) delete evt_server;

    closelog();
    return rc;
}

void svConfServer::Usage(bool version)
{
    svLog("Suva Server v%s Protocol v%d.%d: %s",
        PACKAGE_VERSION, _SUVA_PROTO_VER_MAJOR,
        _SUVA_PROTO_VER_MINOR, _SUVA_VER_RELEASE);
    if (!version) CommonUsage();
    throw svExConfUsageRequest();
}

svServer::svServer(svConf *conf)
    : svService("svServer", conf) { }

svServer::~svServer()
{
    for (map<string, svKeyRing *>::iterator i = key_ring.begin();
        i != key_ring.end(); i++) delete i->second;
    for (map<string, svThreadStorage *>::iterator i = storage.begin();
        i != storage.end(); i++) delete i->second;
}

void svServer::Start(void)
{
    CreateSockets();
    CreateVpnClientThreads();
    SwitchUserGroup();
    Daemonize();
    SaveProcessId();
    StartSignalHandler();
    LoadKeyRing();
    CreateStorageThreads();

    svEvent *event;
    for ( ;; ) {
        while ((event = PopEvent())) {
            switch (event->GetId())
            {
            case svEVT_QUIT:
                return;
            case svEVT_KEYRING_REQUEST:
                KeyRingRequest((svEventKeyRingRequest *)event);
                break;
            case svEVT_HOSTKEY_REQUEST:
                HostKeyRequest((svEventHostKeyRequest *)event);
                break;
            case svEVT_HOSTKEY_RESULT:
                HostKeyResult((svEventHostKeyResult *)event);
                break;
            case svEVT_POOLCLIENT_SAVE:
                PoolClientSave((svEventPoolClientSave *)event);
                break;
            case svEVT_POOLCLIENT_LOAD:
                PoolClientLoad((svEventPoolClientLoad *)event);
                break;
            default:
                ProcessEvent(event);
            }
            delete event;
        }
        SelectSockets();
    }
}

void svServer::LoadKeyRing(void)
{
    for (map<string, svKeyRing *>::iterator i = key_ring.begin();
        i != key_ring.end(); i++) delete i->second;
    key_ring.clear();

    map<string, svConfOrganization *> org;
    org = conf->GetOrganizations();
    map<string, svConfOrganization *>::iterator oi;
    for (oi = org.begin(); oi != org.end(); oi++) {
        string key_dir = oi->second->GetKeyDir();
        svKeyRing *kr = NULL;
        try {
            kr = new svKeyRing(key_dir);
        } catch (runtime_error &e) {
            svError("%s: %s", name.c_str(), e.what());
            continue;
        }
        if (!kr->GetCount()) {
            delete kr;
            continue;
        }
        key_ring[oi->first] = kr;
    }
}

void svServer::CreateStorageThreads(void)
{
    map<string, svConfOrganization *> org;
    org = conf->GetOrganizations();
    map<string, svConfOrganization *>::iterator oi;
    for (oi = org.begin(); oi != org.end(); oi++) {
        map<svConfDatabaseType, svConfDatabase *> db;
        db = oi->second->GetDatabases();
        if (!db.size()) continue;
        
        svThreadStorage *thread;
        thread = new svThreadStorage(oi->second->GetDevice(),
            oi->first, oi->second->GetKeyCacheTTL());
        map<svConfDatabaseType, svConfDatabase *>::iterator di;
        for (di = db.begin(); di != db.end(); di++)
            thread->AddStorageEngine(*(di->second));
        try {
            thread->SetDefaultDest(this);
            thread->Start();
        } catch (runtime_error &e) {
            svError("%s: Error starting storage engine: %s",
                name.c_str(), e.what());
            delete thread;
            continue;
        }
        storage[oi->first] = thread;
    }
}

void svServer::ClientSocketRead(svSocket *skt)
{
    bool found = false;
    map<string, map<string, vector<svPoolClient *> > >::iterator io;
    io = pool.find(skt->GetOrganization());

    if (io != pool.end()) {
        map<string, vector<svPoolClient *> >::iterator id;
        id = io->second.find(skt->GetDevice());

        if (id != io->second.end()) {
            vector<svPoolClient *>::iterator ic;

            for (ic = id->second.begin();
                ic != id->second.end(); ic++) {
                if ((*ic)->GetSocket() != skt) {
                    svError("%s: %s: Pool client active: %s",
                        name.c_str(), io->first.c_str(), id->first.c_str());
                    continue;
                }
                svError("%s: %s: Pool client hung-up: %s",
                    name.c_str(), io->first.c_str(), id->first.c_str());
                map<string, svThreadStorage *>::iterator is;
                is = storage.find((*ic)->GetOrganization());
                if (is != storage.end()) {
                    svEventServer::GetInstance()->Dispatch(
                        new svEventPoolClientUpdate(
                            is->second, (*ic)->GetName(),
                            (*ic)->GetDevice(), svPCS_OFFLINE));
                }
                (*ic)->GetSocket(true);
                delete (*ic);
                id->second.erase(ic);
                found = true;
                break;
            }

            if (!id->second.size()) io->second.erase(id);
        }
    }
    if (found) throw svExSocketHangup();
}

void svServer::CreateSessionConnect(svSocket *skt, svConfFrontDoor *sfd)
{
    svSessionServerConnect *server = NULL;
    try {
        server = new svSessionServerConnect(skt, *sfd);
        CreateSession(server);
    } catch (runtime_error &e) {
        svError("%s: Error starting session: %s", name.c_str(), e.what());
        if (server) delete server;
    }
}

void svServer::CreateSessionConnect(svSocket *skt,
    svConfSessionTunnel *tunnel)
{
    svSessionServerConnect *server = NULL;
    try {
        server = new svSessionServerConnect(skt, *tunnel);
        CreateSession(server);
    } catch (runtime_error &e) {
        svError("%s: Error starting session: %s", name.c_str(), e.what());
        if (server) delete server;
    }
}

void svServer::CreateSessionAccept(svSocket *skt)
{
    svSessionServerAccept *server = NULL;
    try {
        server = new svSessionServerAccept(skt);
        CreateSession(server);
    } catch (runtime_error &e) {
        svError("%s: Error starting session: %s", name.c_str(), e.what());
        if (server) delete server;
    }
}

void svServer::KeyRingRequest(svEventKeyRingRequest *request)
{
    vector<RSA *> kr;
    map<string, svKeyRing *>::iterator i;
    i = key_ring.find(request->GetOrganization());
    if (i != key_ring.end())
        key_ring[request->GetOrganization()]->Copy(request->GetType(), kr);
    svEventKeyRingResult *result = new svEventKeyRingResult(
        request->GetSource(), request->GetOrganization(), kr);
    svEventServer::GetInstance()->Dispatch(result);
}

void svServer::HostKeyRequest(svEventHostKeyRequest *request)
{
    svHostKey key;
    map<string, svThreadStorage *>::iterator i;
    i = storage.find(request->GetOrganization());

    if (i == storage.end()) {
        svEventServer::GetInstance()->Dispatch(
            new svEventHostKeyResult(this,
                request->GetSource(), request->GetDevice(),
                request->GetOrganization(), key));
        return;
    }

    if (i->second->GetHostKeyFromCache(request->GetDevice(), key)) {
        svEventServer::GetInstance()->Dispatch(
            new svEventHostKeyResult(this,
                request->GetSource(), request->GetDevice(),
                request->GetOrganization(), key));
        return;
    }

    if (i->second->AddHostKeyClient(
        request->GetDevice(), request->GetSource()) > 1) return;

    svEventHostKeyRequest *event = new svEventHostKeyRequest(NULL,
        request->GetDevice(), request->GetOrganization());
    event->SetDestination(i->second);
    svEventServer::GetInstance()->Dispatch(event);
}

void svServer::HostKeyResult(svEventHostKeyResult *result)
{
    map<string, svThreadStorage *>::iterator i;
    i = storage.find(result->GetOrganization());

    if (i == storage.end()) {
        svError("%s: Organization storage engine not found: %s",
            name.c_str(), result->GetOrganization().c_str());
        // TODO: throw...
        return;
    }

    i->second->BroadcastHostKeyResult(result);
}

void svServer::PoolClientSave(svEventPoolClientSave *event)
{
    svPoolClient *client = event->GetClient();
    svConfOrganization *org =
        conf->GetOrganization(client->GetOrganization());
    if (!org) {
        svError("%s: Organization not found: %s",
            name.c_str(), client->GetOrganization().c_str());
        delete client;
        return;
    }

    if (org->GetMaxPoolConnections() == 0) {
        svError("%s: %s: Pool connections disabled",
            name.c_str(), org->GetName().c_str());
        delete client;
        return;
    }

    map<string, map<string, vector<svPoolClient *> > >::iterator io;
    io = pool.find(client->GetOrganization());
    if (io != pool.end()) {
        map<string, vector<svPoolClient *> >::iterator id;
        id = io->second.find(client->GetDevice());
        if (id != io->second.end()) {
            if (id->second.size() >= org->GetMaxPoolConnections()) {
                svError("%s: %s: Maximum pool connections reached, "
                    "clients: %d", name.c_str(),
                    org->GetName().c_str(), skt_client.size());
                delete client;
                return;
            }
        }
    }

    svSocket *skt = client->GetSocket();
    skt->SetDevice(client->GetDevice());
    skt->SetOrganization(client->GetOrganization());
    skt->SetConnected();
    skt_client.push_back(skt);
    skt_set.SelectForRead(skt);

    pool[org->GetName()][client->GetDevice()].push_back(client);

    svLog("%s: Saved pool client: %s %s [%s] (%d)",
        name.c_str(), client->GetName().c_str(),
        client->GetDevice().c_str(), client->GetOrganization().c_str(),
        pool[org->GetName()][client->GetDevice()].size());

    map<string, svThreadStorage *>::iterator i;
    i = storage.find(client->GetOrganization());
    if (i != storage.end()) {
        svEventServer::GetInstance()->Dispatch(
            new svEventPoolClientUpdate(
                i->second, client->GetName(), client->GetDevice(),
                svPCS_IDLE));
    }

    for (io = pool.begin(); io != pool.end(); io++) {
        map<string, vector<svPoolClient *> >::iterator id;
        for (id = io->second.begin(); id != io->second.end(); id++) {
            vector<svPoolClient *>::iterator pci;
            for (pci = id->second.begin(); pci != id->second.end(); pci++) {
                svDebug("%s: Pool client: %s %s [%s]",
                    name.c_str(), (*pci)->GetName().c_str(),
                    (*pci)->GetDevice().c_str(), (*pci)->GetOrganization().c_str());
            }
        }
    }
}

void svServer::PoolClientLoad(svEventPoolClientLoad *event)
{
    svPoolClient *client = NULL;

    map<string, map<string, vector<svPoolClient *> > >::iterator io;
    io = pool.find(event->GetOrganization());
    if (io != pool.end()) {
        map<string, vector<svPoolClient *> >::iterator id;
        id = io->second.find(event->GetDevice());
        if (id != io->second.end() && id->second.size()) {
            client = id->second.back();
            id->second.pop_back();
            if (!id->second.size()) io->second.erase(id);
        }
    }

    if (client) {
        for (vector<svSocket *>::iterator i = skt_client.begin();
            i != skt_client.end(); i++) {
            if ((*i) != client->GetSocket()) continue;
            skt_client.erase(i);
            skt_set.RemoveForRead(client->GetSocket());
            break;
        }
        svLog("%s: Pool client found: %s %s [%s]",
            name.c_str(), client->GetName().c_str(),
            client->GetDevice().c_str(), event->GetOrganization().c_str());
        map<string, svThreadStorage *>::iterator i;
        i = storage.find(event->GetOrganization());
        if (i != storage.end()) {
            svEventServer::GetInstance()->Dispatch(
                new svEventPoolClientUpdate(
                    i->second, client->GetName(),
                    event->GetDevice(), svPCS_INUSE));
        }
    }
    else {
        svError("%s: %s: Pool client not found: %s", name.c_str(),
            event->GetOrganization().c_str(), event->GetDevice().c_str());
    }

    svEventServer::GetInstance()->Dispatch(
        new svEventPoolClientLoad(this, event->GetSource(), client));
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
