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

#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <getopt.h>
#include <expat.h>
#include <pthread.h>

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#include <sys/time.h>

#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/md5.h>
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
#include "svkeypoll.h"
#include "svclient.h"

#ifdef __WIN32__
#include "resources.h"

SERVICE_STATUS svServiceStatus;
SERVICE_STATUS_HANDLE svServiceStatusHandle;

static void svServiceMain(int argc, char *argv[]);
static void svServiceControlHandler(DWORD request);
#endif

extern int errno;

int main(int argc, char *argv[])
{
#ifdef __WIN32__
    SERVICE_TABLE_ENTRY service_table[2];
    service_table[0].lpServiceName = "Suva";
    service_table[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)svServiceMain;
    service_table[1].lpServiceName = NULL;
    service_table[1].lpServiceProc = NULL;

    if (!StartServiceCtrlDispatcher(service_table)) {
        switch (GetLastError()) {
        case ERROR_INVALID_DATA:
        case ERROR_SERVICE_ALREADY_RUNNING:
            return 1;
        }
    }
    else return 0;
#endif
    int rc = 0;
    svEventServer *evt_server = NULL;
    svConfClient *conf = NULL;
    svClient *client = NULL;
    svOutput output;

    try {
        conf = new svConfClient(argc, argv);
        evt_server = new svEventServer();
        client = new svClient(conf);
        client->Start();
    } catch (svExConfUsageRequest &e) {
    } catch (svExConfSaveRequest &e) {
#ifdef __WIN32__
    } catch (svExConfServiceRegisterRequest &e) {
    } catch (svExConfServiceUnregisterRequest &e) {
#endif
    } catch (svExConfOpen &e) {
        svError(e.what());
        rc = 1;
    } catch (svExConfParse &e) {
        svError("%s, row: %d, col: %d, byte: 0x%02x",
            e.what(), e.row, e.col, e.byte);
        rc = 1;
    } catch (svExSocketSelect &e) {
        svError("Socket select: %s", e.what());
    } catch (svExKeyPollTestFailure &e) {
        rc = 1;
    } catch (runtime_error &e) {
        svError("Run-time exception: %s", e.what());
        rc = 1;
    } catch (exception &e) {
        svError("Uncaught exception: %s", e.what());
        rc = 1;
    }

    if (client) delete client;
    else if (conf) delete conf;
    if (evt_server) delete evt_server;

    return rc;
}

#ifdef __WIN32
static void svServiceMain(int argc, char *argv[])
{
    svServiceStatus.dwServiceType = SERVICE_WIN32;
    svServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    svServiceStatus.dwControlsAccepted =
        SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    svServiceStatus.dwWin32ExitCode = 0;
    svServiceStatus.dwCheckPoint = 0;
    svServiceStatus.dwWaitHint = 0;

    svServiceStatusHandle = RegisterServiceCtrlHandler(
        "Suva", (LPHANDLER_FUNCTION)svServiceControlHandler);
    if (svServiceStatusHandle == (SERVICE_STATUS_HANDLE)0) return;

    int rc = 0;
    svEventServer *evt_server = NULL;
    svConfClient *conf = NULL;
    svClient *client = NULL;
    svOutput output;
    svOutput::OpenEventLog();

    try {
        conf = new svConfClient(argc, argv);
        evt_server = new svEventServer();
        client = new svClient(conf);
        svServiceStatus.dwCurrentState = SERVICE_RUNNING;
        SetServiceStatus(svServiceStatusHandle, &svServiceStatus);
        client->Start();
    } catch (exception &e) {
        rc = -1;
    }

    svServiceStatus.dwCurrentState = SERVICE_STOPPED;
    svServiceStatus.dwWin32ExitCode = rc;
    SetServiceStatus(svServiceStatusHandle, &svServiceStatus);

    if (client) delete client;
    else if (conf) delete conf;
    if (evt_server) delete evt_server;
}

static void svServiceControlHandler(DWORD request)
{
    switch (request) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        svEventServer::GetInstance()->Dispatch(new svEventQuit);
    }

    SetServiceStatus(svServiceStatusHandle, &svServiceStatus);
}
#endif

void svConfClient::Usage(bool version)
{
    svLog("Suva Client v%s Protocol v%d.%d: %s",
        PACKAGE_VERSION, _SUVA_PROTO_VER_MAJOR,
        _SUVA_PROTO_VER_MINOR, _SUVA_VER_RELEASE);
    if (!version) {
        CommonUsage();
#ifdef __WIN32__
        svLog("  -r, --register");
        svLog("    Register Windows service.");
        svLog("  -u, --unregister");
        svLog("    Unregister Windows service.");
#endif
    }
    throw svExConfUsageRequest();
}

void svConfClient::ParseOptions(void)
{
    int32_t rc;
    struct option suvad_options[] =
    {
        { "key-server-test", 1, 0, 'k' },
        { NULL, 0, 0, 0 }
    };

    for (optind = 1;; ) {
        int32_t o = 0;
        if ((rc = getopt_long(argc, argv,
#ifndef __WIN32__
            "Vc:o:p:f:dk:h?", suvad_options, &o)) == -1) break;
#else
            "Vc:o:p:f:dh?ru", suvad_options, &o)) == -1) break;
#endif
        switch (rc) {
        case 'k':
            key_server_test_org = optarg;
            break;
        }
    }

    ParseCommonOptions();

#ifdef __WIN32__
    if (service_register) {
        RegisterService("Suva", "Suva", "Suva Secure Services");
        svLog("Registered Windows service.");
        throw svExConfServiceRegisterRequest();
    }
#endif
}

#ifdef __WIN32__
void svConfClient::RegisterService(const char *name,
    const char *display_name, const char *description)
{
    char service_path[MAX_PATH];
    SC_HANDLE sc_manager = NULL;
    SC_HANDLE service = NULL;
    char key_applog[] =
        "SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\";
    HKEY key = NULL;
    HKEY key_param = NULL;
    char key_name[512];

    GetModuleFileName(NULL, service_path, MAX_PATH);

    try {
        // Open SCM
        sc_manager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
        if (sc_manager == NULL) throw svExConfScmOpen(GetLastError());

        // Register (create) service entry
        service = CreateService(sc_manager, name, display_name,
            SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, service_path,
            NULL,   // load-order group
            NULL,   // group member tag
            NULL,   // dependencies
            NULL,   // account
            NULL);  // password
        if (service == NULL) throw svExConfCreateService(GetLastError());

        // Create event log registry entries
        strcpy(key_name, key_applog);
        strcat(key_name, name);
        if (RegCreateKey(HKEY_LOCAL_MACHINE, key_name, &key) != ERROR_SUCCESS)
            throw svExConfCreateRegKey(GetLastError());

        RegSetValueEx(key, "EventMessageFile", 0, REG_EXPAND_SZ,
            (const BYTE *)service_path, strlen(service_path) + sizeof(char));

        // Set the supported event types
        DWORD dwData = EVENTLOG_ERROR_TYPE |\
            EVENTLOG_WARNING_TYPE | EVENTLOG_INFORMATION_TYPE;
        RegSetValueEx(key, "TypesSupported", 0, REG_DWORD,
            (const BYTE *)&dwData, sizeof (DWORD));

        RegCloseKey(key);

        // Set optional description and/or start-up parameters
        if (description != NULL || argc > 2) {
            // Create registry key path 
            strcpy(key_name, "SYSTEM\\CurrentControlSet\\Services\\");
            strcat(key_name, name);
            key = NULL;

            // Open registry key
            if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, key_name,
                0, KEY_WRITE, &key) != ERROR_SUCCESS)
                throw svExConfCreateRegKey(GetLastError());

            // Set service description
            if (description != NULL) {
                if (RegSetValueEx(key, "Description", 0, REG_SZ,
                    (const BYTE *)description,
                    strlen(description) + sizeof(char)) != ERROR_SUCCESS)
                    throw svExConfCreateRegKey(GetLastError());
            }

            // Save startup arguments if present 
            if (argc > 2) {
                if (RegCreateKeyEx(key, "Parameters",
                    0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL,
                    &key_param, NULL) != ERROR_SUCCESS)
                    throw svExConfCreateRegKey(GetLastError());

                int i = 1, j;
                for (j = 1; i < argc; i++) {
                    if (!strcasecmp(argv[i], "-r") ||
                        !strcasecmp(argv[i], "--register") ||
                        !strcasecmp(argv[i], "-u") ||
                        !strcasecmp(argv[i], "--unregister")) continue;
                    snprintf(key_name, sizeof(key_name), "%s%d", "Param", j);

                    // Create registry key 
                    if (RegSetValueEx(key_param, key_name, 0, REG_SZ,
                        (const BYTE *)argv[i],
                        strlen(argv[i]) + sizeof(char)) != ERROR_SUCCESS)
                        throw svExConfCreateRegKey(GetLastError());
                    j++;
                }
                RegCloseKey(key_param);
                RegCloseKey(key);
            }
        }
    }
    catch (exception &e) {
        if (sc_manager) CloseServiceHandle(sc_manager);
        if (service) CloseServiceHandle(service);
        if (key) RegCloseKey(key);
        if (key_param) RegCloseKey(key_param);
        throw;
    }
}
#endif

svClient::svClient(svConf *conf)
    : svService("svClient", conf)
{
    svConfClient *conf_client = (svConfClient *)conf;
    key_server_test_org = conf_client->GetKeyServerTestOrg();

    if (key_server_test_org.size() == 0) {
        svOutput::OpenSyslog(name.c_str(),
            conf->GetLogFacility(), conf->GetDebug());
    }
}

svClient::~svClient()
{
    for (map<string,
        svThreadKeyPoll *>::iterator i = key_poll.begin();
        i != key_poll.end(); i++) delete i->second;
    for (map<string,
        svPublicRSAKey *>::iterator i = public_key.begin();
        i != public_key.end(); i++) delete i->second;
    map<string, map<string, svSession *> >::iterator i;
    for (i = pool_client.begin(); i != pool_client.end(); i++) {
        map<string, svSession *>::iterator j;
        for (j = i->second.begin(); j != i->second.end(); j++)
            delete j->second;
    }
}

void svClient::Start(void)
{
    svConfOrganization *conf_org;

    if (key_server_test_org.size() == 0) {
        CreateSockets();
        SwitchUserGroup();
        Daemonize();
        SaveProcessId();
        CreatePoolClientThreads();
        CreateVpnClientThreads();
    }
    else {
        conf_org = svService::GetConf()->GetOrganization(key_server_test_org);
        if (!conf_org) {
            svError("Invalid organization: %s", key_server_test_org.c_str());
            throw svExKeyPollInvalidOrg(key_server_test_org);
        }

        vector<svConfSocket *> key_server = conf_org->GetRSAKeyServers();
        if (!key_server.size()) {
            svError("No key servers defined for organization: %s",
                key_server_test_org.c_str());
            throw svExKeyPollNoKeyServers(key_server_test_org);
        }

        KeyPollRequest(new svEventKeyPollRequest(this, key_server_test_org));
    }

    StartSignalHandler();

    svEvent *event;
    for ( ;; ) {
        while ((event = PopEvent())) {
            switch (event->GetId())
            {
            case svEVT_QUIT:
                return;
            case svEVT_KEYPOLL_REQUEST:
                KeyPollRequest((svEventKeyPollRequest *)event);
                break;
            case svEVT_KEYPOLL_RESULT:
                if (key_server_test_org.size() == 0)
                    KeyPollResult((svEventKeyPollResult *)event);
                else {
                    svEventKeyPollResult *event_result = (svEventKeyPollResult *)event;
                    if (event_result->GetPercent() < conf_org->GetKeyPollThreshold()) {
                        svLog("Key poll test failed: %s",
                            key_server_test_org.c_str());
                        throw svExKeyPollTestFailure(key_server_test_org);
                    }

                    svLog("Key poll test successful: %s",
                        key_server_test_org.c_str());
                    return;
                }
                break;
            case svEVT_POOLCLIENT_DELETE:
                PoolClientDelete((svEventPoolClientDelete *)event);
                break;
            default:
                ProcessEvent(event);
            }
            delete event;
        }
        SelectSockets();
    }
}

void svClient::HandleStateRequest(void)
{
    svService::HandleStateRequest();
    svDebug("%s: No state information", name.c_str());
}

void svClient::CreateSessionConnect(svSocket *skt, svConfFrontDoor *sfd)
{
    svSessionClientConnect *client = NULL;
    try {
        client = new svSessionClientConnect(skt, *sfd);
        CreateSession(client);
    } catch (runtime_error &e) {
        svError("%s: Error starting session: %s", name.c_str(), e.what());
        if (client) delete client;
    }
}

void svClient::CreateSessionConnect(svSocket *skt,
    svConfSessionTunnel *tunnel)
{
    svSessionClientConnect *client = NULL;
    try {
        client = new svSessionClientConnect(skt, *tunnel);
        CreateSession(client);
    } catch (runtime_error &e) {
        svError("%s: Error starting session: %s", name.c_str(), e.what());
        if (client) delete client;
    }
}

void svClient::CreateSessionAccept(svSocket *skt)
{
    svSessionClientAccept *client = NULL;
    try {
        client = new svSessionClientAccept(skt);
        CreateSession(client);
    } catch (runtime_error &e) {
        svError("%s: Error starting session: %s", name.c_str(), e.what());
        if (client) delete client;
    }
}

void svClient::CreatePoolClientThreads(void)
{
    map<string, svConfOrganization *> org;
    org = conf->GetOrganizations();
    map<string, svConfOrganization *>::iterator oi;

    for (oi = org.begin(); oi != org.end(); oi++) {
        map<string, map<string, svSession *> >::iterator pci;
        pci = pool_client.find(oi->first);

        map<string, svConfSession *> conf_session = oi->second->GetSessions();
        map<string, svConfSession *>::iterator si;

        for (si = conf_session.begin(); si != conf_session.end(); si++) {
            if (si->second->GetType() != svSE_POOL) continue;

            if (pci != pool_client.end() &&
                pci->second.find(si->second->GetName()) != pci->second.end())
                continue;

            svSessionClientAccept *client = NULL;
            try {
                client = new svSessionClientAccept(
                    oi->first,
                    *((svConfSessionPool *)si->second));
                pool_client[oi->first][si->second->GetName()] = client;
                client->Start();
                client->SetDefaultDest(this);
            } catch (runtime_error &e) {
                svError("%s: %s: Error starting pool client: %s: %s",
                    name.c_str(), oi->first.c_str(),
                    si->second->GetName().c_str(), e.what());
            }
        }
    }
}

void svClient::KeyPollRequest(svEventKeyPollRequest *request)
{
    svConfOrganization *org =
        conf->GetOrganization(request->GetOrganization());

    map<string, svPublicRSAKey *>::iterator pki;
    pki = public_key.find(request->GetOrganization());
    if (org && pki != public_key.end() &&
        !pki->second->HasExpired(org->GetKeyCacheTTL())) {
        RSA *key = RSAPublicKey_dup(pki->second->GetKey());
        svEventServer::GetInstance()->Dispatch(
            new svEventKeyPollResult(this,
                request->GetSource(), pki->first, key, 0));
        return;
    }

    map<string, svThreadKeyPoll *>::iterator i;
    i = key_poll.find(request->GetOrganization());
    if (i == key_poll.end()) {
        try {
            svThreadKeyPoll *thread = new svThreadKeyPoll(
                request->GetOrganization(), (key_server_test_org.size() > 0));
            thread->SetDefaultDest(this);
            thread->Start();
            key_poll[request->GetOrganization()] = thread;
            i = key_poll.find(request->GetOrganization());
        } catch (svExKeyPollInvalidOrg &e) {
            svError("%s: Invalid organization: %s",
                name.c_str(), e.what());
            svEventServer::GetInstance()->Dispatch(
                new svEventKeyPollResult(this,
                    request->GetSource(),
                    request->GetOrganization(), NULL, 0));
            return;
        } catch (svExKeyPollNoKeyServers &e) {
            svError("%s: No key servers to poll: %s",
                name.c_str(), e.what());
            svEventServer::GetInstance()->Dispatch(
                new svEventKeyPollResult(this,
                    request->GetSource(),
                    request->GetOrganization(), NULL, 0));
            return;
        }
    }
    i->second->AddClient(request->GetSource());
}

void svClient::KeyPollResult(svEventKeyPollResult *result)
{
    map<string, svThreadKeyPoll *>::iterator i;
    i = key_poll.find(result->GetOrganization());
    if (i == key_poll.end()) {
        // TODO: throw exception...
        svError("%s: No keypoll session found for: %s",
            name.c_str(), result->GetOrganization().c_str());
        return;
    }

    i->second->BroadcastResult(result);

    if (result->GetKey() != NULL) {
        map<string, svPublicRSAKey *>::iterator pki;
        pki = public_key.find(result->GetOrganization());
        if (pki != public_key.end()) {
            delete pki->second;
            public_key.erase(pki);
        }
        public_key[result->GetOrganization()] =
            new svPublicRSAKey(result->GetKey());
    }

    delete i->second;
    key_poll.erase(i);
}

void svClient::PoolClientDelete(svEventPoolClientDelete *event)
{
    map<string, map<string, svSession *> >::iterator pci;
    pci = pool_client.find(event->GetOrganization());
    if (pci == pool_client.end()) {
        svError("%s: Pool connection not found: %s",
            name.c_str(), event->GetOrganization().c_str());
        return;
    }

    map<string, svSession *>::iterator i;
    i = pci->second.find(event->GetPoolName());
    if (i == pci->second.end()) {
        svError("%s: Pool connection not found: %s",
            name.c_str(), event->GetPoolName().c_str());
        return;
    }

    session.push_back(i->second);
    pci->second.erase(i);

    svError("%s: %s: Pool connection in-use: %s", name.c_str(),
        event->GetOrganization().c_str(), event->GetPoolName().c_str());

    CreatePoolClientThreads();
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
