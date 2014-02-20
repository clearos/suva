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

#ifndef _SVEVENT_H
#define _SVEVENT_H

enum svEventId
{
    svEVT_NULL,
    svEVT_QUIT,
    svEVT_CONF_RELOAD,
    svEVT_KEYPOLL_REQUEST,
    svEVT_KEYPOLL_RESULT,
    svEVT_KEYRING_REQUEST,
    svEVT_KEYRING_RESULT,
    svEVT_HOSTKEY_REQUEST,
    svEVT_HOSTKEY_RESULT,
    svEVT_SESSION_QUIT,
    svEVT_SESSION_EXIT,
    svEVT_CHILD_EXIT,
    svEVT_POOLCLIENT_SAVE,
    svEVT_POOLCLIENT_LOAD,
    svEVT_POOLCLIENT_DELETE,
    svEVT_POOLCLIENT_UPDATE,
    svEVT_POOLCLIENT_PURGE,
    svEVT_STATE_REQUEST,
};

// Is event exclusive?
#define svEVT_FLAG_EXCL         0x00000001
// Is event high-priority?
#define svEVT_FLAG_PRI          0x00000002
// Is event permanent?
#define svEVT_FLAG_PERM         0x00000004

// Broadcast address
#define svEVT_BROADCAST         (svEventClient *)0xffffffff

class svEventClient;
class svEvent : public svObject
{
public:
    svEvent()
        : svObject("svEvent"), id(svEVT_NULL),
        src(NULL), dst(NULL), flags(0) { };
    svEvent(svEventId id, svEventClient *src, svEventClient *dst)
        : svObject("svEvent"), id(id),
        src(src), dst(dst), flags(0) { };
    virtual ~svEvent() { };

    svEventId GetId(void) { return id; };

    svEventClient *GetSource(void) { return src; };
    svEventClient *GetDestination(void) { return dst; };
    svEventClient *GetDest(void) { return dst; };

    void SetSource(svEventClient *src) { this->src = src; };
    void SetDestination(svEventClient *dst) { this->dst = dst; };
    void SetDest(svEventClient *dst) { this->dst = dst; };

    virtual svEvent *Clone(void) { return new svEvent(*this); };

    uint32_t GetFlags(void) { return flags; };
    bool IsExclusive(void) { return (bool)(flags & svEVT_FLAG_EXCL); };
    bool IsHighPriority(void) { return (bool)(flags & svEVT_FLAG_PRI); };
    bool IsPermanent(void) { return (bool)(flags & svEVT_FLAG_PERM); };

    void SetExclusive(bool enable = true)
    {
        if (enable) flags |= svEVT_FLAG_EXCL;
        else flags &= ~svEVT_FLAG_EXCL;
    };

    void SetHighPriority(bool enable = true)
    {
        if (enable) flags |= svEVT_FLAG_PRI;
        else flags &= ~svEVT_FLAG_PRI;
    };

    void SetPermanent(bool enable = true)
    {
        if (enable) flags |= svEVT_FLAG_PERM;
        else flags &= ~svEVT_FLAG_PERM;
    };

protected:
    svEventId id;
    svEventClient *src;
    svEventClient *dst;
    uint32_t flags;
};

class svEventServer;
class svEventClient : public svObject
{
public:
    svEventClient(const string &name);
    virtual ~svEventClient();

    svEvent *PopEvent(void);
    svEvent *PopWaitEvent(uint32_t wait_ms = 0);

    svEventClient *GetDefaultDest(void) { return evt_dst_default; };
    void SetDefaultDest(svEventClient *dst) { evt_dst_default = dst; };
    void SetDefaultDestination(svEventClient *dst) { evt_dst_default = dst; };

    virtual void HandleStateRequest(void);

protected:
    friend class svEventServer;
    void PushEvent(svEvent *event);

    vector<svEvent *> evt_queue;
    svEventServer *evt_server;
    pthread_mutex_t evt_mutex;
    pthread_cond_t evt_cond;
    pthread_mutex_t evt_cond_lock;

    svEventClient *evt_dst_default;
};

class svEventServer : public svObject
{
public:
    svEventServer();
    virtual ~svEventServer();

    void Dispatch(svEvent *event);
    void Register(svEventClient *client, const string &name);
    void Unregister(svEventClient *client);

    static svEventServer *GetInstance(void) { return instance; };

protected:
    map<svEventClient *, string> client;
    pthread_mutex_t client_mutex;

    static svEventServer *instance;
};

class svEventQuit : public svEvent
{
public:
    svEventQuit()
        : svEvent(svEVT_QUIT, NULL, svEVT_BROADCAST)
    {
        SetExclusive();
        SetHighPriority();
        SetPermanent();
    };
    virtual svEvent *Clone(void) { return new svEventQuit(*this); };
};

class svEventConfReload : public svEvent
{
public:
    svEventConfReload(svEventClient *dst = svEVT_BROADCAST)
        : svEvent(svEVT_CONF_RELOAD, NULL, dst) { };
    virtual svEvent *Clone(void) { return new svEventConfReload(*this); };
};

class svEventKeyPollRequest : public svEvent
{
public:
    svEventKeyPollRequest(svEventClient *src, const string &org)
        : svEvent(svEVT_KEYPOLL_REQUEST, src, NULL), org(org) { };
    virtual svEvent *Clone(void) { return new svEventKeyPollRequest(*this); };

    const string &GetOrganization(void) const { return org; };

protected:
    string org;
};

class svEventKeyPollResult : public svEvent
{
public:
    svEventKeyPollResult(svEventClient *src, svEventClient *dst,
        const string &org, RSA *key = NULL)
        : svEvent(svEVT_KEYPOLL_RESULT, src, dst),
        org(org), key(key) { };
    virtual svEvent *Clone(void) { return new svEventKeyPollResult(*this); };

    const string &GetOrganization(void) const { return org; };
    RSA *GetKey(void) { return key; };

protected:
    string org;
    RSA *key;
};

class svEventKeyRingRequest : public svEvent
{
public:
    svEventKeyRingRequest(svEventClient *src,
        const string &org, svRSAKeyType which)
        : svEvent(svEVT_KEYRING_REQUEST, src, NULL),
        org(org), which(which) { };
    virtual svEvent *Clone(void) { return new svEventKeyRingRequest(*this); };

    const string &GetOrganization(void) const { return org; };
    svRSAKeyType GetType(void) { return which; };

protected:
    string org;
    svRSAKeyType which;
};

class svEventKeyRingResult : public svEvent
{
public:
    svEventKeyRingResult(svEventClient *dst, const string &org,
        const vector<RSA *> key_ring)
        : svEvent(svEVT_KEYRING_RESULT, NULL, dst),
        org(org), key_ring(key_ring) { };
    virtual svEvent *Clone(void) { return new svEventKeyRingResult(*this); };

    const string &GetOrganization(void) const { return org; };
    vector<RSA *> GetKeyRing(void) { return key_ring; };

protected:
    string org;
    vector<RSA *> key_ring;
};

class svEventHostKeyRequest : public svEvent
{
public:
    svEventHostKeyRequest(svEventClient *src,
        const string &dev, const string &org)
        : svEvent(svEVT_HOSTKEY_REQUEST, src, NULL),
        dev(dev), org(org) { };
    virtual svEvent *Clone(void) { return new svEventHostKeyRequest(*this); };

    const string &GetDevice(void) const { return dev; };
    const string &GetOrganization(void) const { return org; };

protected:
    string dev;
    string org;
};

class svEventHostKeyResult : public svEvent
{
public:
    svEventHostKeyResult(svEventClient *src, svEventClient *dst,
        const string &dev, const string &org, const svHostKey &key)
        : svEvent(svEVT_HOSTKEY_RESULT, src, dst),
        dev(dev), org(org), key(key) { };
    virtual svEvent *Clone(void) { return new svEventHostKeyResult(*this); };

    const string &GetDevice(void) const { return dev; };
    const string &GetOrganization(void) const { return org; };
    const svHostKey &GetKey(void) const { return key; };

protected:
    string dev;
    string org;
    svHostKey key;
};

class svEventSessionQuit : public svEvent
{
public:
    svEventSessionQuit(svEventClient *dst)
        : svEvent(svEVT_SESSION_QUIT, NULL, dst) { };
    virtual svEvent *Clone(void) { return new svEventSessionQuit(*this); };
};

class svEventSessionExit : public svEvent
{
public:
    svEventSessionExit(svEventClient *src)
        : svEvent(svEVT_SESSION_EXIT, src, NULL) { };
    virtual svEvent *Clone(void) { return new svEventSessionExit(*this); };
};

class svEventChildExit : public svEvent
{
public:
    svEventChildExit(pid_t pid, int status)
        : svEvent(svEVT_CHILD_EXIT, NULL, svEVT_BROADCAST),
        pid(pid), status(status) { };
    virtual svEvent *Clone(void) { return new svEventChildExit(*this); };

    pid_t GetPid(void) { return pid; };
    int GetStatus(void) { return status; };

protected:
    pid_t pid;
    int status;
};

class svEventPoolClientSave : public svEvent
{
public:
    svEventPoolClientSave(svEventClient *src, svPoolClient *client)
        : svEvent(svEVT_POOLCLIENT_SAVE, src, NULL),
        client(client) { };
    virtual svEvent *Clone(void) { return new svEventPoolClientSave(*this); };

    svPoolClient *GetClient(void) { return client; };

protected:
    svPoolClient *client;
};

class svEventPoolClientLoad : public svEvent
{
public:
    svEventPoolClientLoad(svEventClient *src,
        const string &dev, const string &org)
        : svEvent(svEVT_POOLCLIENT_LOAD, src, NULL),
        dev(dev), org(org), client(NULL) { };
    svEventPoolClientLoad(svEventClient *src, svEventClient *dst,
        svPoolClient *client)
        : svEvent(svEVT_POOLCLIENT_LOAD, src, dst),
        client(client) { };
    virtual svEvent *Clone(void) { return new svEventPoolClientLoad(*this); };

    const string &GetDevice(void) { return dev; };
    const string &GetOrganization(void) { return org; };
    svPoolClient *GetClient(void) { return client; };

protected:
    string dev;
    string org;
    svPoolClient *client;
};

class svEventPoolClientDelete : public svEvent
{
public:
    svEventPoolClientDelete(svEventClient *src,
        const string &pool, const string &org)
        : svEvent(svEVT_POOLCLIENT_DELETE, src, NULL),
        pool(pool), org(org) { };
    virtual svEvent *Clone(void) { return new svEventPoolClientDelete(*this); };

    const string &GetPoolName(void) { return pool; };
    const string &GetOrganization(void) { return org; };

protected:
    string pool;
    string org;
};

enum svPoolClientState
{
    svPCS_IDLE,
    svPCS_INUSE,
    svPCS_OFFLINE,
};

class svEventPoolClientUpdate : public svEvent
{
public:
    svEventPoolClientUpdate(svEventClient *dst,
        const string &pool, const string &dev, svPoolClientState state)
        : svEvent(svEVT_POOLCLIENT_UPDATE, NULL, dst),
        pool(pool), dev(dev), state(state) { };
    virtual svEvent *Clone(void) { return new svEventPoolClientUpdate(*this); };

    const string &GetPoolName(void) { return pool; };
    const string &GetDevice(void) { return dev; };
    svPoolClientState GetState(void) { return state; };

protected:
    string pool;
    string dev;
    svPoolClientState state;
};

class svEventStateRequest : public svEvent
{
public:
    svEventStateRequest()
        : svEvent(svEVT_STATE_REQUEST, NULL, svEVT_BROADCAST)
    {
        SetHighPriority();
    };
    virtual svEvent *Clone(void) { return new svEventStateRequest(*this); };
};

class svExEventInstanceNotFound : public runtime_error
{
public:
    explicit svExEventInstanceNotFound()
        : runtime_error("svEventQueue instance not found") { };
    virtual ~svExEventInstanceNotFound() throw() { };
};

class svExEventInstance : public runtime_error
{
public:
    explicit svExEventInstance()
        : runtime_error("Multiple svEventServer instances detected") { };
    virtual ~svExEventInstance() throw() { };
};

class svExEventCondWait : public runtime_error
{
public:
    explicit svExEventCondWait(int rc)
        : runtime_error(strerror(rc)) { };
    virtual ~svExEventCondWait() throw() { };
};

class svExEventUnhandled : public runtime_error
{
public:
    explicit svExEventUnhandled(svEventId id)
        : runtime_error("Unhandled event"), id(id) { };
    virtual ~svExEventUnhandled() throw() { };
    svEventId GetId(void) { return id; };

protected:
    svEventId id;
};

#endif // _SVEVENT_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
