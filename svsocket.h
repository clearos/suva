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

#ifndef _SVSOCKET_H
#define _SVSOCKET_H

using namespace std;

#define SVSKT_FLAG_RAW          0x00000001
#define SVSKT_FLAG_SFD          0x00000002

enum svSocketState
{
    svSS_NULL,
    svSS_LISTEN,
    svSS_ACCEPTED,
    svSS_CONNECT,
    svSS_CONNECTING,
    svSS_CONNECTED
};

class svExSocketCreate : public runtime_error
{
public:
    explicit svExSocketCreate(int errid)
        : runtime_error("Error creating socket"), errid(errid) { };
    virtual ~svExSocketCreate() throw() { };
    int errid;
};

class svExSocketSyscall : public runtime_error
{
public:
    explicit svExSocketSyscall(const string &call, int errid)
        : runtime_error(call), errid(errid) { };
    virtual ~svExSocketSyscall() throw() { };
    int errid;
};

class svExSocketListen : public runtime_error
{
public:
    explicit svExSocketListen(int errid)
        : runtime_error("Error listening on socket"), errid(errid) { };
    virtual ~svExSocketListen() throw() { };
    int errid;
};

class svExSocketAccept : public runtime_error
{
public:
    explicit svExSocketAccept(int errid)
        : runtime_error("Error accepting connection"), errid(errid) { };
    virtual ~svExSocketAccept() throw() { };
    int errid;
};

class svExSocketConnect : public runtime_error
{
public:
    explicit svExSocketConnect(int errid)
        : runtime_error("Error connecting socket"), errid(errid) { };
    virtual ~svExSocketConnect() throw() { };
    int errid;
};

class svExSocketTimeout : public runtime_error
{
public:
    explicit svExSocketTimeout(const string &what)
        : runtime_error(what) { };
    virtual ~svExSocketTimeout() throw() { };
};

class svExSocketRead : public runtime_error
{
public:
    explicit svExSocketRead(int errid)
        : runtime_error("Error reading from socket"), errid(errid) { };
    virtual ~svExSocketRead() throw() { };
    int errid;
};

class svExSocketWrite : public runtime_error
{
public:
    explicit svExSocketWrite(int errid)
        : runtime_error("Error writing to socket"), errid(errid) { };
    virtual ~svExSocketWrite() throw() { };
    int errid;
};

class svExSocketHangup : public runtime_error
{
public:
    explicit svExSocketHangup()
        : runtime_error("Hang-up") { };
    virtual ~svExSocketHangup() throw() { };
};

class svExSocketUnsupported : public runtime_error
{
public:
    explicit svExSocketUnsupported(const string &what)
        : runtime_error("Unsupported or undefined: " + what) { };
    virtual ~svExSocketUnsupported() throw() { };
};

class svExSocketPayloadTooLarge : public runtime_error
{
public:
    explicit svExSocketPayloadTooLarge()
        : runtime_error("Payload too large") { };
    virtual ~svExSocketPayloadTooLarge() throw() { };
};

#ifdef __WIN32__
#define socklen_t               size_t
#define SHUT_RD                 SD_RECEIVE
#define SHUT_WR                 SD_SEND
#define SHUT_RDWR               SD_BOTH
#endif

#if !defined(__WIN32__)
#define _SUVA_SOCKET_TYPE       int
#else
#define _SUVA_SOCKET_TYPE       SOCKET
#endif

#if !defined(__WIN32__)
#define _SUVA_SOCKET_CLOSE(x)   close(x)
#else
#define _SUVA_SOCKET_CLOSE(x)   closesocket(x)
#endif

#if !defined(__WIN32__)
#define _SUVA_SOCKET_INVALID    -1
#else
#define _SUVA_SOCKET_INVALID    INVALID_SOCKET
#endif

#if !defined(__WIN32__)
#define _SUVA_SOCKET_ERROR(x)   errno == x
#else
#define _SUVA_SOCKET_ERROR(x)   WSAGetLastError() == WSA##x
#endif

#if !defined(__WIN32__)
#define _SUVA_SOCKET_ERRNO  errno
#else
#define _SUVA_SOCKET_ERRNO  WSAGetLastError()
#endif

#if !defined(_SUVA_SOCKET_MAX_BUFFER)
// Maximum RAW socket buffer length: 2MiB
#define _SUVA_SOCKET_MAX_BUFFER 2097152
#endif

class svSocketSet;
class svSocketBuffer;
class svSocket : public svObject
{
public:
    svSocket(svConfSocketType type, svConfSocketMode mode);
    virtual ~svSocket();

    static void Initialize(void);
    static void Uninitialize(void);
    static svSocket *Create(const svConfSocket &skt_conf);

    virtual void Close(void);

    void Read(uint8_t *data, ssize_t &length);
    void ReadPacket(svPacket &pkt, ssize_t payload_size);

    void Write(uint8_t *data, ssize_t &length);
    void WritePacket(svPacket &pkt);

    _SUVA_SOCKET_TYPE GetDescriptor(void) { return sd; };
    svConfSocketType GetType(void) { return type; };
    svConfSocketMode GetMode(void) { return mode; };
    svSocketState GetState(void) { return state; };
    const string &GetHostPath(void) const { return hostpath; };
    const string &GetAddress(void) const { return addr; };
    const string &GetNetmask(void) const { return netmask; };
    const string &GetMacAddr(void) const { return mac; };
    uint16_t GetPort(void) { return port; };
    struct sockaddr *GetSockAddr(void)
    {
        return (struct sockaddr *)saddr;
    };
    const string &GetDevice(void) const { return dev; };
    const string &GetSession(void) const { return session; };
    const string &GetOrganization(void) const { return org; };

    bool IsRaw(void)
    {
        return (bool)(flags & SVSKT_FLAG_RAW);
    };
    bool IsFrontDoor(void)
    {
        return (bool)(flags & SVSKT_FLAG_SFD);
    };
    bool IsConnecting(void)
    {
        return (bool)(state == svSS_CONNECTING);
    };
    bool IsConnected(void)
    {
        return (bool)(state == svSS_CONNECTED);
    };
    void SetConnected(void) { state = svSS_CONNECTED; };

    void SetRaw(bool enable = true);

    void SetFrontDoor(bool enable = true)
    {
        if (enable) flags |= SVSKT_FLAG_SFD;
        else flags &= ~SVSKT_FLAG_SFD;
    };
    void SetDevice(const string &dev)
    {
        this->dev = dev;
    };
    void SetSession(const string &session)
    {
        this->session = session;
    };
    void SetOrganization(const string &org)
    {
        this->org = org;
    };

    ssize_t GetBufferLength(void);
    void FlushBuffer(void);
    void ClearBuffer(void);

    uint32_t GetLastActive(void) { return (uint32_t)active.tv_sec; };
    void UpdateLastActive(void) { gettimeofday(&active, NULL); };

    virtual void Connect(void) = 0;
    virtual svSocket *Accept(void) = 0;

    void SetNonBlockingMode(void);
    void SetKeepalive(bool enable,
        int ka_time = 7200, int ka_intvl = 75, int ka_probes = 9);

    virtual void DumpState(void) const;

protected:
    _SUVA_SOCKET_TYPE sd;
    uint8_t *saddr;
    socklen_t slen;
    svConfSocketType type;
    svConfSocketMode mode;
    svSocketState state;
    uint32_t flags;
    uint32_t ttl;
    string ifn;
    string addr;
    string netmask;
    string mac;
    string hostpath;
    string session;
    string dev;
    string org;
    uint16_t port;
    ssize_t bytes_read;
    ssize_t bytes_wrote;
    struct timeval active;
    svSocketBuffer *buffer;
#ifdef __WIN32__
    static WSADATA ws_data;
#endif

    friend class svSocketSet;
};

class svSocketInet : public svSocket
{
public:
    svSocketInet();
    svSocketInet(svConfSocketMode mode);
    svSocketInet(_SUVA_SOCKET_TYPE sd, socklen_t sa_slen, struct sockaddr_in *sa_in);
    virtual ~svSocketInet();

    struct sockaddr_in *GetSockAddr(void)
    {
        return (struct sockaddr_in *)saddr;
    };

    virtual void Connect(void) { };
    virtual svSocket *Accept(void) { return NULL; };
};

class svSocketPipe : public svSocket
{
public:
    svSocketPipe(svConfSocketMode mode);
    svSocketPipe(int sd, socklen_t sa_slen,
        struct sockaddr_un *sa_un, const string &path);
    virtual ~svSocketPipe();

    struct sockaddr_un *GetSockAddr(void)
    {
        return (struct sockaddr_un *)saddr;
    };

    virtual void Connect(void) { };
    virtual svSocket *Accept(void) { return NULL; };
};

class svSocketVpn : public svSocket
{
public:
    svSocketVpn(const svConfSocket &conf);
    virtual ~svSocketVpn();

    void SetAddress(const string &addr) { this->addr = addr; };
    void SetNetmask(const string &netmask) { this->netmask = netmask; };
    void SetMacAddr(const string &mac) { this->mac = mac; };

    virtual void Connect(void) { };
    virtual svSocket *Accept(void) { return NULL; };
};

class svSocketInetListen : public svSocketInet
{
public:
    svSocketInetListen(const string &ifn, uint16_t port);

    virtual svSocket *Accept(void);
    virtual void Connect(void) { };
};

class svSocketInetConnect : public svSocketInet
{
public:
    svSocketInetConnect(const string &host, uint16_t port);

    virtual svSocket *Accept(void) { return NULL; };
    virtual void Connect(void);
};

class svSocketPipeListen : public svSocketPipe
{
public:
    svSocketPipeListen(const string &path);

    virtual svSocket *Accept(void);
    virtual void Connect(void) { };
};

class svSocketPipeConnect : public svSocketPipe
{
public:
    svSocketPipeConnect(const string &path);

    virtual svSocket *Accept(void) { return NULL; };
    virtual void Connect(void);
};

class svSocketPair : public svSocketInet
{
public:
    svSocketPair();
    virtual ~svSocketPair();

    virtual void Close(void);

    void GetDescriptor(_SUVA_SOCKET_TYPE spd[2])
    {
        spd[0] = sp[0]; spd[1] = sp[1];
    };

protected:
    _SUVA_SOCKET_TYPE sp[2];
};

class svExSocketSelect : public runtime_error
{
public:
    explicit svExSocketSelect(int errid)
        : runtime_error("Error selecting on socket"), errid(errid) { };
    virtual ~svExSocketSelect() throw() { };
    int errid;
};

class svExSocketInvalidParam : public runtime_error
{
public:
    explicit svExSocketInvalidParam(const string &what)
        : runtime_error(what + ": Invalid parameter") { };
    virtual ~svExSocketInvalidParam() throw() { };
};

class svSocketSet : public svObject
{
public:
    svSocketSet();
    virtual ~svSocketSet();

    void SelectForRead(svSocket *skt);
    void SelectForWrite(svSocket *skt);

    bool IsSetForRead(svSocket *skt);
    bool IsSetForWrite(svSocket *skt);

    void RemoveForRead(svSocket *skt);
    void RemoveForWrite(svSocket *skt);

    bool IsReadyForRead(svSocket *skt);
    bool IsReadyForWrite(svSocket *skt);

    uint32_t GetCountForRead(void) { return skt_read.size(); };
    uint32_t GetCountForWrite(void) { return skt_write.size(); };

    void Reset(void);
    int Select(uint32_t timeout = 0);

protected:
    fd_set fds_read, fds_write;
    vector<svSocket *> skt_read, skt_write;
};

class svSocketBuffer : public svObject
{
public:
    svSocketBuffer();
    virtual ~svSocketBuffer();

    void Push(uint8_t *data, ssize_t data_size);
    uint8_t *Pop(ssize_t *data_size = NULL);
    ssize_t GetLength(void) { return length; };

protected:

    struct chunk
    {
        uint8_t *data;
        ssize_t length;
    };

    ssize_t length;
    queue<struct chunk *> buffer;
};

#endif // _SVSOCKET_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
