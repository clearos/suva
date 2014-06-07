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
#include <string>
#include <sstream>
#include <stdexcept>
#include <vector>
#include <map>
#include <queue>

#include <sys/time.h>

#ifdef __WIN32__
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#define _WIN32_WINNT            0x0502
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#ifndef __ANDROID__
#include <sys/socketvar.h>
#endif
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#if defined(__linux__)
#include <linux/un.h>
#include <linux/sockios.h>
#include <linux/if_tun.h>
#elif defined(__MACH__)
#include <sys/un.h>
#endif

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX           108
#endif

#ifndef __WIN32__
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#if HAVE_NETINET_TCP_VAR_H
#include <netinet/tcp_var.h>
#endif
#include <arpa/inet.h>
#endif

#ifndef TCP_KEEPIDLE
#define TCP_KEEPIDLE            TCPCTL_KEEPIDLE
#endif
#ifndef TCP_KEEPINTVL
#define TCP_KEEPINTVL           TCPCTL_KEEPINTVL
#endif
#ifndef TCP_KEEPCNT
#define TCP_KEEPCNT             TCPCTL_KEEPINIT
#endif

#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
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
#include "svsignal.h"
#include "svsession.h"
#include "svutil.h"
#include "svservice.h"

#ifndef __ANDROID__
extern int errno;
#endif

#ifdef __WIN32__
WSADATA svSocket::ws_data;
#endif

svSocket::svSocket(svConfSocketType type, svConfSocketMode mode)
    : svObject("svSocket"),
    sd(_SUVA_SOCKET_INVALID), saddr(NULL), slen(0),
    type(type), mode(mode), state(svSS_NULL), flags(0), port(0),
    bytes_read(0), bytes_wrote(0), buffer(NULL)
{
    gettimeofday(&active, NULL);
    svService::GetConf()->Lock();
    ttl = svService::GetConf()->GetSocketTTL();
    svService::GetConf()->Unlock();
}

svSocket::~svSocket()
{
    Close();
    if (saddr) delete [] saddr;
    if (buffer) delete buffer;
}

svSocket *svSocket::Create(const svConfSocket &skt_conf)
{
    svSocket *skt = NULL;
    svConfSocket conf(skt_conf);

    if (conf.GetType() == svST_INET &&
        conf.GetMode() == svSM_LISTEN) {
        skt = (svSocket *)new svSocketInetListen(
            conf.GetInterface(), conf.GetPort());
    }
    else if (conf.GetType() == svST_INET &&
        conf.GetMode() == svSM_CONNECT) {
        skt = (svSocket *)new svSocketInetConnect(
            conf.GetHost(), conf.GetPort());
    }
    else if (conf.GetType() == svST_PIPE &&
        conf.GetMode() == svSM_LISTEN) {
        skt = (svSocket *)new svSocketPipeListen(conf.GetPath());
    }
    else if (conf.GetType() == svST_PIPE &&
        conf.GetMode() == svSM_CONNECT) {
        skt = (svSocket *)new svSocketPipeConnect(conf.GetPath());
    }
    else if (conf.GetType() == svST_VPN) {
        svSocketVpn *skt_vpn = new svSocketVpn(conf);
        skt_vpn->SetAddress(conf.GetAddress());
        skt_vpn->SetNetmask(conf.GetNetmask());
        skt_vpn->SetMacAddr(conf.GetMacAddr());
        skt = (svSocket *)skt_vpn;
    }
    else {
#ifndef __WIN32__
        throw svExSocketCreate(EINVAL);
#else
        throw svExSocketCreate(WSA_INVALID_PARAMETER);
#endif
    }

    if (!skt) {
#ifndef __WIN32__
        throw svExSocketCreate(ENOMEM);
#else
        throw svExSocketCreate(WSA_NOT_ENOUGH_MEMORY);
#endif
    }

    return skt;
}

void svSocket::Initialize(void)
{
#ifdef __WIN32__
    int rc;
    if ((rc = WSAStartup(MAKEWORD(2, 2), &ws_data)) != 0)
        throw svExSocketSyscall("WSAStartup", _SUVA_SOCKET_ERRNO);
#endif
}

void svSocket::Uninitialize(void)
{
#ifdef __WIN32__
    int rc = WSACleanup();
    if (rc != 0)
        svError("WSACleanup failed: %d", rc);
#endif
}

void svSocket::Close(void)
{
    if (sd != _SUVA_SOCKET_INVALID) {
        if (type == svST_INET &&
            (state & svSS_CONNECTED || state & svSS_ACCEPTED))
            shutdown(sd, SHUT_RDWR);
        _SUVA_SOCKET_CLOSE(sd);
        sd = _SUVA_SOCKET_INVALID;
    }
    state = svSS_NULL;
}

void svSocket::Read(uint8_t *data, ssize_t &length)
{
    struct timeval tv;
    uint8_t *ptr = data;
    ssize_t bytes_read, bytes_left = length;

    if (!ptr || !bytes_left)
        throw svExSocketInvalidParam("data or length");

    for (length = 0; bytes_left > 0; ) {
        if (type != svST_VPN)
            bytes_read = recv(sd, (char *)ptr, bytes_left, 0);
#if !defined(__WIN32__)
        else bytes_read = read(sd, (char *)ptr, bytes_left);
#endif
        if (!bytes_read) {
            if (flags & SVSKT_FLAG_RAW && length) break;
            throw svExSocketHangup();
        }
        else if (bytes_read == -1) {
            if (errno == EAGAIN ||
                _SUVA_SOCKET_ERROR(EWOULDBLOCK)) {
                if (flags & SVSKT_FLAG_RAW) break;

                gettimeofday(&tv, NULL);
                if (uint32_t(tv.tv_sec - active.tv_sec) <= ttl) {
                    svDelay(_SUVA_DEFAULT_DELAY);
                    continue;
                }

                throw svExSocketTimeout("read");
            }

            throw svExSocketRead(_SUVA_SOCKET_ERRNO);
        }

        ptr += bytes_read;
        this->bytes_read += (uint32_t)bytes_read;
        bytes_left -= bytes_read;
        length += bytes_read;

        gettimeofday(&active, NULL);

        if (type == svST_VPN) break;
    }
#ifdef USE_HEAVY_DEBUG
    svDebug("%s: Read: %d", name.c_str(), length);
    svHexDump(stderr, data, length);
#endif
}

void svSocket::ReadPacket(svPacket &pkt, ssize_t payload_size)
{
    ssize_t length;
    length = _SUVA_PKT_HEADER_SIZE;
    Read(pkt.GetBuffer(), length);
    pkt.SyncReadHeader();

    // XXX: This is an unfortunate hack which resolves a bug
    // in Suva/2 where the packet header contains left over
    // information from a previous read/write.  The pad and length
    // fields may contain old values which cause this code to
    // time-out while trying to read a payload which should be 0.
    if (pkt.GetId() == PKT_ID_KEY && pkt.GetArg1() == PKT_ARG_KEY_SYNC)
        pkt.SetPayloadLength(0);

    if (payload_size && pkt.GetPayloadLength()) {
        if (pkt.GetPayloadLength() > payload_size)
            throw svExSocketPayloadTooLarge();
        length = pkt.GetPayloadLength();
        Read(pkt.GetPayload(), length);
        pkt.Decrypt();
    }

    pkt.SyncRead();
}

void svSocket::Write(uint8_t *data, ssize_t &length)
{
    struct timeval tv;
    uint8_t *ptr = data;
    ssize_t bytes_wrote, bytes_left = length;

#ifdef USE_HEAVY_DEBUG
    if (!ptr || !bytes_left)
        throw svExSocketInvalidParam("data or length");

    svDebug("%s: Write: %d", name.c_str(), length);
    svHexDump(stderr, data, length);
#endif

    if (flags & SVSKT_FLAG_RAW) {
        buffer->Push(data, length);
        ptr = buffer->Pop(&length);
    }
    
    for (length = 0; bytes_left > 0; ) {
        if (type != svST_VPN)
            bytes_wrote = send(sd, (const char *)ptr, bytes_left, 0);
#if !defined(__WIN32__)
        else bytes_wrote = write(sd, (const char *)ptr, bytes_left);
#endif
        if (!bytes_wrote) throw svExSocketHangup();
        else if (bytes_wrote == -1) {
            if (errno == EAGAIN ||
                _SUVA_SOCKET_ERROR(EWOULDBLOCK)) {
                if (flags & SVSKT_FLAG_RAW) break;

                gettimeofday(&tv, NULL);
                if (uint32_t(tv.tv_sec - active.tv_sec) <= ttl) {
                    svDelay(_SUVA_DEFAULT_DELAY);
                    continue;
                }

                throw svExSocketTimeout("write");
            }

            throw svExSocketWrite(_SUVA_SOCKET_ERRNO);
        }

        ptr += bytes_wrote;
        this->bytes_wrote += (uint32_t)bytes_wrote;
        bytes_left -= bytes_wrote;
        length += bytes_wrote;

        gettimeofday(&active, NULL);
    }

    if (flags & SVSKT_FLAG_RAW && bytes_left > 0)
        buffer->Push(ptr, bytes_left);
}

void svSocket::SetRaw(bool enable)
{
    if (enable) {
        flags |= SVSKT_FLAG_RAW;
        if (!buffer) buffer = new svSocketBuffer();
    }
    else flags &= ~SVSKT_FLAG_RAW;
}

void svSocket::WritePacket(svPacket &pkt)
{
    pkt.SyncWrite();
    pkt.Encrypt();
    ssize_t length = pkt.GetPacketLength();
    Write(pkt.GetBuffer(), length);
}

ssize_t svSocket::GetBufferLength(void)
{
    if (buffer != NULL) return buffer->GetLength();
    return (ssize_t)-1;
}

void svSocket::FlushBuffer(void)
{
    if (buffer && buffer->GetLength()) {
        ssize_t length = 0;
        Write(NULL, length);
    }
}

void svSocket::ClearBuffer(void)
{
    if (buffer) buffer->Pop(NULL);
}

void svSocket::SetNonBlockingMode(void)
{
#ifndef __WIN32__
    // XXX: Should use ioctl for this...
    if (fcntl(sd, F_SETFL, O_NONBLOCK) != 0) {
        throw svExSocketSyscall(
            "fcntl: O_NONBLOCK", _SUVA_SOCKET_ERRNO);
    }
#else
    u_long mode = 1;
    if (ioctlsocket(sd, FIONBIO, &mode) != 0) {
        throw svExSocketSyscall(
            "ioctlsocket: FIONBIO", _SUVA_SOCKET_ERRNO);
    }
#endif
}

void svSocket::SetKeepalive(bool enable,
    int ka_time, int ka_intvl, int ka_probes)
{
#if !defined(__WIN32__) && !defined(__MACH__)
    if (type != svST_INET)
        throw svExSocketUnsupported("TCP keep-alive");
    int value = 0;
    if (enable) value = 1;
    if (setsockopt(sd,
        SOL_SOCKET, SO_KEEPALIVE, &value, sizeof(int)) != 0) {
        throw svExSocketSyscall("setsockopt: SO_KEEPALIVE",
            _SUVA_SOCKET_ERRNO);
    }
    if (enable) {
        value = ka_time;
        struct protoent *proto;
        proto = getprotobyname("tcp");
        if (!proto) {
            throw svExSocketSyscall("getprotobyname: TCP",
                _SUVA_SOCKET_ERRNO);
        }
        if (setsockopt(sd,
            proto->p_proto, TCP_KEEPIDLE, &value, sizeof(int)) != 0) {
            throw svExSocketSyscall("setsockopt: TCP_KEEPIDLE",
                _SUVA_SOCKET_ERRNO);
        }
        value = ka_intvl;
        if (setsockopt(sd,
            proto->p_proto, TCP_KEEPINTVL, &value, sizeof(int)) != 0) {
            throw svExSocketSyscall("setsockopt: TCP_KEEPINTVL",
                _SUVA_SOCKET_ERRNO);
        }
        value = ka_probes;
        if (setsockopt(sd,
            proto->p_proto, TCP_KEEPCNT, &value, sizeof(int)) != 0) {
            throw svExSocketSyscall("setsockopt: TCP_KEEPCNT",
                _SUVA_SOCKET_ERRNO);
        }
    }
#endif
}

void svSocket::DumpState(void) const
{
    svObject::DumpState();
}

svSocketInet::svSocketInet()
    : svSocket(svST_INET, svSM_CONNECT) { }

svSocketInet::svSocketInet(svConfSocketMode mode)
    : svSocket(svST_INET, mode)
{
    sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sd == _SUVA_SOCKET_INVALID)
        throw svExSocketCreate(_SUVA_SOCKET_ERRNO);
    SetNonBlockingMode();
    slen = sizeof(struct sockaddr_in);
    saddr = new uint8_t[slen];
    memset(saddr, 0, slen);

    struct sockaddr_in *sa_in = GetSockAddr();
    sa_in->sin_family = AF_INET;
}

svSocketInet::svSocketInet(_SUVA_SOCKET_TYPE sd,
    socklen_t sa_slen, struct sockaddr_in *sa_in)
    : svSocket(svST_INET, svSM_NULL)
{
    this->sd = sd;
    slen = sa_slen;
    saddr = (uint8_t *)sa_in;
    state = svSS_ACCEPTED;
    port = htons(sa_in->sin_port);
    hostpath = inet_ntoa(sa_in->sin_addr);
    SetNonBlockingMode();
}

svSocketInet::~svSocketInet() { }

svSocketPipe::svSocketPipe(svConfSocketMode mode)
    : svSocket(svST_PIPE, mode)
{
#ifndef __WIN32__
    sd = socket(AF_LOCAL, SOCK_STREAM, 0);
    if (sd == _SUVA_SOCKET_INVALID) throw svExSocketCreate(_SUVA_SOCKET_ERRNO);
    SetNonBlockingMode();
    slen = sizeof(struct sockaddr_un);
    saddr = new uint8_t[slen];
    memset(saddr, 0, slen);

    struct sockaddr_un *sa_un = GetSockAddr();
    sa_un->sun_family = AF_LOCAL;
#else
    throw svExSocketUnsupported("Local UNIX socket");
#endif
}

svSocketPipe::svSocketPipe(int sd,
    socklen_t sa_slen, struct sockaddr_un *sa_un, const string &path)
    : svSocket(svST_PIPE, svSM_NULL)
{
#ifndef __WIN32__
    this->sd = sd;
    slen = sa_slen;
    saddr = (uint8_t *)sa_un;
    state = svSS_ACCEPTED;
    hostpath = path;
    SetNonBlockingMode();
#endif
}

svSocketPipe::~svSocketPipe() { }

svSocketVpn::svSocketVpn(const svConfSocket &conf)
    : svSocket(svST_VPN, svSM_NULL)
{
#ifdef __linux__
    ifn = conf.GetInterface();
    sd = open("/dev/net/tun", O_RDWR);
    if (sd == _SUVA_SOCKET_INVALID) throw svExSocketCreate(_SUVA_SOCKET_ERRNO);

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_NO_PI;

    if (conf.GetVpnType() == svVT_TUN)
        ifr.ifr_flags |= IFF_TUN;
    else ifr.ifr_flags |= IFF_TAP; 

    if (ifn == "auto") {
        if (conf.GetVpnType() == svVT_TUN)
            strncpy(ifr.ifr_name, "tun%d", IFNAMSIZ);
        else
            strncpy(ifr.ifr_name, "tap%%d", IFNAMSIZ);
        if (ioctl(sd, TUNSETIFF, (void *)&ifr) != 0) {
            close(sd); sd = -1;
            throw svExSocketSyscall("ioctl: TUNSETIFF",
                _SUVA_SOCKET_ERRNO);
        }
    }
    else {
        strncpy(ifr.ifr_name, ifn.c_str(), IFNAMSIZ);

        if (ioctl(sd, TUNSETIFF, (void *)&ifr) != 0) {
            struct ifreq ifr_current;
            memset(&ifr_current, 0, sizeof(ifr_current));
            strncpy(ifr_current.ifr_name, ifn.c_str(), IFNAMSIZ);
#ifdef TUNGETIFF
            if (ioctl(sd, TUNGETIFF, (void *)&ifr_current) == -1) {
                close(sd); sd = -1;
                svError("Error retrieving TUN/TAP interface details: %s: %s",
                    ifn.c_str(), strerror(_SUVA_SOCKET_ERRNO));
                throw svExSocketSyscall("ioctl: TUNGETIFF",
                    _SUVA_SOCKET_ERRNO);
            }
#else
            errno = ENOTSUP;
            throw svExSocketSyscall("ioctl: TUNGETIFF",
                _SUVA_SOCKET_ERRNO);
#endif
            svLog("Unable to set TUN/TAP interface, "
                "using previous configuration: %s",
                ifr_current.ifr_name);
        }
        ifn.assign(ifr.ifr_name);
    }

    if (conf.IsPersistent()) {
        int enable = 1;
        if (ioctl(sd, TUNSETPERSIST, (void *)&enable) != 0) {
            close(sd); sd = -1;
            throw svExSocketSyscall("ioctl: TUNSETPERSIST",
                _SUVA_SOCKET_ERRNO);
        }
    }
#endif
    state = svSS_CONNECTED;
    SetNonBlockingMode();
}

svSocketVpn::~svSocketVpn() { }

svSocketInetListen::svSocketInetListen(const string &ifn,
    uint16_t port) : svSocketInet(svSM_LISTEN)
{
    this->ifn = ifn;
    this->port = port;

    struct sockaddr_in *sa_in = GetSockAddr();
    sa_in->sin_port = htons(port);
#ifndef __WIN32__
    if (ifn.size() && ifn != "all") {
        int ifd;
        struct ifreq ifr;
        struct sockaddr_in ifaddr;

        if ((ifd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
            throw svExSocketSyscall("socket", _SUVA_SOCKET_ERRNO);

        strncpy(ifr.ifr_name,
            ifn.c_str(), sizeof(ifr.ifr_name) - 1);
        ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';

        if (ioctl(ifd, SIOCGIFADDR, &ifr) != 0) {
            close(ifd);
            throw svExSocketSyscall("ioctl: SIOCGIFADDR",
                _SUVA_SOCKET_ERRNO);
        }
        close(ifd);

        ifaddr = *((struct sockaddr_in *)&ifr.ifr_addr);
        sa_in->sin_addr.s_addr = ifaddr.sin_addr.s_addr;
    }

    hostpath = inet_ntoa(sa_in->sin_addr);
#else
    hostpath = "0.0.0.0";
#endif
    int on = 1;
    if (setsockopt(sd,
        SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on)) != 0) {
        throw svExSocketSyscall("setsockopt: SO_REUSEADDR",
            _SUVA_SOCKET_ERRNO);
    }

    if (bind(sd, svSocket::GetSockAddr(), slen) != 0)
        throw svExSocketSyscall("bind", _SUVA_SOCKET_ERRNO);

    if (listen(sd, SOMAXCONN) != 0)
        throw svExSocketSyscall("listen", _SUVA_SOCKET_ERRNO);

    state = svSS_LISTEN;
}

svSocket *svSocketInetListen::Accept(void)
{
#ifndef __WIN32__
    socklen_t sa_slen = slen;
#else
    int sa_slen = (int)slen;
#endif
    struct sockaddr_in *sa_in =
        (struct sockaddr_in *)new uint8_t[slen];
    _SUVA_SOCKET_TYPE sa_sd = accept(sd,
        (struct sockaddr *)sa_in, &sa_slen);
    if (sa_sd == _SUVA_SOCKET_INVALID) {
        delete sa_in;
        throw svExSocketSyscall("accept", _SUVA_SOCKET_ERRNO);
    }

    svSocketInet *skt = new svSocketInet(sa_sd, sa_slen, sa_in);
    skt->SetRaw((bool)(flags & SVSKT_FLAG_RAW));
    skt->SetFrontDoor((bool)(flags & SVSKT_FLAG_SFD));
    skt->SetSession(session);
    skt->SetOrganization(org);

    return skt;
}

svSocketInetConnect::svSocketInetConnect(const string &host,
    uint16_t port) : svSocketInet(svSM_CONNECT)
{
    hostpath = host;
    this->port = port;

    struct sockaddr_in *sa_in = GetSockAddr();
    sa_in->sin_port = htons(port);

    struct linger linger;

    memset(&linger, 0, sizeof(struct linger));
    linger.l_onoff = 1;
    linger.l_linger = ttl;

    if (setsockopt(sd, SOL_SOCKET, SO_LINGER,
        (char *)&linger, sizeof(struct linger)) != 0) {
        throw svExSocketSyscall("setsockopt: SO_LINGER",
            _SUVA_SOCKET_ERRNO);
    }

    state = svSS_CONNECT;
}

void svSocketInetConnect::Connect(void)
{
    if (sd == _SUVA_SOCKET_INVALID && type == svST_INET &&
        mode == svSM_CONNECT && state == svSS_NULL) {
        delete [] saddr;
        slen = sizeof(struct sockaddr_in);
        saddr = new uint8_t[slen];
        memset(saddr, 0, slen);

        sd = socket(AF_INET, SOCK_STREAM, 0);
        if (sd == _SUVA_SOCKET_INVALID)
            throw svExSocketCreate(_SUVA_SOCKET_ERRNO);
        SetNonBlockingMode();
        struct sockaddr_in *sa_in = GetSockAddr();
        sa_in->sin_family = AF_INET;
        sa_in->sin_port = htons(port);

        struct linger linger;

        memset(&linger, 0, sizeof(struct linger));
        linger.l_onoff = 1;
        linger.l_linger = ttl;

        if (setsockopt(sd, SOL_SOCKET, SO_LINGER,
            (char *)&linger, sizeof(struct linger)) != 0) {
            throw svExSocketSyscall("setsockopt: SO_LINGER",
                _SUVA_SOCKET_ERRNO);
        }
        state = svSS_CONNECT;
    }

    if (state == svSS_CONNECT) {
        struct sockaddr_in *sa_in = GetSockAddr();
        struct addrinfo hints, *result;

        memset(&hints, 0, sizeof(struct addrinfo));
        hints.ai_family = sa_in->sin_family;
        hints.ai_flags = AI_PASSIVE;

        int rc;
        if ((rc = getaddrinfo(hostpath.c_str(),
            NULL, &hints, &result)) != 0) {
            throw svExSocketSyscall("getaddrinfo", rc);
        }

        struct sockaddr_in *sa_in_src =
            (struct sockaddr_in *)result->ai_addr;
        sa_in->sin_addr.s_addr = sa_in_src->sin_addr.s_addr;
        freeaddrinfo(result);
        gettimeofday(&active, NULL);
        if (connect(sd, svSocket::GetSockAddr(), slen) == 0) {
            state = svSS_CONNECTED;
            return;
        }

        state = svSS_CONNECTING;
    }

    if (state == svSS_CONNECTING) {
        struct timeval tv_now;
        gettimeofday(&tv_now, NULL);
        if (uint32_t(tv_now.tv_sec - active.tv_sec) > ttl)
            throw svExSocketTimeout("connect");

        if (connect(sd, svSocket::GetSockAddr(), slen) == 0) {
            state = svSS_CONNECTED;
            return;
        }

        if (_SUVA_SOCKET_ERROR(EISCONN)) {
            state = svSS_CONNECTED;
            return;
        }

        if (_SUVA_SOCKET_ERROR(EALREADY) ||
            _SUVA_SOCKET_ERROR(EINPROGRESS) ||
            _SUVA_SOCKET_ERROR(EWOULDBLOCK))
            return;

        throw svExSocketSyscall("connect", _SUVA_SOCKET_ERRNO);
    }
}

svSocketPipeListen::svSocketPipeListen(const string &path)
    : svSocketPipe(svSM_LISTEN)
{
#ifndef __WIN32__
    hostpath = path;

    struct sockaddr_un *sa_un = GetSockAddr();
    strncpy(sa_un->sun_path, hostpath.c_str(), UNIX_PATH_MAX);

#ifdef __linux__
    long max_path_len = 4096;
    max_path_len = pathconf(path.c_str(), _PC_PATH_MAX);
    if (max_path_len == -1) {
        throw svExSocketSyscall("pathconf: " + hostpath,
            _SUVA_SOCKET_ERRNO);
    }

    FILE *fh = fopen("/proc/net/unix", "r");
    if (!fh) {
        throw svExSocketSyscall("fopen: /proc/net/unix",
            _SUVA_SOCKET_ERRNO);
    }

    int result = 0;
    for ( ;; ) {
        char filename[max_path_len];
        uint32_t a, b, c, d, e, f, g;
        int count = fscanf(fh, "%x: %u %u %u %u %u %u ",
            &a, &b, &c, &d, &e, &f, &g);
        if (count == 0) {
            if (!fgets(filename, max_path_len, fh)) break;
            continue;
        }
        else if (count == -1) break;
        else if (!fgets(filename, max_path_len, fh)) break;
        else if (strncmp(filename,
            hostpath.c_str(), hostpath.size()) == 0) {
            result = EADDRINUSE;
            break;
        }
    }

    fclose(fh);
    if (result != 0)
        throw svExSocketSyscall(hostpath, _SUVA_SOCKET_ERRNO);
#endif // __linux__

    struct stat skt_stat;
    if (stat(hostpath.c_str(), &skt_stat) != 0) {
        if (errno != ENOENT) {
            throw svExSocketSyscall("stat: " + hostpath,
                _SUVA_SOCKET_ERRNO);
        }
    }
    else if (unlink(hostpath.c_str()) != 0) {
        throw svExSocketSyscall("unlink: " + hostpath,
            _SUVA_SOCKET_ERRNO);
    }

    if (bind(sd, svSocket::GetSockAddr(), slen) != 0)
        throw svExSocketSyscall("bind", _SUVA_SOCKET_ERRNO);

    if (listen(sd, SOMAXCONN) != 0)
        throw svExSocketSyscall("listen", _SUVA_SOCKET_ERRNO);

    uid_t uid; gid_t gid;
    svService::GetConf()->Lock();
    svService::GetConf()->GetUidGid(uid, gid);
    svService::GetConf()->Unlock();

    if (chown(hostpath.c_str(), uid, gid) != 0) {
        throw svExSocketSyscall("chown: " + hostpath,
            _SUVA_SOCKET_ERRNO);
    }
    if (chmod(hostpath.c_str(),
        S_IRUSR | S_IWUSR | S_IXUSR |
        S_IRGRP | S_IWGRP | S_IXGRP) != 0) {
        throw svExSocketSyscall("chmod: " + hostpath,
            _SUVA_SOCKET_ERRNO);
    }

    state = svSS_LISTEN;
#else
    throw svExSocketUnsupported("Local UNIX socket");
#endif
}

svSocket *svSocketPipeListen::Accept(void)
{
#ifndef __WIN32__
    socklen_t sa_slen = slen;
    struct sockaddr_un *sa_un =
        (struct sockaddr_un *)new uint8_t[slen];

    int sa_sd = accept(sd, (struct sockaddr *)sa_un, &sa_slen);

    if (sa_sd == -1) {
        delete sa_un;
        throw svExSocketSyscall("accept", _SUVA_SOCKET_ERRNO);
    }

    svSocketPipe *skt = new svSocketPipe(sa_sd,
        sa_slen, sa_un, hostpath);
    skt->SetRaw((bool)(flags & SVSKT_FLAG_RAW));
    skt->SetFrontDoor((bool)(flags & SVSKT_FLAG_SFD));
    skt->SetSession(session);
    skt->SetOrganization(org);

    return skt;
#else
    return NULL;
#endif
}

svSocketPipeConnect::svSocketPipeConnect(const string &path)
    : svSocketPipe(svSM_CONNECT)
{
#ifndef __WIN32__
    hostpath = path;

    struct sockaddr_un *sa_un = GetSockAddr();
    strncpy(sa_un->sun_path, hostpath.c_str(), UNIX_PATH_MAX);

    state = svSS_CONNECT;
#else
    throw svExSocketUnsupported("Local UNIX socket");
#endif
}

void svSocketPipeConnect::Connect(void)
{
}

svSocketPair::svSocketPair() : svSocketInet()
{
    sp[0] = _SUVA_SOCKET_INVALID;
    sp[1] = _SUVA_SOCKET_INVALID;
#if HAVE_SOCKETPAIR
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == -1)
        throw svExSocketSyscall("socketpair", _SUVA_SOCKET_ERRNO);
#else
#warning "No suitable socketpair() found."
    return;
#endif
    sd = sp[0];
    sp[0] = _SUVA_SOCKET_INVALID;
    SetNonBlockingMode();
    flags = SVSKT_FLAG_RAW;
    state = svSS_CONNECTED;
    name = "svSocketPair";
}

svSocketPair::~svSocketPair()
{
    Close();
    svSocket::Close();
}

void svSocketPair::Close(void)
{
    if (sp[1] != _SUVA_SOCKET_INVALID) {
        shutdown(sp[1], SHUT_RDWR);
        _SUVA_SOCKET_CLOSE(sp[1]);
        sp[1] = _SUVA_SOCKET_INVALID;
    }
}

svSocketSet::svSocketSet()
    : svObject("svSocketSet")
{
    Reset();
}

svSocketSet::~svSocketSet() { } 

void svSocketSet::SelectForRead(svSocket *skt)
{
    vector<svSocket *>::iterator i;
    for (i = skt_read.begin(); i != skt_read.end(); i++) {
        if ((*i)->sd != skt->sd) continue;
        return;
    }
    skt_read.push_back(skt);
}

void svSocketSet::SelectForWrite(svSocket *skt)
{
    vector<svSocket *>::iterator i;
    for (i = skt_write.begin(); i != skt_write.end(); i++) {
        if ((*i)->sd != skt->sd) continue;
        return;
    }
    skt_write.push_back(skt);
}

bool svSocketSet::IsSetForRead(svSocket *skt)
{
    vector<svSocket *>::iterator i;
    for (i = skt_read.begin(); i != skt_read.end(); i++) {
        if ((*i) != skt) continue;
        return true;
    }
    return false;
}

bool svSocketSet::IsSetForWrite(svSocket *skt)
{
    vector<svSocket *>::iterator i;
    for (i = skt_write.begin(); i != skt_write.end(); i++) {
        if ((*i) != skt) continue;
        return true;
    }
    return false;
}

void svSocketSet::RemoveForRead(svSocket *skt)
{
    vector<svSocket *>::iterator i;
    for (i = skt_read.begin(); i != skt_read.end(); i++) {
        if ((*i)->sd != skt->sd) continue;
        skt_read.erase(i);
        break;
    }
}

void svSocketSet::RemoveForWrite(svSocket *skt)
{
    vector<svSocket *>::iterator i;
    for (i = skt_write.begin(); i != skt_write.end(); i++) {
        if ((*i)->sd != skt->sd) continue;
        skt_write.erase(i);
        break;
    }
}

bool svSocketSet::IsReadyForRead(svSocket *skt)
{
    return (bool)FD_ISSET(skt->sd, &fds_read);
}

bool svSocketSet::IsReadyForWrite(svSocket *skt)
{
    return (bool)FD_ISSET(skt->sd, &fds_write);
}

void svSocketSet::Reset(void)
{
    FD_ZERO(&fds_read);
    FD_ZERO(&fds_write);

    skt_read.clear();
    skt_write.clear();
}

int svSocketSet::Select(uint32_t timeout)
{
    FD_ZERO(&fds_read);
    FD_ZERO(&fds_write);

    int max_fd = 0;
    vector<svSocket *>::iterator i;
    for (i = skt_read.begin(); i != skt_read.end(); i++) {
        if ((*i)->sd > max_fd) max_fd = (*i)->sd;
        FD_SET((*i)->sd, &fds_read);
    }
    for (i = skt_write.begin(); i != skt_write.end(); i++) {
        if ((*i)->sd > max_fd) max_fd = (*i)->sd;
        FD_SET((*i)->sd, &fds_write);
    }

    struct timeval tv;
    if (timeout > 0) {
        uint32_t s = timeout / 1000;
        uint32_t us = (timeout - s) * 1000;
        tv.tv_sec = s;
        tv.tv_usec = us;
    }

    int rc;
    rc = select(max_fd + 1,
        skt_read.size() ? &fds_read : NULL,
        skt_write.size() ? &fds_write : NULL,
        NULL, timeout ? &tv : NULL);
    if (rc == -1) {
        if (errno == EINTR) return -1;
        throw svExSocketSelect(_SUVA_SOCKET_ERRNO);
    }

    return rc;
}

svSocketBuffer::svSocketBuffer()
    : svObject("svSocketBuffer"), length(0) { }

svSocketBuffer::~svSocketBuffer()
{
}

void svSocketBuffer::Push(uint8_t *data, ssize_t data_size)
{
    struct chunk *p = new struct chunk;
    p->length = data_size;
    p->data = new uint8_t[data_size];
    memcpy(p->data, data, data_size);
    buffer.push(p);
    length += data_size;
}

uint8_t *svSocketBuffer::Pop(ssize_t *data_size)
{
    struct chunk *p;
    uint8_t *data;

    if (data_size == NULL) {

        while (!buffer.empty()) {
            p = buffer.front();
            delete p->data;
            delete p;
            buffer.pop();
        }

        length = 0;
        return NULL;
    }

    p = buffer.front();
    buffer.pop();

    length -= p->length;
    *data_size = p->length;
    data = p->data;
    delete p;

    return data;
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
