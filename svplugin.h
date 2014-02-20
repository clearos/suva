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

#ifndef _SVPLUGIN_H
#define _SVPLUGIN_H

using namespace std;

#include "plugin/sfd.h"

class svExPluginLoad : public runtime_error
{
public:
    explicit svExPluginLoad(const string &plugin)
        : runtime_error("Error loading plug-in: " + plugin) { };
    virtual ~svExPluginLoad() throw() { };
};

class svExPluginBind : public runtime_error
{
public:
    explicit svExPluginBind(const string &plugin, const string &func)
        : runtime_error(plugin + ": " + func) { };
    virtual ~svExPluginBind() throw() { };
};

enum svPluginType
{
    svSPT_SFD,
};

class svPlugin : public svObject
{
public:
    svPlugin(svPluginType type, const svConfPlugin &conf);
    virtual ~svPlugin();

    svPluginType GetType(void) { return type; };

protected:
    string path;
    svPluginType type;
    DSO *dso;

    virtual void Load(void);
    virtual void Unload(void);
    virtual void Bind(void) = 0;
};

class svExPluginFrontDoorInit : public runtime_error
{
public:
    explicit svExPluginFrontDoorInit(const string &plugin,
        const string &what)
        : runtime_error(plugin + ": " + what) { };
    virtual ~svExPluginFrontDoorInit() throw() { };
};

class svExPluginFrontDoorVersion : public runtime_error
{
public:
    explicit svExPluginFrontDoorVersion(const string &plugin,
        const string &what)
        : runtime_error(plugin + ": " + what) { };
    virtual ~svExPluginFrontDoorVersion() throw() { };
};

class svExPluginFrontDoorKnock : public runtime_error
{
public:
    explicit svExPluginFrontDoorKnock(const string &plugin,
        const string &what)
        : runtime_error(plugin + ": " + what) { };
    virtual ~svExPluginFrontDoorKnock() throw() { };
};

class svPluginFrontDoor : public svPlugin
{
public:
    svPluginFrontDoor(const svConfPlugin &conf, svSocket *skt);
    virtual ~svPluginFrontDoor();

    void Knock(void);
    void Answer(void);
    void Close(uint32_t reason);

    const string &GetDevice(void) const { return dev; };
    const string &GetOrganization(void) const { return org; };
    const string &GetSession(void) const { return session; };
    const string &GetHost(void) const { return dst_host; };
    uint16_t GetPort(void) { return sfd_conf.dst_port; };
    uint16_t GetSessionTTL(void) { return sfd_conf.session_ttl; };

    void SetWriteFunc(sfd_write_t sfd_write)
    {
        sfd_conf.sfd_write = sfd_write;
    };
    void SetPrivateData(void *data)
    {
        sfd_conf.private_data = data;
    };

protected:
    uint32_t version;
    string dev;
    string org;
    string session;
    string dst_host;
    struct sfd_conf_t sfd_conf;

    sfd_load_t sfd_load;
    sfd_unload_t sfd_unload;
    sfd_knock_t sfd_knock;
    sfd_answer_t sfd_answer;
    sfd_close_t sfd_close;

    virtual void Load(void);
    virtual void Unload(void);
    virtual void Bind(void);
};

#endif // _SVPLUGIN_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
