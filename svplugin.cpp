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

#include <sys/time.h>

#include <unistd.h>
#include <string.h>
#include <expat.h>
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
#include "svutil.h"
#include "svplugin.h"

static void sv_plugin_output(uint32_t level,
    const char *prefix, char *format, ...)
{
}

svPlugin::svPlugin(svPluginType type, const svConfPlugin &conf)
    : svObject("svPlugin"), type(type), dso(NULL)
{
    svConfPlugin plugin_conf(conf);
    name = plugin_conf.GetName();
    path = plugin_conf.GetLibrary();
}

svPlugin::~svPlugin()
{
    Unload();
}

void svPlugin::Load(void)
{
    if (!(dso = DSO_load(NULL, path.c_str(), NULL, 0)))
        throw svExPluginLoad(name + " (" + path.c_str() + ")");
}

void svPlugin::Unload(void)
{
    if (dso) {
        DSO_free(dso);
        dso = NULL;
    }
}

svPluginFrontDoor::svPluginFrontDoor(const svConfPlugin &conf,
    svSocket *skt)
    : svPlugin(svSPT_SFD, conf),
    sfd_load(NULL), sfd_unload(NULL), sfd_knock(NULL),
    sfd_answer(NULL), sfd_close(NULL)
{
    Load();
    memset(&sfd_conf, 0, sizeof(struct sfd_conf_t));
    sfd_conf.sd = skt->GetDescriptor();
    sfd_conf.sfd_output = sv_plugin_output;
}

svPluginFrontDoor::~svPluginFrontDoor()
{
    Unload();
}

#ifndef HAVE_STRNLEN
#define strnlen(s, n)   strlen(s)
#endif

void svPluginFrontDoor::Knock(void)
{
    int rc = sfd_knock(&sfd_conf);
    if (rc != 0) {
        throw svExPluginFrontDoorKnock(name,
            "Front door knock failed");
    }

    if (sfd_conf.dev == NULL ||
        sfd_conf.session == NULL ||
        sfd_conf.org == NULL ||
        sfd_conf.dst_host == NULL) {
        throw svExPluginFrontDoorKnock(name,
            "Front door knock returned invalid data");
    }

    svLegalizeString(dev, sfd_conf.dev,
        strnlen(sfd_conf.dev, _SUVA_MAX_NAME_LEN));
    svLegalizeString(org, sfd_conf.org,
        strnlen(sfd_conf.org, _SUVA_MAX_NAME_LEN));
    svLegalizeString(session, sfd_conf.session,
        strnlen(sfd_conf.session, _SUVA_MAX_NAME_LEN));
    svLegalizeString(dst_host, sfd_conf.dst_host,
        strnlen(sfd_conf.dst_host, _SUVA_MAX_NAME_LEN));
}

void svPluginFrontDoor::Answer(void)
{
    if (sfd_answer) sfd_answer(&sfd_conf);
}

void svPluginFrontDoor::Close(uint32_t reason)
{
    if (sfd_close) sfd_close(&sfd_conf, reason);
}

void svPluginFrontDoor::Load(void)
{
    svPlugin::Load();
    if (!(sfd_load = (sfd_load_t)DSO_bind_func(dso, "sfd_load")))
        throw svExPluginBind(name, "sfd_load");

    int version = sfd_load(sv_plugin_output);
    if (version == -1) {
        throw svExPluginFrontDoorInit(name,
            "Font-door initialization failed");
    } else if ((uint32_t)version > SFD_VERSION) {
        throw svExPluginFrontDoorVersion(name,
            "Incompatible front door version; too new");
    } else if ((uint32_t)version <= 0x20071126) {
        throw svExPluginFrontDoorVersion(name,
            "Incompatible front door version; too old");
    }

    Bind();
}

void svPluginFrontDoor::Unload(void)
{
    if (sfd_unload) sfd_unload();
    svPlugin::Unload();
}

void svPluginFrontDoor::Bind(void)
{
    if (!(sfd_unload = (sfd_unload_t)DSO_bind_func(dso,
        "sfd_unload"))) throw svExPluginBind(name, "sfd_unload");
    if (!(sfd_knock = (sfd_knock_t)DSO_bind_func(dso,
        "sfd_knock"))) throw svExPluginBind(name, "sfd_knock");
    sfd_answer = (sfd_answer_t)DSO_bind_func(dso, "sfd_answer");
    sfd_close = (sfd_close_t)DSO_bind_func(dso, "sfd_close");
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
