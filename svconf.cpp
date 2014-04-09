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

#include <sys/types.h>
#include <sys/stat.h>

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <fcntl.h>
#include <pthread.h>
#include <libgen.h>
#include <errno.h>
#include <expat.h>

#ifndef __WIN32__
#include <pwd.h>
#include <grp.h>
#endif 

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

#ifdef HAVE_LIBPOPT
#include <popt.h>
#endif

#include "svoutput.h"
#include "svobject.h"
#include "svutil.h"
#include "svconf.h"

#ifndef __ANDROID__
extern int errno;
#endif
extern int optind;

svConfSocket::svConfSocket()
    : svObject("svConfNullSocket"),
    type(svST_NULL), mode(svSM_NULL), port(0) { }

svConfSocket::svConfSocket(
    svConfSocketType type, svConfSocketMode mode,
    const string &ifn, const string &path,
    const string &host, uint16_t port)
    : svObject("svConfSocket"), type(type), mode(mode),
    ifn(ifn), path(path), host(host), port(port),
    vpn_type(svVT_TAP), persist(false) { }

svConfInetSocket::svConfInetSocket(
    svConfSocketMode mode, const string &ifn,
    const string &host, uint16_t port)
    : svConfSocket(svST_INET, mode, ifn, "", host, port)
{
    name = "svConfInetSocket";
}

svConfPipeSocket::svConfPipeSocket(
    svConfSocketMode mode, const string &path)
    : svConfSocket(svST_PIPE, mode, "", path, "", 0)
{
    name = "svConfPipeSocket";
}

svConfSocketVpn::svConfSocketVpn(const string &ifn)
    : svConfSocket(svST_VPN, svSM_NULL, ifn, "", "", 0)
{
    name = "svConfSocketVpn";
}

svConfInetListen::svConfInetListen(const string &ifn, uint16_t port)
    : svConfInetSocket(svSM_LISTEN, ifn, "", port)
{
    name = "svConfInetListen";
}

svConfInetConnect::svConfInetConnect(const string &host, uint16_t port)
    : svConfInetSocket(svSM_CONNECT , "", host, port)
{
    name = "svConfInetConnect";
}

svConfPipeListen::svConfPipeListen(const string &path)
    : svConfPipeSocket(svSM_LISTEN, path)
{
    name = "svConfPipeListen";
}

svConfPipeConnect::svConfPipeConnect(const string &path)
    : svConfPipeSocket(svSM_CONNECT, path)
{
    name = "svConfPipeConnect";
}

svConfRSAKey::svConfRSAKey(const string &name,
    svConfRSAKeyType type, uint32_t bits)
    : svObject(name), type(type), bits(bits), mtime(0) { }

svConfSession::svConfSession(const string &name,
    svConfSessionType type, bool exclusive)
    : svObject(name), type(type), exclusive(exclusive) { }

svConfSessionApp::svConfSessionApp(
    const string &name, int fdr, int fdw)
    : svConfSession(name, svSE_APP), fdr(fdr), fdw(fdw) { }

svConfSessionApp::svConfSessionApp(const string &name,
    const string &path, const string &args, int fdr, int fdw)
    : svConfSession(name, svSE_APP), path(path), fdr(fdr), fdw(fdw)
{
    if (args.size()) {
#ifdef _SUVA_USE_POPT
        int32_t argc;
        char **argv;
        if (poptParseArgvString(args.c_str(), &argc,
            (const char ***)&argv) != 0) {
            svError("%s: Error parsing arguments: %s",
                name.c_str(), args.c_str());
        }
        else {
            for(int32_t i = 0; i < argc; i++)
                this->args.push_back(argv[i]);
            free(argv);
        }
#else
        this->args.push_back(args);
#endif
    }
}

svConfSessionTunnel::svConfSessionTunnel(const string &name,
    const svConfSocket &skt_connect, uint32_t flags)
    : svConfSession(name, svSE_TUNNEL),
    skt_listen(), skt_connect(skt_connect), flags(flags) { }

svConfSessionTunnel::svConfSessionTunnel(const string &name,
    const svConfSocket &skt_listen, const svConfSocket &skt_connect)
    : svConfSession(name, svSE_TUNNEL),
    skt_listen(skt_listen), skt_connect(skt_connect), flags(0) { }

svConfSessionVpn::svConfSessionVpn(const string &name,
    const svConfSocketVpn &skt_vpn)
    : svConfSession(name, svSE_VPN, true),
    skt_vpn(skt_vpn), retry(_SUVA_DEFAULT_RETRY) { }

svConfSessionVpn::svConfSessionVpn(const string &name,
    const svConfSocketVpn &skt_vpn, const svConfSocket &skt_connect)
    : svConfSession(name, svSE_VPN, true),
    skt_vpn(skt_vpn), skt_connect(skt_connect),
    retry(_SUVA_DEFAULT_RETRY) { }

svConfSessionPool::svConfSessionPool(const string &name,
    const svConfSocket &skt_connect)
    : svConfSession(name, svSE_POOL),
    skt_connect(skt_connect), retry(_SUVA_DEFAULT_RETRY) { }

svConfDatabase::svConfDatabase(const string &name, svConfDatabaseType type)
    : svObject(name), type(type) { }

const string &svConfDatabase::GetSqlVariable(const string &key) const
{
    map<string, string>::const_iterator i = sql_var.find(key);
    if (i == sql_var.end()) throw svExConfSqlVarNotFound(key);
    return i->second;
}

svConfDatabaseBerkeley::svConfDatabaseBerkeley(
    const string &data_dir)
    : svConfDatabase("svConfDatabaseBerkeley", svDT_BDB)
{
    this->data_dir = data_dir;
}

svConfDatabasePostgreSQL::svConfDatabasePostgreSQL(
    const string &host, const string &port,
    const string &user, const string &pass, const string &dbname,
    const string &timeout)
    : svConfDatabase("svConfDatabasePostgreSQL", svDT_PGSQL)
{
    this->host = host;
    this->port = port;
    this->user = user;
    this->pass = pass;
    this->dbname = dbname,
    this->timeout = timeout;
}

svConfDatabaseMySQL::svConfDatabaseMySQL(
    const string &host, const string &port,
    const string &user, const string &pass, const string &dbname,
    const string &timeout)
    : svConfDatabase("svConfDatabaseMySQL", svDT_MYSQL)
{
    this->host = host;
    this->port = port;
    this->user = user;
    this->pass = pass;
    this->dbname = dbname,
    this->timeout = timeout;
}

svConfPlugin::svConfPlugin(const string &name, const string &library)
    : svObject(name), library(library) { }

svConfFrontDoor::svConfFrontDoor(const string &name,
    const string &plugin, const string &ifn, uint16_t port)
    : svObject(name), plugin(plugin),
    skt(svConfInetListen(ifn, port)) { }

svConfFrontDoor::svConfFrontDoor(const string &name,
    const string &plugin, const string &path)
    : svObject(name), plugin(plugin),
    skt(svConfPipeListen(path)) { }

svConfOrganization::svConfOrganization(const string &name)
    : svObject(name), pg_legacy(NULL) { LoadDefaults(); }

svConfOrganization::~svConfOrganization()
{
    LoadDefaults();
}

void svConfOrganization::LoadDefaults(void)
{
    device.clear();
    hostkey.clear();
    key_dir.clear();
    admin = false;
    rsa_key_cache_ttl = 3600;
    rsa_key_threshold = 66;

    for (vector<svConfRSAKey *>::iterator i = rsa_key_ring.begin();
        i != rsa_key_ring.end(); i++) delete (*i);
    rsa_key_ring.clear();

    for (vector<svConfSocket *>::iterator i = rsa_key_server.begin();
        i != rsa_key_server.end(); i++) delete (*i);
    rsa_key_server.clear();

    for (map<string, svConfSession *>::iterator i = session.begin();
        i != session.end(); i++) delete i->second;
    session.clear();

    for (map<string, svConfSocket *>::iterator i = pool_server.begin();
        i != pool_server.end(); i++) delete i->second;
    pool_server.clear();

    for (map<svConfDatabaseType, svConfDatabase *>::iterator i = database.begin();
        i != database.end(); i++) delete i->second;
    database.clear();

    if (pg_legacy) delete pg_legacy;
    pg_legacy = NULL;
}

svConfSession *svConfOrganization::GetSession(const string &name)
{
    map<string, svConfSession *>::iterator i;
    i = session.find(name);
    if (i == session.end()) return NULL;
    return i->second;
}

svConfDatabase *svConfOrganization::GetDatabase(svConfDatabaseType type)
{
    map<svConfDatabaseType, svConfDatabase *>::iterator i;
    i = database.find(type);
    if (i == database.end()) return NULL;
    return i->second;
}

void svConfOrganization::AddSessionApp(const string &name,
    const string &path, const string &args, int fdr, int fdw)
{
    if (GetSession(name)) {
        throw svExConfValueDuplicate(
            "Invalid application value; duplicate \"execute\"");
    }
    svConfSessionApp *app = new svConfSessionApp(name,
        path, args, fdr, fdw);
    session[name] = app;
}

void svConfOrganization::AddSessionTunnel(const string &name,
    const svConfSocket &skt_connect, uint32_t flags)
{
    if (GetSession(name)) {
        throw svExConfValueDuplicate(
            "Invalid tunnel value; duplicate");
    }
    svConfSessionTunnel *tunnel =
        new svConfSessionTunnel(name, skt_connect, flags);
    session[name] = tunnel;
}

void svConfOrganization::AddSessionTunnel(const string &name,
    const svConfSocket &skt_listen, const svConfSocket &skt_connect)
{
    if (GetSession(name)) {
        throw svExConfValueDuplicate(
            "Invalid tunnel value; duplicate");
    }
    svConfSessionTunnel *tunnel =
        new svConfSessionTunnel(name, skt_listen, skt_connect);
    session[name] = tunnel;
}

svConfSessionVpn *svConfOrganization::AddSessionVpn(
    const string &name, const svConfSocketVpn &skt_vpn)
{
    if (GetSession(name)) {
        throw svExConfValueDuplicate(
            "Invalid tunnel value; duplicate");
    }
    svConfSessionVpn *vpn = new svConfSessionVpn(name, skt_vpn);
    session[name] = vpn;
    return vpn;
}

svConfSessionVpn *svConfOrganization::AddSessionVpn(
    const string &name,
    const svConfSocketVpn &skt_vpn, const svConfSocket &skt_connect)
{
    if (GetSession(name)) {
        throw svExConfValueDuplicate(
            "Invalid tunnel value; duplicate");
    }
    svConfSessionVpn *vpn = new svConfSessionVpn(name,
        skt_vpn, skt_connect);
    session[name] = vpn;
    return vpn;
}

svConfSessionPool *svConfOrganization::AddSessionPool(
    const string &name, const svConfSocket &skt_connect)
{
    if (GetSession(name)) {
        throw svExConfValueDuplicate(
            "Invalid pool-server value; duplicate");
    }
    svConfSessionPool *pool = new svConfSessionPool(name,
        skt_connect);
    session[name] = pool;
    return pool;
}

void svConfOrganization::AddDatabase(svConfDatabaseType type, const svConfDatabase &db)
{
    if (GetDatabase(type)) {
        throw svExConfValueDuplicate(
            "Invalid database value; duplicate");
    }
    database[type] = new svConfDatabase(db);
}

void svConfOrganization::SetLegacyPostgreSQLValue(
    svConfLegacyPostgreSQLKey key, const string &value)
{
    if (!pg_legacy) pg_legacy = new svConfDatabasePostgreSQL();
    switch (key) {
    case svPK_HOST:
        pg_legacy->SetHost(value);
        break;
    case svPK_PORT:
        pg_legacy->SetPort(value);
        break;
    case svPK_DBNAME:
        pg_legacy->SetDatabaseName(value);
        break;
    case svPK_USER:
        pg_legacy->SetUsername(value);
        break;
    case svPK_PASS:
        pg_legacy->SetPassword(value);
        break;
    case svPK_TIMEOUT:
        pg_legacy->SetTimeout(value);
        break;
    case svPK_QUERY_HOSTKEY:
        {
            string sql = value;
            size_t pos = sql.find("%s");
            if (pos != string::npos)
                sql.replace(pos, 2, "%d");
            pg_legacy->SetSqlQueryHostKey(sql);
        }
        break;
    }
}

svXmlTag::svXmlTag(const char *name, const char **attr)
    : svObject(name)
{
    for (int i = 0; attr[i]; i += 2)
        param[attr[i]] = attr[i + 1];
}

bool svXmlTag::ParamExists(const string &key)
{
    map<string, string>::iterator i;
    i = param.find(key);
    return (bool)(i != param.end());
}

string svXmlTag::GetParamValue(const string &key)
{
    map<string, string>::iterator i;
    i = param.find(key);
    if (i == param.end())
        throw svExConfKeyNotFound(key);
    return i->second;
}

bool svXmlTag::operator==(const char *tag)
{
    if (!strcasecmp(tag, name.c_str())) return true;
    return false;
}

bool svXmlTag::operator!=(const char *tag)
{
    if (!strcasecmp(tag, name.c_str())) return false;
    return true;
}

static void svXmlElementOpen(
    void *data, const char *element, const char **attr)
{
    svXmlParser *svp = (svXmlParser *)data;

    svXmlTag *tag = new svXmlTag(element, attr);
    svDebug("Element open: %s", tag->GetName().c_str());
    svp->ParseElementOpen(tag);
    svp->stack.push_back(tag);
}

static void svXmlElementClose(void *data, const char *element)
{
    svXmlParser *svp = (svXmlParser *)data;

    svXmlTag *tag = svp->stack.back();
    svDebug("Element close: %s", tag->GetName().c_str());
    string text = tag->GetText();
#if 0
    if (text.size()) {
        svDebug("Text[%d]:", text.size());
        svHexDump(stderr, text.c_str(), text.size());
    }
#endif
    svp->stack.pop_back();
    svp->ParseElementClose(tag);
    delete tag;
}

static void svXmlText(void *data, const char *txt, int length)
{
    svXmlParser *svp = (svXmlParser *)data;

    svXmlTag *tag = svp->stack.back();
    string text = tag->GetText();
    for (int i = 0; i < length; i++) {
        if (txt[i] == '\n' || txt[i] == '\r' ||
            !isprint(txt[i])) continue;
        text.append(1, txt[i]);
    }
    tag->SetText(text);
}

svXmlParser::svXmlParser(svConf *conf)
    : svObject("svXmlParser"),
    conf(conf), fh(NULL), buffer(NULL), version(0)
{
    p = XML_ParserCreate(NULL);
    XML_SetUserData(p, (void *)this);
    XML_SetElementHandler(p, svXmlElementOpen, svXmlElementClose);
    XML_SetCharacterDataHandler(p, svXmlText);
    page_size = svGetPageSize();
    buffer = new uint8_t[page_size];
}

svXmlParser::~svXmlParser()
{
    XML_ParserFree(p);
    delete [] buffer;
    if (fh) fclose(fh);
    for (vector<svXmlTag *>::iterator i = stack.begin();
        i != stack.end(); i++) delete (*i);
}

void svXmlParser::Parse(void)
{
    if (!(fh = fopen(conf->filename.c_str(), "r")))
        throw svExConfOpen(conf->filename, strerror(errno));
    for (;;) {
        size_t length;
        length = fread(buffer, 1, page_size, fh);
        if (ferror(fh))
            throw svExConfRead(conf->filename, strerror(errno));
        int done = feof(fh);

        if (!XML_Parse(p, (const char *)buffer, length, done)) {
            ParseError(string("XML parse error: ") +
                    XML_ErrorString(XML_GetErrorCode(p)));
        }
        if (done) break;
    }
}

void svXmlParser::ParseError(const string &what)
{
    throw svExConfParse(conf->filename, what,
        XML_GetCurrentLineNumber(p),
        XML_GetCurrentColumnNumber(p),
        buffer[XML_GetCurrentByteIndex(p)]);
}

void svXmlParser::ParseElementOpen(svXmlTag *tag)
{
    if ((*tag) == "inet-accept" &&
        stack.size() && (*stack.back()) == "stl-port") {
        string ifn("all");
        if (tag->ParamExists("ifn"))
            ifn = tag->GetParamValue("ifn");
        if (!tag->ParamExists("port"))
            ParseError("Missing required parameter: port");

        uint16_t port;
        port = (uint16_t)atoi(tag->GetParamValue("port").c_str());
        conf->AddSTLInetPort(ifn, port);
    }
    else if ((*tag) == "library" &&
        stack.size() && (*stack.back()) == "plug-in") {
        if (!tag->ParamExists("name"))
            ParseError("Missing required parameter: name");
        if (!tag->ParamExists("dso"))
            ParseError("Missing required parameter: dso");
        if (conf->GetPlugin(tag->GetParamValue("name")))
            ParseError("Duplicate plug-in: " + tag->GetName());

        conf->AddPlugin(tag->GetParamValue("name"),
            tag->GetParamValue("dso"));
    }
    else if ((*tag) == "inet-accept" &&
        stack.size() && (*stack.back()) == "front-door") {
        string ifn("all");
        if (!tag->ParamExists("name"))
            ParseError("Missing required parameter: name");
        if (!tag->ParamExists("plug-in"))
            ParseError("Missing required parameter: plug-in");
        if (tag->ParamExists("ifn"))
            ifn = tag->GetParamValue("ifn");
        if (!tag->ParamExists("port"))
            ParseError("Missing required parameter: port");
        if (conf->GetFrontDoor(tag->GetParamValue("name")))
            ParseError("Duplicate front-door: " + tag->GetName());

        uint16_t port;
        port = (uint16_t)atoi(tag->GetParamValue("port").c_str());
        svConfFrontDoor *fd;
        fd = new svConfFrontDoor(
            tag->GetParamValue("name"),
            tag->GetParamValue("plug-in"), ifn, port);
        conf->front_door[fd->GetName()] = fd;
    }
    else if ((*tag) == "inet-accept" &&
        stack.size() && (*stack.back()) == "tunnel") {
        string ifn("all");
        if (!tag->ParamExists("name"))
            ParseError("Missing required parameter: name");
        if (tag->ParamExists("ifn"))
            ifn = tag->GetParamValue("ifn");
        if (!tag->ParamExists("port"))
            ParseError("Missing required parameter: port");
        if (!tag->ParamExists("dst-host"))
            ParseError("Missing required parameter: dst-host");
        if (!tag->ParamExists("dst-port"))
            ParseError("Missing required parameter: dst-port");

        svConfOrganization *org;
        org = (svConfOrganization *)stack.back()->GetObject();
        if (!org) ParseError("Unexpected tag: " + tag->GetName());
        uint16_t port, dst_port;
        port = (uint16_t)atoi(
            tag->GetParamValue("port").c_str());
        dst_port = (uint16_t)atoi(
            tag->GetParamValue("dst-port").c_str());
        svConfInetListen skt_listen(ifn, port);
        svConfInetConnect skt_connect(
            tag->GetParamValue("dst-host"), dst_port);
        org->AddSessionTunnel(
            tag->GetParamValue("name"), skt_listen, skt_connect);
    }
    else if ((*tag) == "inet-connect" &&
        stack.size() && (*stack.back()) == "tunnel") {
        string ifn("all");
        if (!tag->ParamExists("name"))
            ParseError("Missing required parameter: name");
        if (!tag->ParamExists("dst-host"))
            ParseError("Missing required parameter: dst-host");
        if (!tag->ParamExists("dst-port"))
            ParseError("Missing required parameter: dst-port");

        svConfOrganization *org;
        org = (svConfOrganization *)stack.back()->GetObject();
        if (!org) ParseError("Unexpected tag: " + tag->GetName());
        if (org->GetSession(tag->GetParamValue("name"))) {
            ParseError("Duplicate tunnel: " +
                tag->GetParamValue("name"));
        }
        uint32_t flags = 0;
        if (tag->ParamExists("flags")) {
            flags = (uint32_t)strtol(
                tag->GetParamValue("flags").c_str(), (char **)NULL, 0);
        }
        uint16_t dst_port;
        dst_port = (uint16_t)atoi(
            tag->GetParamValue("dst-port").c_str());
        svConfInetConnect skt_connect(
            tag->GetParamValue("dst-host"), dst_port);
        org->AddSessionTunnel(
            tag->GetParamValue("name"), skt_connect, flags);
    }
    else if ((*tag) == "pipe-accept" &&
        stack.size() && (*stack.back()) == "front-door") {
        if (!tag->ParamExists("name"))
            ParseError("Missing required parameter: name");
        if (!tag->ParamExists("plug-in"))
            ParseError("Missing required parameter: plug-in");
        if (!tag->ParamExists("path"))
            ParseError("Missing required parameter: path");
        if (conf->GetFrontDoor(tag->GetParamValue("name")))
            ParseError("Duplicate front-door: " + tag->GetName());

        svConfFrontDoor *fd;
        fd = new svConfFrontDoor(
            tag->GetParamValue("name"),
            tag->GetParamValue("plug-in"),
            tag->GetParamValue("path"));
        conf->front_door[fd->GetName()] = fd;
    }
    else if ((*tag) == "pipe-accept" &&
        stack.size() && (*stack.back()) == "tunnel") {
        if (!tag->ParamExists("name"))
            ParseError("Missing required parameter: name");
        if (!tag->ParamExists("path"))
            ParseError("Missing required parameter: path");
        if (!tag->ParamExists("dst-host"))
            ParseError("Missing required parameter: dst-host");
        if (!tag->ParamExists("dst-port"))
            ParseError("Missing required parameter: dst-port");

        svConfOrganization *org;
        org = (svConfOrganization *)stack.back()->GetObject();
        if (!org) ParseError("Unexpected tag: " + tag->GetName());
        if (org->GetSession(tag->GetParamValue("name"))) {
            ParseError("Duplicate tunnel: " +
                tag->GetParamValue("name"));
        }
        uint16_t dst_port;
        dst_port = (uint16_t)atoi(
            tag->GetParamValue("dst-port").c_str());
        svConfPipeListen skt_listen(
            tag->GetParamValue("path"));
        svConfInetConnect skt_connect(
            tag->GetParamValue("dst-host"), dst_port);
        org->AddSessionTunnel(
            tag->GetParamValue("name"), skt_listen, skt_connect);
    }
    else if ((*tag) == "pipe-connect" &&
        stack.size() && (*stack.back()) == "tunnel") {
        if (!tag->ParamExists("name"))
            ParseError("Missing required parameter: name");
        if (!tag->ParamExists("path"))
            ParseError("Missing required parameter: path");

        svConfOrganization *org;
        org = (svConfOrganization *)stack.back()->GetObject();
        if (!org) ParseError("Unexpected tag: " + tag->GetName());
        if (org->GetSession(tag->GetParamValue("name"))) {
            ParseError("Duplicate tunnel: " +
                tag->GetParamValue("name"));
        }

        uint32_t flags = 0;
        if (tag->ParamExists("flags")) {
            flags = (uint32_t)strtol(
                tag->GetParamValue("flags").c_str(), (char **)NULL, 0);
        }
        svConfPipeConnect skt_connect(
            tag->GetParamValue("path"));
        org->AddSessionTunnel(
            tag->GetParamValue("name"), skt_connect, flags);
    }
    else if ((*tag) == "organization") {
        if (!stack.size() || (*stack.back()) != "svconf")
            ParseError("Unexpected tag: " + tag->GetName());
        if (!tag->ParamExists("name"))
            ParseError("Missing required parameter: name");
        if (conf->GetOrganization(tag->GetParamValue("name")))
            ParseError("Duplicate organization: " + tag->GetName());

        svConfOrganization *org;
        org = new svConfOrganization(tag->GetParamValue("name"));
        tag->SetObject(org);
        conf->org[org->GetName()] = org;
    }
    else if ((*tag) == "tunnel" &&
        stack.size() && (*stack.back()) == "organization") {
        svConfOrganization *org;
        org = (svConfOrganization *)stack.back()->GetObject();
        tag->SetObject(org);
    }
    else if ((*tag) == "key-server" &&
        stack.size() && (*stack.back()) == "organization") {
        if (!tag->ParamExists("host"))
            ParseError("Missing required parameter: host");
        if (!tag->ParamExists("port"))
            ParseError("Missing required parameter: port");

        svConfOrganization *org;
        org = (svConfOrganization *)stack.back()->GetObject();
        org->AddRSAKeyServer(
            tag->GetParamValue("host"),
            (uint16_t)atoi(tag->GetParamValue("port").c_str()));
    }
    else if ((*tag) == "application" &&
        stack.size() && (*stack.back()) == "organization") {
        if (!tag->ParamExists("fd-read"))
            ParseError("Missing required parameter: fd-read");
        if (!tag->ParamExists("fd-write"))
            ParseError("Missing required parameter: fd-write");

        svConfOrganization *org;
        org = (svConfOrganization *)stack.back()->GetObject();
        if (org->GetSession(tag->GetParamValue("name")))
            ParseError("Duplicate session: " + tag->GetName());
        svConfSessionApp *app = new svConfSessionApp(
            tag->GetParamValue("name"),
            atoi(tag->GetParamValue("fd-read").c_str()),
            atoi(tag->GetParamValue("fd-write").c_str()));
        tag->SetObject(app);
        org->session[tag->GetParamValue("name")] = app;
    }
    else if ((*tag) == "vpn-connect" &&
        stack.size() && (*stack.back()) == "organization") {
        if (!tag->ParamExists("name"))
            ParseError("Missing required parameter: name");
        if (!tag->ParamExists("dst-host"))
            ParseError("Missing required parameter: dst-host");
        if (!tag->ParamExists("dst-port"))
            ParseError("Missing required parameter: dst-port");

        svConfOrganization *org;
        org = (svConfOrganization *)stack.back()->GetObject();
        if (org->GetSession(tag->GetParamValue("name")))
            ParseError("Duplicate session: " + tag->GetName());

        svConfSocketVpn skt_vpn(tag->ParamExists("ifn") ?
            tag->GetParamValue("ifn") : "auto");
        svDebug("vpn-connect: ifn: %s", skt_vpn.GetInterface().c_str());
        if (tag->ParamExists("persistent")) {
            skt_vpn.SetPersistent(conf->ParseBooleanValue(
                tag->GetParamValue("persistent")));
        }
        svConfInetConnect skt_connect(
            tag->GetParamValue("dst-host"),
            atoi(tag->GetParamValue("dst-port").c_str()));
        svConfSessionVpn *vpn = org->AddSessionVpn(
            tag->GetParamValue("name"), skt_vpn, skt_connect);
        if (tag->ParamExists("retry")) {
            vpn->SetRetryInterval(atoi(
                tag->GetParamValue("retry").c_str()));
        }
        tag->SetObject(vpn);
    }
    else if ((*tag) == "vpn-accept" &&
        stack.size() && (*stack.back()) == "organization") {
        if (!tag->ParamExists("name"))
            ParseError("Missing required parameter: name");

        svConfOrganization *org;
        org = (svConfOrganization *)stack.back()->GetObject();
        if (org->GetSession(tag->GetParamValue("name")))
            ParseError("Duplicate session: " + tag->GetName());

        svConfSocketVpn skt_vpn(tag->ParamExists("ifn") ?
            tag->GetParamValue("ifn") : "auto");
        if (tag->ParamExists("persistent")) {
            skt_vpn.SetPersistent(conf->ParseBooleanValue(
                tag->GetParamValue("persistent")));
        }
        svConfSessionVpn *vpn = org->AddSessionVpn(
            tag->GetParamValue("name"), skt_vpn);
        tag->SetObject(vpn);
    }
    else if ((*tag) == "pool" &&
        stack.size() && (*stack.back()) == "organization") {
        if (!tag->ParamExists("name"))
            ParseError("Missing required parameter: name");
        if (!tag->ParamExists("dst-host"))
            ParseError("Missing required parameter: dst-host");
        if (!tag->ParamExists("dst-port"))
            ParseError("Missing required parameter: dst-port");

        svConfOrganization *org;
        org = (svConfOrganization *)stack.back()->GetObject();
        if (org->GetSession(tag->GetParamValue("name")))
            ParseError("Duplicate session: " + tag->GetName());

        svConfInetConnect skt(
            tag->GetParamValue("dst-host"),
            atoi(tag->GetParamValue("dst-port").c_str()));
        svConfSessionPool *pool = org->AddSessionPool(
            tag->GetParamValue("name"), skt);
        if (tag->ParamExists("retry")) {
            pool->SetRetryInterval(atoi(
                tag->GetParamValue("retry").c_str()));
        }
    }
    else if ((*tag) == "database" &&
        stack.size() && (*stack.back()) == "organization") {
        if (!tag->ParamExists("type"))
            ParseError("Missing required parameter: type");
        if (!tag->ParamExists("db"))
            ParseError("Missing required parameter: db");

        svConfDatabase *db;
        svConfDatabaseType type = svDT_NULL;
        string db_name;
        if (!strcasecmp(
            tag->GetParamValue("type").c_str(), "pgsql")) {
            type = svDT_PGSQL;
            db_name = "PostgreSQL";
        }
        else if (!strcasecmp(
            tag->GetParamValue("type").c_str(), "mysql")) {
            type = svDT_MYSQL;
            db_name = "MySQL";
        }
        else ParseError(
            "Invalid database type: " + tag->GetParamValue("type"));
        svConfOrganization *org;
        org = (svConfOrganization *)stack.back()->GetObject();
        if (org->GetDatabase(type)) {
            throw svExConfValueDuplicate(
                "Invalid database value; duplicate");
        }
        db = new svConfDatabase(db_name, type);
        db->SetDatabaseName(tag->GetParamValue("db"));
        if (tag->ParamExists("host"))
            db->SetHost(tag->GetParamValue("host"));
        if (tag->ParamExists("port"))
            db->SetPort(tag->GetParamValue("port"));
        if (tag->ParamExists("user"))
            db->SetUsername(tag->GetParamValue("user"));
        if (tag->ParamExists("pass"))
            db->SetPassword(tag->GetParamValue("pass"));
        if (tag->ParamExists("timeout"))
            db->SetTimeout(tag->GetParamValue("timeout"));
        tag->SetObject(db);
        org->database[type] = db;
    }
}

void svXmlParser::ParseElementClose(svXmlTag *tag)
{
    string text = tag->GetText();

    if ((*tag) == "user") {
        if (!stack.size() || (*stack.back()) != "svconf")
            ParseError("Unexpected tag: " + tag->GetName());
        if (!text.size())
            ParseError("Missing value for tag: " + tag->GetName());

        conf->SetUser(text);
    }
    else if ((*tag) == "group") {
        if (!stack.size() || (*stack.back()) != "svconf")
            ParseError("Unexpected tag: " + tag->GetName());
        if (!text.size())
            ParseError("Missing value for tag: " + tag->GetName());

        conf->SetGroup(text);
    }
    else if ((*tag) == "debug") {
        if (!stack.size() || (*stack.back()) != "svconf")
            ParseError("Unexpected tag: " + tag->GetName());
        if (!text.size())
            ParseError("Missing value for tag: " + tag->GetName());

        if (conf->ParseBooleanValue(text)) svOutput::SetDebug();
    }
    else if ((*tag) == "log-facility") {
        if (!stack.size() || (*stack.back()) != "svconf")
            ParseError("Unexpected tag: " + tag->GetName());
        if (!text.size())
            ParseError("Missing value for tag: " + tag->GetName());

        conf->log_facility = conf->ParseLogFacility(text);
    }
    else if ((*tag) == "log-file") {
        if (!stack.size() || (*stack.back()) != "svconf")
            ParseError("Unexpected tag: " + tag->GetName());
        if (!text.size())
            ParseError("Missing value for tag: " + tag->GetName());

        conf->log_file = text;
    }
    else if ((*tag) == "key-ttl") {
        if (!stack.size() || (*stack.back()) != "svconf")
            ParseError("Unexpected tag: " + tag->GetName());
        if (!text.size())
            ParseError("Missing value for tag: " + tag->GetName());

        conf->key_ttl = atoi(text.c_str());
    }
    else if ((*tag) == "poll-ttl") {
        if (!stack.size() || (*stack.back()) != "svconf")
            ParseError("Unexpected tag: " + tag->GetName());
        if (!text.size())
            ParseError("Missing value for tag: " + tag->GetName());

        conf->poll_ttl = atoi(text.c_str());
    }
    else if ((*tag) == "session-ttl") {
        if (!stack.size() || (*stack.back()) != "svconf")
            ParseError("Unexpected tag: " + tag->GetName());
        if (!text.size())
            ParseError("Missing value for tag: " + tag->GetName());

        conf->session_ttl = atoi(text.c_str());
    }
    else if ((*tag) == "socket-ttl") {
        if (!stack.size() || (*stack.back()) != "svconf")
            ParseError("Unexpected tag: " + tag->GetName());
        if (!text.size())
            ParseError("Missing value for tag: " + tag->GetName());

        conf->socket_ttl = atoi(text.c_str());
    }
    else if ((*tag) == "key-size") {
        if (!stack.size() || (*stack.back()) != "svconf")
            ParseError("Unexpected tag: " + tag->GetName());
        if (!text.size())
            ParseError("Missing value for tag: " + tag->GetName());

        conf->aes_key_size = atoi(text.c_str());
    }
    else if ((*tag) == "device") {
        if (!stack.size() || (*stack.back()) != "organization")
            ParseError("Unexpected tag: " + tag->GetName());
        if (!text.size())
            ParseError("Missing value for tag: " + tag->GetName());

        svConfOrganization *org;
        org = (svConfOrganization *)stack.back()->GetObject();
        org->SetDevice(text);
    }
    else if ((*tag) == "hostkey") {
        if (!stack.size() || (*stack.back()) != "organization")
            ParseError("Unexpected tag: " + tag->GetName());
        if (!text.size())
            ParseError("Missing value for tag: " + tag->GetName());

        svConfOrganization *org;
        org = (svConfOrganization *)stack.back()->GetObject();
        org->SetHostKey(text);
    }
    else if ((*tag) == "administrator") {
        if (!stack.size() || (*stack.back()) != "organization")
            ParseError("Unexpected tag: " + tag->GetName());
        if (!text.size())
            ParseError("Missing value for tag: " + tag->GetName());

        svConfOrganization *org;
        org = (svConfOrganization *)stack.back()->GetObject();
        org->SetAdministrator(conf->ParseBooleanValue(text));
    }
    else if ((*tag) == "key-dir") {
        if (!stack.size() || (*stack.back()) != "organization")
            ParseError("Unexpected tag: " + tag->GetName());
        if (!text.size())
            ParseError("Missing value for tag: " + tag->GetName());

        svConfOrganization *org;
        org = (svConfOrganization *)stack.back()->GetObject();
        org->SetKeyDir(text);
    }
    else if ((*tag) == "key-cache-ttl") {
        if (!stack.size() || (*stack.back()) != "organization")
            ParseError("Unexpected tag: " + tag->GetName());
        if (!text.size())
            ParseError("Missing value for tag: " + tag->GetName());

        svConfOrganization *org;
        org = (svConfOrganization *)stack.back()->GetObject();
        org->SetKeyCacheTTL(atoi(text.c_str()));
    }
    else if ((*tag) == "key-poll-threshold") {
        if (!stack.size() || (*stack.back()) != "organization")
            ParseError("Unexpected tag: " + tag->GetName());
        if (!text.size())
            ParseError("Missing value for tag: " + tag->GetName());

        svConfOrganization *org;
        org = (svConfOrganization *)stack.back()->GetObject();
        org->SetKeyPollThreshold(atoi(text.c_str()));
    }
    else if ((*tag) == "max-pool-connections") {
        if (!stack.size() || (*stack.back()) != "organization")
            ParseError("Unexpected tag: " + tag->GetName());
        if (!text.size())
            ParseError("Missing value for tag: " + tag->GetName());

        svConfOrganization *org;
        org = (svConfOrganization *)stack.back()->GetObject();
        org->SetMaxPoolConnections(atoi(text.c_str()));
    }
    else if ((*tag) == "path") {
        if (!stack.size() || (*stack.back()) != "application")
            ParseError("Unexpected tag: " + tag->GetName());
        if (!text.size())
            ParseError("Missing value for tag: " + tag->GetName());

        svConfSessionApp *app;
        app = (svConfSessionApp *)stack.back()->GetObject();
        app->SetPath(text);
    }
    else if ((*tag) == "param") {
        if (!stack.size() || (*stack.back()) != "application")
            ParseError("Unexpected tag: " + tag->GetName());
        if (!text.size())
            ParseError("Missing value for tag: " + tag->GetName());

        svConfSessionApp *app;
        app = (svConfSessionApp *)stack.back()->GetObject();
        app->AddArg(text);
    }
    else if ((*tag) == "application") {
        svConfSessionApp *app;
        app = (svConfSessionApp *)tag->GetObject();
        string path = app->GetPath();
        if (!path.size())
            ParseError("Missing path for app: " + app->GetName());
    }
    else if ((*tag) == "sql") {
        if (!stack.size() || (*stack.back()) != "database")
            ParseError("Unexpected tag: " + tag->GetName());
        if (!text.size())
            ParseError("Missing value for tag: " + tag->GetName());
        if (!tag->ParamExists("name"))
            ParseError("Missing required parameter: name");

        svConfDatabase *db;
        db = (svConfDatabase *)stack.back()->GetObject();
        string query = tag->GetParamValue("name");
        if (!strcasecmp(query.c_str(), "query-hostkey"))
            db->SetSqlQueryHostKey(text);
        else if (!strcasecmp(query.c_str(), "insert-pool-client"))
            db->SetSqlInsertPoolClient(text);
        else if (!strcasecmp(query.c_str(), "update-pool-client"))
            db->SetSqlUpdatePoolClient(text);
        else if (!strcasecmp(query.c_str(), "purge-pool-clients"))
            db->SetSqlPurgePoolClients(text);
    }
    else if ((*tag) == "sql-var") {
        if (!stack.size() || (*stack.back()) != "database")
            ParseError("Unexpected tag: " + tag->GetName());
        if (!tag->ParamExists("name"))
            ParseError("Missing required parameter: name");
        if (!tag->ParamExists("value"))
            ParseError("Missing required parameter: value");

        svConfDatabase *db;
        db = (svConfDatabase *)stack.back()->GetObject();
        string key = tag->GetParamValue("name");
        string value = tag->GetParamValue("value");
        db->SetSqlVariable(key, value);
    }
    else if ((*tag) == "address") {
        if (!stack.size() ||
            ((*stack.back()) != "vpn-accept" &&
            (*stack.back()) != "vpn-connect"))
            ParseError("Unexpected tag: " + tag->GetName());
        svConfSessionVpn *vpn;
        vpn = (svConfSessionVpn *)stack.back()->GetObject();
        svConfSocketVpn *skt_vpn = vpn->GetConfSocketVpnPtr();
        skt_vpn->SetAddress(text);
    }
    else if ((*tag) == "netmask") {
        if (!stack.size() ||
            ((*stack.back()) != "vpn-accept" &&
            (*stack.back()) != "vpn-connect"))
            ParseError("Unexpected tag: " + tag->GetName());
        svConfSessionVpn *vpn;
        vpn = (svConfSessionVpn *)stack.back()->GetObject();
        svConfSocketVpn *skt_vpn = vpn->GetConfSocketVpnPtr();
        skt_vpn->SetNetmask(text);
    }
    else if ((*tag) == "mac") {
        if (!stack.size() ||
            ((*stack.back()) != "vpn-accept" &&
            (*stack.back()) != "vpn-connect"))
            ParseError("Unexpected tag: " + tag->GetName());
        svConfSessionVpn *vpn;
        vpn = (svConfSessionVpn *)stack.back()->GetObject();
        svConfSocketVpn *skt_vpn = vpn->GetConfSocketVpnPtr();
        skt_vpn->SetMacAddr(text);
    }
}

svConf::svConf(int argc, char *argv[])
    : svObject("svConf"), argc(argc), argv(argv)
{
    process_name = basename(argv[0]);
    pthread_mutex_init(&mutex, NULL);
#ifdef __WIN32__
    service_register = false;
    service_unregister = false;
#endif
}

svConf::~svConf()
{
    LoadDefaults();
    pthread_mutex_destroy(&mutex);
}

void svConf::Load(void)
{
    svMutexLocker mutex_locker(&mutex);

    LoadDefaults();
    ParseOptions();
    ParseConfigurationFile();

    for (map<string, svConfOrganization *>::iterator i = org.begin();
        i != org.end(); i++) {
        svConfDatabaseBerkeley bdb(i->second->GetKeyDir());
        i->second->AddDatabase(svDT_BDB, bdb);
        i->second->AddLegacyPostgreSQL();
    }

    if (filename_save.size()) {
        Save();
        svLog("Saved configuration to: %s", filename_save.c_str());
        filename_save.clear();
        throw svExConfSaveRequest();
    }
}

void svConf::Save(bool client)
{
    FILE *fh = fopen(filename_save.c_str(), "w");
    if (!fh) throw svExConfOpen(filename_save, strerror(errno));

    fprintf(fh, "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n");
    fprintf(fh, "<!-- Suva/3 %s Configuration\n",
        (client) ? "Client" : "Server");
    fprintf(fh, "     Generated from: %s -->\n", filename.c_str());
    fprintf(fh, "<svconf version=\"%d.%d\">\n\n",
        _SUVA_CONF_VER_MAJOR, _SUVA_CONF_VER_MINOR);
    if (user.size())
        fprintf(fh, "<user>%s</user>\n", user.c_str());
    if (group.size())
        fprintf(fh, "<group>%s</group>\n", group.c_str());
    if (user.size() || group.size()) fprintf(fh, "\n");
#ifndef __WIN32__
    fprintf(fh, "<log-facility>");
    switch (log_facility) {
    case LOG_DAEMON:
        fprintf(fh, "LOG_DAEMON");
        break;
    case LOG_LOCAL0:
        fprintf(fh, "LOG_LOCAL0");
        break;
    case LOG_LOCAL1:
        fprintf(fh, "LOG_LOCAL1");
        break;
    case LOG_LOCAL2:
        fprintf(fh, "LOG_LOCAL2");
        break;
    case LOG_LOCAL3:
        fprintf(fh, "LOG_LOCAL3");
        break;
    case LOG_LOCAL4:
        fprintf(fh, "LOG_LOCAL4");
        break;
    case LOG_LOCAL5:
        fprintf(fh, "LOG_LOCAL5");
        break;
    case LOG_LOCAL6:
        fprintf(fh, "LOG_LOCAL6");
        break;
    case LOG_LOCAL7:
        fprintf(fh, "LOG_LOCAL7");
        break;
    case LOG_USER:
        fprintf(fh, "LOG_USER");
        break;
    default:
        fprintf(fh, "%d", log_facility);
    }
    fprintf(fh, "</log-facility>\n\n");
#endif
    if (client) {
        fprintf(fh, "<key-ttl>%d</key-ttl>\n", key_ttl);
        fprintf(fh, "<poll-ttl>%d</poll-ttl>\n", poll_ttl);
    }
    else fprintf(fh, "<session-ttl>%d</session-ttl>\n", session_ttl);
    fprintf(fh, "<socket-ttl>%d</socket-ttl>\n", socket_ttl);
    fprintf(fh, "<key-size>%d</key-size>\n", aes_key_size);
//  fprintf(fh,
//      "<tcp-keepalive time=\"%d\" interval=\"%d\" probes=\"%d\"/>\n",
    fprintf(fh, "\n<stl-port>\n");
    for (vector<svConfSocket *>::iterator i = stl_port.begin();
        i != stl_port.end(); i++) {
        fprintf(fh, "\t<inet-accept ifn=\"%s\" port=\"%d\"/>\n",
            (*i)->GetInterface().c_str(), (*i)->GetPort());
    }
    fprintf(fh, "</stl-port>\n");

    fprintf(fh, "\n<plug-in>\n");
    for (map<string, svConfPlugin *>::iterator i = plugin.begin();
        i != plugin.end(); i++) {
        fprintf(fh, "\t<library name=\"%s\" dso=\"%s\"/>\n",
            i->first.c_str(), i->second->GetLibrary().c_str());
    }
    fprintf(fh, "</plug-in>\n");

    fprintf(fh, "\n<front-door>\n");
    for (map<string, svConfFrontDoor *>::iterator i =
        front_door.begin(); i != front_door.end(); i++) {
        svConfSocket conf_skt = i->second->GetConfSocket();
        if (conf_skt.GetType() == svST_INET)
            fprintf(fh, "\t<inet-accept ");
        else if (conf_skt.GetType() == svST_PIPE)
            fprintf(fh, "\t<pipe-accept ");
        fprintf(fh, "name=\"%s\" plug-in=\"%s\" ",
            i->first.c_str(), i->second->GetPlugin().c_str());
        if (conf_skt.GetType() == svST_INET) {
            fprintf(fh, "ifn=\"%s\" port=\"%d\"/>\n",
                conf_skt.GetHost().size() ?
                    conf_skt.GetHost().c_str() : "all",
                conf_skt.GetPort());
        }
        else if (conf_skt.GetType() == svST_PIPE) {
            fprintf(fh, "path=\"%s\"/>\n",
                conf_skt.GetPath().c_str());
        }
    }
    fprintf(fh, "</front-door>\n");

    uint32_t app = 0;
    uint32_t vpn = 0;
    uint32_t pool = 0;
    uint32_t tunnel = 0;
    map<string, svConfSession *> session;
    map<string, svConfOrganization *>::iterator oi;

    if (!org.size()) goto sv_conf_save_exit;
    oi = org.begin();

sv_conf_save_next_org:
    fprintf(fh, "\n<organization name=\"%s\">\n", oi->first.c_str());

    fprintf(fh, "\t<device>%s</device>\n",
        oi->second->GetDevice().c_str());
    if (client) {
        fprintf(fh, "\t<hostkey>%s</hostkey>\n",
            oi->second->GetHostKey().c_str());
        fprintf(fh, "\n\t<administrator>%s</administrator>\n",
            oi->second->GetAdministrator() ? "true" : "false");
    }

    fprintf(fh, "\n\t<key-dir>%s</key-dir>\n",
        oi->second->GetKeyDir().c_str());
    fprintf(fh, "\t<key-cache-ttl>%d</key-cache-ttl>\n",
        oi->second->GetKeyCacheTTL());
    if (client) {
        fprintf(fh,
            "\t<key-poll-threshold>%d</key-poll-threshold>\n",
            oi->second->GetKeyPollThreshold());
        vector<svConfSocket *> key_server;
        key_server = oi->second->GetRSAKeyServers();
        if (key_server.size()) fprintf(fh, "\n");
        for (vector<svConfSocket *>::iterator i = key_server.begin();
            i != key_server.end(); i++) {
            fprintf(fh, "\t<key-server host=\"%s\" port=\"%d\"/>\n",
                (*i)->GetHost().c_str(), (*i)->GetPort());
        }
    }
    else {
        fprintf(fh,
            "\t<max-pool-connections>%d</max-pool-connections>\n",
            oi->second->GetMaxPoolConnections());
    }
    fprintf(fh, "\n");

    session = oi->second->GetSessions();
    for (map<string, svConfSession *>::iterator i = session.begin();
        i != session.end(); i++) {
        if (i->second->GetType() == svSE_TUNNEL) tunnel++;
        else if (i->second->GetType() == svSE_POOL) pool++;
        else if (i->second->GetType() == svSE_VPN) vpn++;
        if (i->second->GetType() != svSE_APP) continue;
        app++;
        svConfSessionApp *conf_app;
        conf_app = (svConfSessionApp *)i->second;
        int fdr, fdw;
        conf_app->GetDescriptors(fdr, fdw);
        fprintf(fh, "\t<application name=\"%s\" ",
            i->first.c_str());
        fprintf(fh, "fd-read=\"%d\" fd-write=\"%d\">\n",
            fdr, fdw);
        fprintf(fh, "\t\t<path>%s</path>\n",
            conf_app->GetPath().c_str());
        vector<string>::iterator ai;
        vector<string> args = conf_app->GetArgs();
        for (ai = args.begin(); ai != args.end(); ai++) {
            fprintf(fh, "\t\t<param>%s</param>\n",
                (*ai).c_str());
        }
        fprintf(fh, "\t</application>\n");
    }
    if (tunnel && app > 0) fprintf(fh, "\n");
    if (tunnel > 0) fprintf(fh, "\t<tunnel>\n");
    for (map<string, svConfSession *>::iterator i = session.begin();
        i != session.end(); i++) {
        if (i->second->GetType() != svSE_TUNNEL) continue;
        svConfSessionTunnel *conf_tunnel;
        conf_tunnel = (svConfSessionTunnel *)i->second;

        svConfSocket skt_accept(conf_tunnel->GetConfSocketListen());
        svConfSocket skt_connect(conf_tunnel->GetConfSocketConnect());
        if (skt_accept.GetType() == svST_INET &&
            skt_accept.GetMode() == svSM_LISTEN) {
            fprintf(fh, "\t\t<inet-accept ");
            fprintf(fh, "name=\"%s\"\n\t\t\t", i->first.c_str());
            fprintf(fh, "ifn=\"%s\" port=\"%d\" ",
                skt_accept.GetInterface().c_str(), skt_accept.GetPort());
        }
        else if (skt_accept.GetType() == svST_PIPE &&
            skt_accept.GetMode() == svSM_LISTEN) {
            fprintf(fh, "\t\t<pipe-accept ");
            fprintf(fh, "name=\"%s\"\n\t\t\t", i->first.c_str());
            fprintf(fh, "path=\"%s\" ", skt_accept.GetPath().c_str());
        }
        else if (skt_connect.GetType() == svST_INET &&
            skt_connect.GetMode() == svSM_CONNECT) {
            fprintf(fh, "\t\t<inet-connect ");
            fprintf(fh, "name=\"%s\" flags=\"0x%x\"\n\t\t\t",
                i->first.c_str(), conf_tunnel->GetConnectFlags());
        }
        else if (skt_connect.GetType() == svST_PIPE &&
            skt_connect.GetMode() == svSM_CONNECT) {
            fprintf(fh, "\t\t<pipe-connect ");
            fprintf(fh, "name=\"%s\" flags=\"0x%x\"\n\t\t\t",
                i->first.c_str(), conf_tunnel->GetConnectFlags());
        }
        fprintf(fh, "dst-host=\"%s\" dst-port=\"%d\"/>\n",
            skt_connect.GetHost().c_str(), skt_connect.GetPort());
    }
    if (tunnel > 0) fprintf(fh, "\t</tunnel>\n");
    if (tunnel && (vpn || pool)) fprintf(fh, "\n");

    for (map<string, svConfSession *>::iterator i = session.begin();
        i != session.end(); i++) {
        if (i->second->GetType() != svSE_VPN) continue;
        svConfSessionVpn *conf_vpn;
        conf_vpn = (svConfSessionVpn *)i->second;
        svConfSocketVpn skt_vpn(conf_vpn->GetConfSocketVpn());
        svConfSocket skt_connect(conf_vpn->GetConfSocketConnect());
        if (skt_connect.GetMode() != svSM_NULL)
            fprintf(fh, "\t<vpn-connect ");
        else
            fprintf(fh, "\t<vpn-listen ");
        fprintf(fh, "name=\"%s\"", i->first.c_str());
        if (skt_connect.GetMode() != svSM_NULL)
            fprintf(fh, " retry=\"%d\"", conf_vpn->GetRetryInterval());
        fprintf(fh, "\n\t\tifn=\"%s\"",
            skt_vpn.GetInterface().c_str());
        if (skt_connect.GetMode() == svSM_NULL)
            fprintf(fh, "/>\n");
        else {
            fprintf(fh, " dst-host=\"%s\" dst-port=\"%d\"/>\n",
                skt_connect.GetHost().c_str(), skt_connect.GetPort());
        }
    }
    if ((app || tunnel || vpn) && pool) fprintf(fh, "\n");

    for (map<string, svConfSession *>::iterator i = session.begin();
        i != session.end(); i++) {
        if (i->second->GetType() != svSE_POOL) continue;
        svConfSessionPool *conf_pool;
        conf_pool = (svConfSessionPool *)i->second;
        svConfSocket skt_connect(conf_pool->GetConfSocketConnect());
        fprintf(fh, "\t<pool name=\"%s\" retry=\"%d\"\n\t\t",
            i->first.c_str(), conf_pool->GetRetryInterval());
        fprintf(fh, "dst-host=\"%s\" dst-port=\"%d\"/>\n",
            skt_connect.GetHost().c_str(), skt_connect.GetPort());
    }

    if (!client) {
        map<svConfDatabaseType, svConfDatabase *> db;
        db = oi->second->GetDatabases();
        if ((app || tunnel || vpn || pool) && db.size())
            fprintf(fh, "\n");
        for (map<svConfDatabaseType, svConfDatabase *>::iterator i =
            db.begin(); i != db.end(); i++) {
            if (i->first != svDT_PGSQL &&
                i->first != svDT_MYSQL) continue;
            string type;
            switch (i->first) {
            case svDT_NULL:
            case svDT_BDB:
                break;
            case svDT_PGSQL:
                type = "pgsql";
                break;
            case svDT_MYSQL:
                type = "mysql";
                break;
            }
            fprintf(fh, "\t<database type=\"%s\" db=\"%s\"\n\t\tuser=\"%s\""
                " pass=\"%s\" host=\"%s\" port=\"%s\" timeout=\"%s\">\n",
                type.c_str(),
                i->second->GetDatabaseName().c_str(),
                i->second->GetUsername().c_str(),
                i->second->GetPassword().c_str(),
                i->second->GetHost().c_str(),
                i->second->GetPort().c_str(),
                i->second->GetTimeout().c_str());
            fprintf(fh, "\t\t<sql name=\"query-hostkey\">\n");
            fprintf(fh, "\t\t\t%s\n\t\t</sql>\n",
                i->second->GetSqlQueryHostKey().c_str());
            fprintf(fh, "\t</database>\n");
        }
    }

    fprintf(fh, "</organization>\n");
    if (++oi != org.end()) goto sv_conf_save_next_org;

sv_conf_save_exit:
    fprintf(fh, "\n</svconf>\n<!--\n\tEnd of configuration\n");
    fprintf(fh, "\tvi: syntax=xml ts=2\n-->\n");
    fclose(fh);
}

void svConf::SetUser(const string &user)
{
#if defined(__linux__) && !defined(__ANDROID__)
    struct passwd pwd;
    struct passwd *result;
    char *buffer;
    long buffer_size;
    int rc;

    buffer_size = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (buffer_size == -1) buffer_size = 16384;

    buffer = new char[buffer_size];
    rc = getpwnam_r(user.c_str(),
        &pwd, buffer, (size_t)buffer_size, &result);
    if (result == NULL) {
        delete [] buffer;
        if (rc == 0) {
            throw svExConfValueInvalid(
                "User not found: \"" + user + "\"");
        }
        throw svExConfValueInvalid(
            "getpwnam_r: " + string(strerror(rc)));
    }
    uid = pwd.pw_uid;
    delete [] buffer;
    this->user = user;
#endif
}

void svConf::SetGroup(const string &group)
{
#if defined(__linux__) && !defined(__ANDROID__)
    struct group grp;
    struct group *result;
    char *buffer;
    long buffer_size;
    int rc;

    buffer_size = sysconf(_SC_GETGR_R_SIZE_MAX);
    if (buffer_size == -1) buffer_size = 16384;

    buffer = new char[buffer_size];
    rc = getgrnam_r(group.c_str(),
        &grp, buffer, (size_t)buffer_size, &result);
    if (result == NULL) {
        delete [] buffer;
        if (rc == 0) {
            throw svExConfValueInvalid(
                "Group not found: \"" + group + "\"");
        }
        throw svExConfValueInvalid(
            "getgrnam_r: " + string(strerror(rc)));
    }
    gid = grp.gr_gid;
    delete [] buffer;
    this->group = group;
#endif
}

svConfPlugin *svConf::GetPlugin(const string &name)
{
    map<string, svConfPlugin *>::iterator i;
    i = plugin.find(name);
    if (i == plugin.end()) return NULL;
    return i->second;
}

svConfFrontDoor *svConf::GetFrontDoor(const string &name)
{
    map<string, svConfFrontDoor *>::iterator i;
    i = front_door.find(name);
    if (i == front_door.end()) return NULL;
    return i->second;
}

svConfOrganization *svConf::GetOrganization(const string &name)
{
    map<string, svConfOrganization *>::iterator i;
    i = org.find(name);
    if (i == org.end()) return NULL;
    return i->second;
}

void svConf::LoadDefaults(void)
{
    debug = false;
#ifdef __WIN32__
    uid = -1;
    gid = -1;
    log_facility = -1;
#else
    uid = getuid();
    gid = getgid();
    log_facility = LOG_DAEMON;
#endif
    filename = _SUVA_DEFAULT_CONF;
#ifdef __linux__
    pid_file = string(_SUVA_PIDDIR) + "/" + process_name + ".pid";
#endif
    key_ttl = 30;
    poll_ttl = 60;
    session_ttl = 60 * 10;
    socket_ttl = 30;
    aes_key_size = 256;

    for (vector<svConfSocket *>::iterator i = stl_port.begin();
        i != stl_port.end(); i++) delete (*i);
    stl_port.clear();

    for (map<string, svConfPlugin *>::iterator i = plugin.begin();
        i != plugin.end(); i++) delete i->second;
    plugin.clear();

    for (map<string, svConfFrontDoor *>::iterator i = front_door.begin();
        i != front_door.end(); i++) delete i->second;
    front_door.clear();

    for (map<string, svConfOrganization *>::iterator i = org.begin();
        i != org.end(); i++) delete i->second;
    org.clear();
}

void svConf::ParseOptions(void)
{
    ParseCommonOptions();
}

void svConf::ParseCommonOptions(void)
{
    int32_t rc;
    struct option suvad_options[] =
    {
        { "version", 0, 0, 'V' },
        { "config", 1, 0, 'c' },
        { "save-config", 1, 0, 'o' },
        { "pid-file", 1, 0, 'p' },
        { "log-file", 1, 0, 'f' },
        { "help", 0, 0, '?' },
        { "debug", 0, 0, 'd' },
#ifdef __WIN32__
        { "register", 0, 0, 'r' },
        { "unregister", 0, 0, 'u' },
#endif
        { NULL, 0, 0, 0 }
    };

    for (optind = 1;; ) {
        int32_t o = 0;
        if ((rc = getopt_long(argc, argv,
#ifndef __WIN32__
            "Vc:o:p:f:dh?", suvad_options, &o)) == -1) break;
#else
            "Vc:o:p:f:dh?ru", suvad_options, &o)) == -1) break;
#endif
        switch (rc) {
        case 'V':
            Usage(true);
        case 'c':
            filename = optarg;
            break;
        case 'o':
            filename_save = optarg;
            break;
        case 'p':
            pid_file = optarg;
            break;
        case 'f':
            log_file = optarg;
            break;
        case 'd':
            debug = true;
            svOutput::SetDebug();
            break;
#ifdef __WIN32__
        case 'r':
            service_register = true;
            break;
        case 'u':
            service_unregister = true;
            break;
#endif
        case '?':
        case 'h':
            Usage();
        }
    }
}

void svConf::CommonUsage(void)
{
    svLog("Copyright (C) 2001-2012 ClearFoundation [%s %s]",
        __DATE__, __TIME__);
    svLog("  -V, --version");
    svLog("    Display program version information.");
    svLog("  -c <file>, --config <file>");
    svLog("    Specify an alternate configuration file.");
    svLog("  -p <file>, --pid-file <file>");
    svLog("    Specify an alternate PID file.");
    svLog("  -f <file>, --log-file <file>");
    svLog("    Specify a log file.");
    svLog("  -d, --debug");
    svLog("    Enable debug mode.");
}

#define CPF_COMMENT             0x01
#define CPF_KEYWORD             0x02
#define CPF_VALUE               0x04

void svConf::ParseConfigurationFile(void)
{
    int fd;
    ssize_t rc;
    uint8_t byte, quote = 0;
    vector<string> block;
    string key, value;
    uint32_t row = 1, col = 1, flags = 0;

    if ((fd = open(filename.c_str(), O_RDONLY)) < 0)
        throw svExConfOpen(filename, strerror(errno));
    else {
        uint8_t magic[2];
        if (read(fd, magic, sizeof(magic)) != sizeof(magic))
            throw svExConfRead(filename, strerror(errno));
        if (magic[0] == '<' && magic[1] == '?') {
            close(fd);
            ParseXmlConfigurationFile();
            return;
        }
        lseek(fd, 0, SEEK_SET);
        svLog("Deprecated configuration file format: %s",
            filename.c_str());
    }

    for ( ; (rc = read(fd, &byte, sizeof(uint8_t))) > 0; col++) {
        if (byte == '#' && !(flags & CPF_COMMENT)) {
            if (flags & CPF_KEYWORD || flags & CPF_VALUE) {
                throw svExConfParse(filename,
                    "Inappropriate location for a comment",
                    row, col, byte);
            }

            flags |= CPF_COMMENT;
            continue;
        }
        else if (byte == '\n') {
            row++; col = 1;
            flags &= ~CPF_COMMENT;
            continue;
        }
        else if (flags & CPF_COMMENT) continue;
        else if (byte == quote) {
            quote = 0;
            continue;
        }
        else if ((byte == '"' || byte == '\'') && !quote) {
            quote = byte;
            continue;
        }
        else if ((byte == ' ' || byte == '\t') && !quote) continue;
        else if (byte == '=' && !quote) {
            if (!(flags & CPF_KEYWORD) || flags & CPF_VALUE) {
                throw svExConfParse(filename,
                    "Keyword not open or value still open",
                    row, col, byte);
            }

            flags |= CPF_VALUE; flags &= ~CPF_KEYWORD;
            continue;
        } else if (byte == ';' && !quote) {
            if (!(flags & CPF_VALUE) || flags & CPF_KEYWORD) {
                throw svExConfParse(filename,
                    "Value not open or value still open",
                    row, col, byte);
            }
            else if (!value.size()) {
                throw svExConfParse(filename,
                    "Keyword \"" + key + "\" requires a value",
                    row, col, byte);
            }

            if (debug) {
                ostringstream os;
                os << filename.c_str() << ": ";
                if (block.size())
                    os << block.back() << ": ";
                svDebug("%s%s = %s", os.str().c_str(),
                    key.c_str(), value.c_str());
            }

            try {
                ParseKeyValue(block, key, value);
            } catch (svExConfKeyUnknown &e) {
                throw svExConfParse(filename,
                    "Unknown keyword \"" + key + "\"",
                    row, col, byte);
            } catch (svExConfPluginNotFound &e) {
                throw svExConfParse(filename,
                    "Front door plugin \"" + string(e.what()) +
                        "\" not found",
                    row, col, byte);
            } catch (svExConfValueInvalid &e) {
                throw svExConfParse(filename,
                    e.what(), row, col, byte);
            } catch (svExConfValueDuplicate &e) {
                throw svExConfParse(filename,
                    e.what(), row, col, byte);
            }

            flags &= ~CPF_VALUE;
            key.clear();
            value.clear();
            continue;
        }
        else if (byte == '{') {
            if (flags & CPF_VALUE || quote) {
                throw svExConfParse(filename,
                    "Inappropriate block open; value still open",
                    row, col, byte);
            }

            try {
                ParseBlock(block, key);
            } catch (svExConfBlockParse &e) {
                throw svExConfParse(filename, e.what(),
                    row, col, byte);
            } catch (svExConfBlockUnknown &e) {
                throw svExConfParse(filename,
                    "Unknown block keyword \"" + key + "\"",
                    row, col, byte);
            }

            flags &= ~CPF_KEYWORD;
            block.push_back(key);
            key.clear();
            continue;
        }
        else if (byte == '}') {
            if (flags & CPF_KEYWORD || flags & CPF_VALUE || quote) {
                throw svExConfParse(filename,
                    "Inappropriate block close; keyword or value still open",
                    row, col, byte);
            }

            if (block.size()) block.pop_back();
            else {
                throw svExConfParse(filename,
                    "Closing block mismatch", row, col, byte);
            }
            continue;
        }

        if (!(flags & CPF_KEYWORD) &&
            !(flags & CPF_VALUE)) flags |= CPF_KEYWORD;
        if (flags & CPF_KEYWORD) {
            key.push_back((char)byte);
            continue;
        }
        if (flags & CPF_VALUE) {
            value.push_back((char)byte);
            continue;
        }
        throw svExConfParse(filename,
            "Unexpected character", row, col, byte);
    }

    if (rc == -1)
        throw svExConfRead(filename, strerror(errno));
    if (flags & quote || block.size() != 0 ||
        flags & CPF_KEYWORD || flags & CPF_VALUE) {
        throw svExConfParse(filename,
            "Premature end-of-file", row, col, byte);
    }

    close(fd);
}

void svConf::ParseXmlConfigurationFile(void)
{
    svXmlParser xml(this);
    xml.Parse();
}

void svConf::ParseBlock(const vector<string> &block, const string &key)
{
    if (!strcmp("stl-port", key.c_str()) ||
        !strcmp("plug-in", key.c_str()) ||
        !strcmp("front-door", key.c_str())) {
        if (block.size()) {
            throw svExConfBlockParse(
                "Block \"" + key + "\" must be declared globally");
        }
        return;
    }
    else if (!strncmp("organization", key.c_str(), 12)) {
        string _key = key.substr(0, 12);
        string value = key.substr(12);
        if (block.size()) {
            throw svExConfBlockParse(
                "Block \"" + _key + "\" must be declared globally");
        }
        if (GetOrganization(value) != NULL) {
            throw svExConfBlockParse(
                "Duplicate organization: " + value);
        }

        org[value] = new svConfOrganization(value);
        return;
    }
    else if (!strcmp("key-server", key.c_str()) ||
        !strcmp("tunnel", key.c_str()) ||
        !strcmp("application", key.c_str()) ||
        !strcmp("pool", key.c_str()) ||
        !strcmp("database", key.c_str())) {
        if (!block.size() ||
            block.back().substr(0, 12) != "organization") {
            throw svExConfBlockParse(
                "Keyword \"" + key + "\" must be declared within " +
                "an organization block");
        }
        return;
    }

    throw svExConfBlockUnknown();
}

void svConf::ParseKeyValue(const vector<string> &block,
    const string &key, const string &value)
{
    // Global keywords
    if (!block.size()) {
        if (
            // Deprecated keywords...
            !strcmp("enable-db", key.c_str()) ||
            !strcmp("max-sockets", key.c_str()) ||
            !strcmp("max-children", key.c_str()) ||
            !strcmp("external-ipc", key.c_str()) ||
            !strcmp("child-ttl", key.c_str()) ||
            !strcmp("lzo-compression", key.c_str()) ||
            !strcmp("log-types", key.c_str()) ||
            !strcmp("log-levels", key.c_str())) {
            return;
        }
        else if (!strcmp("user", key.c_str())) {
            SetUser(value);
            return;
        }
        else if (!strcmp("group", key.c_str())) {
            SetGroup(value);
            return;
        }
        else if (!strcmp("debug", key.c_str())) {
            debug = ParseBooleanValue(value);
            return;
        }
        else if (!strcmp("key-ttl", key.c_str())) {
            key_ttl = atoi(value.c_str());
            return;
        }
        else if (!strcmp("poll-ttl", key.c_str())) {
            poll_ttl = atoi(value.c_str());
            return;
        }
        else if (!strcmp("session-ttl", key.c_str())) {
            session_ttl = atoi(value.c_str());
            return;
        }
        else if (!strcmp("socket-ttl", key.c_str())) {
            socket_ttl = atoi(value.c_str());
            return;
        }
        else if (!strcmp("key-size", key.c_str())) {
            aes_key_size = atoi(value.c_str());
            return;
        }
        else if (!strcmp("facility", key.c_str()) ||
            !strcmp("log-facility", key.c_str())) {
            log_facility = ParseLogFacility(value);
            return;
        }
        else if (!strcmp("log-file", key.c_str()) ||
            !strcmp("log-output", key.c_str())) {
            log_file = value;
            return;
        }
    }
    // STL port keywords
    else if (!strcmp("stl-port", block[0].c_str())) {
        if (!strcmp("inet", key.c_str())) {
            ParseSTLPort(svST_INET, value);
            return;
        }
    }
    // SFD plug-ins
    else if (!strcmp("plug-in", block[0].c_str())) {
        if (!strcmp("fd-library", key.c_str())) {
            ParsePlugin(value);
            return;
        }
    }
    // SFD access ports
    else if (!strcmp("front-door", block[0].c_str())) {
        if (!strcmp("inet-listen", key.c_str())) {
            ParseFrontDoor(svST_INET, value);
            return;
        }
        else if (!strcmp("pipe-listen", key.c_str())) {
            ParseFrontDoor(svST_PIPE, value);
            return;
        }
    }
    // Organization keywords
    else if (!strncmp("organization", block[0].c_str(), 12)) {
        svConfOrganization *org = GetOrganization(
            block[0].substr(12));
        if (!org) throw svExConfKeyUnknown();

        if (
            // Deprecated organization keywords
            !strcmp("enable-db", key.c_str()) ||
            !strcmp("pg-insert-pool-client", key.c_str()) ||
            !strcmp("pg-update-pool-client", key.c_str()) ||
            !strcmp("key-server", key.c_str()) ||
            !strcmp("key-cache-dir", key.c_str())) {
            return;
        }

        if (!strcmp("device-name", key.c_str())) {
            org->SetDevice(value);
            return;
        }
        else if (!strcmp("device-hostkey", key.c_str())) {
            org->SetHostKey(value);
            return;
        }
        else if (!strcmp("administrator", key.c_str())) {
            org->SetAdministrator(ParseBooleanValue(value));
            return;
        }
        else if (!strcmp("key-dir", key.c_str())) {
            org->SetKeyDir(value);
            return;
        }
        else if (!strcmp("key-cache-ttl", key.c_str())) {
            org->SetKeyCacheTTL(atoi(value.c_str()));
            return;
        }
        else if (!strcmp("key-poll-threshold", key.c_str())) {
            org->SetKeyPollThreshold(atoi(value.c_str()));
            return;
        }
        else if (!strcmp("max-pool-connections", key.c_str())) {
            org->SetMaxPoolConnections(atoi(value.c_str()));
            return;
        }
        else if (!strcmp("pg-host", key.c_str())) {
            org->SetLegacyPostgreSQLValue(svPK_HOST, value);
            return;
        }
        else if (!strcmp("pg-port", key.c_str())) {
            org->SetLegacyPostgreSQLValue(svPK_PORT, value);
            return;
        }
        else if (!strcmp("pg-dbname", key.c_str())) {
            org->SetLegacyPostgreSQLValue(svPK_DBNAME, value);
            return;
        }
        else if (!strcmp("pg-user", key.c_str())) {
            org->SetLegacyPostgreSQLValue(svPK_USER, value);
            return;
        }
        else if (!strcmp("pg-pass", key.c_str())) {
            org->SetLegacyPostgreSQLValue(svPK_PASS, value);
            return;
        }
        else if (!strcmp("pg-timeout", key.c_str())) {
            org->SetLegacyPostgreSQLValue(svPK_TIMEOUT, value);
            return;
        }
        else if (!strcmp("pg-query-hostkey", key.c_str()) ||
            !strcmp("pg-query", key.c_str())) {
            org->SetLegacyPostgreSQLValue(svPK_QUERY_HOSTKEY, value);
            return;
        }

        // Organization blocks
        if (block.size() == 2 && block[1] == "key-server") {
            if (!strcmp("host", key.c_str())) {
                ParseKeyServer(org, value);
                return;
            }
        }
        else if (block.size() == 2 && block[1] == "application") {
            if (!strcmp("execute", key.c_str())) {
                ParseApplicationSession(org, value);
                return;
            }
        }
        else if (block.size() == 2 && block[1] == "tunnel") {
            if (!strcmp("inet-listen", key.c_str())) {
                ParseTunnelSession(org,
                    svST_INET, svSM_LISTEN, value);
                return;
            }
            else if (!strcmp("inet-connect", key.c_str())) {
                ParseTunnelSession(org,
                    svST_INET, svSM_CONNECT, value);
                return;
            }
            else if (!strcmp("pipe-listen", key.c_str())) {
                ParseTunnelSession(org,
                    svST_PIPE, svSM_LISTEN, value);
                return;
            }
            else if (!strcmp("pipe-connect", key.c_str())) {
                ParseTunnelSession(org,
                    svST_PIPE, svSM_CONNECT, value);
                return;
            }
            else if (!strcmp("vpn-listen", key.c_str())) {
                ParseTunnelSession(org,
                    svST_VPN, svSM_LISTEN, value);
                return;
            }
            else if (!strcmp("vpn-connect", key.c_str())) {
                ParseTunnelSession(org,
                    svST_VPN, svSM_CONNECT, value);
                return;
            }
        }
        else if (block.size() == 2 && block[1] == "pool") {
            if (!strcmp("server", key.c_str())) {
                ParsePoolSession(org, value);
                return;
            }
        }
    }

    throw svExConfKeyUnknown();
}

bool svConf::ParseBooleanValue(const string &value)
{
    if (!strcmp("true", value.c_str()))
        return true;
    else if (strcmp("false", value.c_str())) {
        throw svExConfValueInvalid(
            "Invalid value, expected \"true\" or \"false\"");
    }
    return false;
}

int svConf::ParseLogFacility(const string &value)
{
    int facility = -1;
#ifndef __WIN32__
    if (value.size() == 1 && value[0] >= '0' && value[0] <= '7') {
        switch (value[0]) {
        case '0':
            facility = LOG_LOCAL0;
            break;
        case '1':
            facility = LOG_LOCAL1;
            break;
        case '2':
            facility = LOG_LOCAL2;
            break;
        case '3':
            facility = LOG_LOCAL3;
            break;
        case '4':
            facility = LOG_LOCAL4;
            break;
        case '5':
            facility = LOG_LOCAL5;
            break;
        case '6':
            facility = LOG_LOCAL6;
            break;
        case '7':
            facility = LOG_LOCAL7;
            break;
        }
        return facility;
    }

    if (value == "LOG_DAEMON")
        facility = LOG_DAEMON;
    else if (value == "LOG_LOCAL0")
        facility = LOG_LOCAL0;
    else if (value == "LOG_LOCAL1")
        facility = LOG_LOCAL1;
    else if (value == "LOG_LOCAL2")
        facility = LOG_LOCAL2;
    else if (value == "LOG_LOCAL3")
        facility = LOG_LOCAL3;
    else if (value == "LOG_LOCAL4")
        facility = LOG_LOCAL4;
    else if (value == "LOG_LOCAL5")
        facility = LOG_LOCAL5;
    else if (value == "LOG_LOCAL6")
        facility = LOG_LOCAL6;
    else if (value == "LOG_LOCAL7")
        facility = LOG_LOCAL7;
    else if (value == "LOG_USER")
        facility = LOG_USER;

    if (facility < 0)
        throw svExConfValueInvalid("Invalid syslog facility");
#endif
    return facility;
}

void svConf::ParseSTLPort(svConfSocketType type, const string &value)
{
    if (type == svST_INET) {
        string ifn;
        uint16_t port;
        size_t match = value.find_first_of(":");
        if (match == string::npos) {
            throw svExConfValueInvalid(
                "Invalid stl-port value; missing interface");
        }
        ifn = value.substr(0, match);
        if (match + 1 == value.size()) {
            throw svExConfValueInvalid(
                "Invalid stl-port value; missing port");
        }
        port = atoi(value.substr(match + 1).c_str());
        AddSTLInetPort(ifn, port);
    }
}

void svConf::AddSTLInetPort(const string &ifn, uint16_t port)
{
    svConfInetListen *skt = new svConfInetListen(ifn, port);
    for (vector<svConfSocket *>::iterator i = stl_port.begin();
        i != stl_port.end(); i++) {
        if (*skt != *(*i)) continue;
        delete skt;
        throw svExConfValueDuplicate(
            "Invalid stl-port value; duplicate \"inet\"");
    }

    stl_port.push_back(skt);
}

void svConf::ParsePlugin(const string &value)
{
    string name;
    string library;
    size_t offset, length;
    
    length = value.find_first_of(":");
    if (length == string::npos) {
        throw svExConfValueInvalid(
            "Invalid plug-in value; missing name");
    }
    name = value.substr(0, length);
    offset = length + 1;

    if (!value.substr(offset).size()) {
        throw svExConfValueInvalid(
            "Invalid plug-in value; missing library");
    }
    library = value.substr(offset);

    AddPlugin(name, library);
}

void svConf::AddPlugin(const string &name, const string &library)
{
    if (GetPlugin(name)) {
        throw svExConfValueDuplicate(
            "Invalid plug-in value; duplicate");
    }
    plugin[name] = new svConfPlugin(name, library);
}

void svConf::ParseFrontDoor(svConfSocketType type, const string &value)
{
    string name;
    string plugin;
    size_t offset, length;
    
    length = value.find_first_of(":");
    if (length == string::npos) {
        throw svExConfValueInvalid(
            "Invalid front-door value; missing name");
    }
    name = value.substr(0, length);
    offset = length + 1;

    if (GetFrontDoor(name)) {
        throw svExConfValueDuplicate(
            "Invalid front-door value; duplicate");
    }

    length = value.find_first_of(":", offset);
    if (length == string::npos ||
        !value.substr(offset, length - offset).size()) {
        throw svExConfValueInvalid(
            "Invalid font-door value; missing plug-in library");
    }
    plugin = value.substr(offset, length - offset);
    offset = length + 1;

    if (!GetPlugin(plugin))
        throw svExConfPluginNotFound(plugin);

    if (type == svST_INET) {
        string ifn;
        uint16_t port;

        length = value.find_first_of(":", offset);
        if (length == string::npos ||
            !value.substr(offset, length - offset).size()) {
            throw svExConfValueInvalid(
                "Invalid front-door value; missing interface");
        }
        ifn = value.substr(offset, length - offset);
        offset = length + 1;

        if (!value.substr(offset).size()) {
            throw svExConfValueInvalid(
                "Invalid front-door value; missing listen-port");
        }
        port = atoi(value.substr(offset).c_str());
        svConfFrontDoor *fd = new svConfFrontDoor(name, plugin, ifn, port);
        front_door[name] = fd;
    }
    else if (type == svST_PIPE) {
        string path;

        if (!value.substr(offset).size()) {
            throw svExConfValueInvalid(
                "Invalid font-door value; missing pipe-path");
        }
        path = value.substr(offset);
        svConfFrontDoor *fd = new svConfFrontDoor(name, plugin, path);
        front_door[name] = fd;
    }
}

void svConf::ParseKeyServer(svConfOrganization *org,
    const string &value)
{
    uint16_t port = 0;
    string host = value;
    size_t match = value.find_first_of(":");
    if (match != string::npos) {
        host = value.substr(0, match);
        if (match + 1 < value.size())
            port = atoi(value.substr(match + 1).c_str());
    }
    org->AddRSAKeyServer(host, (port != 0) ? port : 1975);
}

void svConf::ParseApplicationSession(svConfOrganization *org,
    const string &value)
{
    string name;
    int fdr = -1, fdw = -1;
    string path;
    string args;
    size_t offset, length;
    
    length = value.find_first_of(":");
    if (length == string::npos) {
        throw svExConfValueInvalid(
            "Invalid application value; missing name");
    }
    name = value.substr(0, length);
    offset = length + 1;

    length = value.find_first_of(":", offset);
    if (length == string::npos) {
        throw svExConfValueInvalid(
            "Invalid application value; missing fd-read");
    }
    if (value.substr(offset, length - offset).size())
        fdr = atoi(value.substr(offset, length - offset).c_str());
    offset = length + 1;

    length = value.find_first_of(":", offset);
    if (length == string::npos) {
        throw svExConfValueInvalid(
            "Invalid application value; missing fd-write");
    }
    if (value.substr(offset, length - offset).size())
        fdw = atoi(value.substr(offset, length - offset).c_str());
    offset = length + 1;

    length = value.find_first_of(":", offset);
    if (length != string::npos) {
        if (value.substr(offset, length - offset).size())
            path = value.substr(offset, length - offset);
        offset = length + 1;

        if (value.substr(offset).size())
            args = value.substr(offset);
    }
    else path = value.substr(offset, length - offset);

    if (!path.size()) {
        throw svExConfValueInvalid(
            "Invalid application value; missing application-path");
    }

    org->AddSessionApp(name, path, args, fdr, fdw);
}

void svConf::ParseTunnelSession(svConfOrganization *org,
    svConfSocketType type, svConfSocketMode mode,
    const string &value)
{
    string name;
    size_t offset, length;

    length = value.find_first_of(":");
    if (length == string::npos) {
        throw svExConfValueInvalid(
            "Invalid tunnel value; missing name");
    }
    name = value.substr(0, length);
    offset = length + 1;

    if (type == svST_INET && mode == svSM_LISTEN) {
        string ifn;
        uint16_t port;
        string dest_host;
        uint16_t dest_port;

        length = value.find_first_of(":", offset);
        if (length == string::npos ||
            !value.substr(offset, length - offset).size()) {
            throw svExConfValueInvalid(
                "Invalid tunnel value; missing interface");
        }
        ifn = value.substr(offset, length - offset);
        offset = length + 1;

        length = value.find_first_of(":", offset);
        if (length == string::npos ||
            !value.substr(offset, length - offset).size()) {
            throw svExConfValueInvalid(
                "Invalid tunnel value; missing listen-port");
        }
        port = atoi(value.substr(offset, length - offset).c_str());
        offset = length + 1;

        length = value.find_first_of(":", offset);
        if (length == string::npos ||
            !value.substr(offset, length - offset).size()) {
            throw svExConfValueInvalid(
                "Invalid tunnel value; missing dest-host");
        }
        dest_host = value.substr(offset, length - offset);
        offset = length + 1;

        if (!value.substr(offset).size()) {
            throw svExConfValueInvalid(
                "Invalid tunnel value; missing dest-port");
        }
        dest_port = atoi(value.substr(offset).c_str());

        svConfInetListen skt_listen(ifn, port);
        svConfInetConnect skt_connect(dest_host, dest_port);

        org->AddSessionTunnel(name, skt_listen, skt_connect);
    }
    else if (type == svST_INET && mode == svSM_CONNECT) {
        string dest_host;
        uint16_t dest_port;
        uint32_t flags;

        length = value.find_first_of(":", offset);
        if (length == string::npos ||
            !value.substr(offset, length - offset).size()) {
            throw svExConfValueInvalid(
                "Invalid tunnel value; missing flags");
        }
        flags = (uint32_t)strtol(
            value.substr(offset, length - offset).c_str(),
            (char **)NULL, 0);
        offset = length + 1;

        length = value.find_first_of(":", offset);
        if (length == string::npos ||
            !value.substr(offset, length - offset).size()) {
            throw svExConfValueInvalid(
                "Invalid tunnel value; missing dest-host");
        }
        dest_host = value.substr(offset, length - offset);
        offset = length + 1;

        if (!value.substr(offset).size()) {
            throw svExConfValueInvalid(
                "Invalid tunnel value; missing dest-port");
        }
        dest_port = atoi(value.substr(offset).c_str());

        svConfInetConnect skt_connect(dest_host, dest_port);

        org->AddSessionTunnel(name, skt_connect, flags);
    }
    else if (type == svST_PIPE && mode == svSM_LISTEN) {
        string path;
        string dest_host;
        uint16_t dest_port;

        length = value.find_first_of(":", offset);
        if (length == string::npos ||
            !value.substr(offset, length - offset).size()) {
            throw svExConfValueInvalid(
                "Invalid tunnel value; missing pipe-path");
        }
        path = value.substr(offset, length - offset);
        offset = length + 1;

        length = value.find_first_of(":", offset);
        if (length == string::npos ||
            !value.substr(offset, length - offset).size()) {
            throw svExConfValueInvalid(
                "Invalid tunnel value; missing dest-host");
        }
        dest_host = value.substr(offset, length - offset);
        offset = length + 1;

        if (!value.substr(offset).size()) {
            throw svExConfValueInvalid(
                "Invalid tunnel value; missing dest-port");
        }
        dest_port = atoi(value.substr(offset).c_str());

        svConfPipeListen skt_listen(path);
        svConfInetConnect skt_connect(dest_host, dest_port);

        org->AddSessionTunnel(name, skt_listen, skt_connect);
    }
    else if (type == svST_PIPE && mode == svSM_CONNECT) {
        string path;

        if (!value.substr(offset).size()) {
            throw svExConfValueInvalid(
                "Invalid tunnel value; missing pipe-path");
        }
        path = value.substr(offset);

        svConfPipeConnect skt_connect(path);

        org->AddSessionTunnel(name, skt_connect);
    }
    else if (type == svST_VPN && mode == svSM_LISTEN) {
        string ifn;
        string dest_host;
        uint16_t dest_port;

        length = value.find_first_of(":", offset);
        if (length == string::npos ||
            !value.substr(offset, length - offset).size()) {
            throw svExConfValueInvalid(
                "Invalid tunnel value; missing interface");
        }
        ifn = value.substr(offset, length - offset);
        offset = length + 1;

        length = value.find_first_of(":", offset);
        if (length == string::npos ||
            !value.substr(offset, length - offset).size()) {
            throw svExConfValueInvalid(
                "Invalid tunnel value; missing dest-host");
        }
        dest_host = value.substr(offset, length - offset);
        offset = length + 1;

        if (!value.substr(offset).size()) {
            throw svExConfValueInvalid(
                "Invalid tunnel value; missing dest-port");
        }
        dest_port = atoi(value.substr(offset).c_str());

        svConfSocketVpn skt_vpn(ifn);
        svConfInetConnect skt_connect(dest_host, dest_port);

        org->AddSessionVpn(name, skt_vpn, skt_connect);
    }
    else if (type == svST_VPN && mode == svSM_CONNECT) {
        string ifn;

        if (!value.substr(offset).size()) {
            throw svExConfValueInvalid(
                "Invalid tunnel value; missing interface");
        }
        ifn = value.substr(offset);

        svConfSocketVpn skt_vpn(ifn);

        org->AddSessionVpn(name, skt_vpn);
    }
}

void svConf::ParsePoolSession(svConfOrganization *org,
    const string &value)
{
    string name;
    string dest_host;
    uint16_t dest_port;
    size_t offset, length;

    length = value.find_first_of(":");
    if (length == string::npos) {
        throw svExConfValueInvalid(
            "Invalid pool server value; missing name");
    }
    name = value.substr(0, length);
    offset = length + 1;

    length = value.find_first_of(":", offset);
    if (length == string::npos ||
        !value.substr(offset, length - offset).size()) {
        throw svExConfValueInvalid(
            "Invalid pool server value; missing dest-host");
    }
    dest_host = value.substr(offset, length - offset);
    offset = length + 1;

    if (!value.substr(offset).size()) {
        throw svExConfValueInvalid(
            "Invalid pool server value; missing dest-port");
    }
    dest_port = atoi(value.substr(offset).c_str());

    svConfInetConnect skt(dest_host, dest_port);
    org->AddSessionPool(name, skt);
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
