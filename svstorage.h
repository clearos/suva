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

#ifndef _SVSTORAGE_H
#define _SVSTORAGE_H

using namespace std;

class svExStorageConnect : public runtime_error
{
public:
    explicit svExStorageConnect(const string &what)
        : runtime_error(what) { };
    virtual ~svExStorageConnect() throw() { };
};

class svExStorageDisconnect : public runtime_error
{
public:
    explicit svExStorageDisconnect(const string &what)
        : runtime_error(what) { };
    virtual ~svExStorageDisconnect() throw() { };
};

class svExStorageQuery : public runtime_error
{
public:
    explicit svExStorageQuery(const string &what)
        : runtime_error(what) { };
    virtual ~svExStorageQuery() throw() { };
};

class svExStorageEscapeString : public runtime_error
{
public:
    explicit svExStorageEscapeString(const string &what)
        : runtime_error(what) { };
    virtual ~svExStorageEscapeString() throw() { };
};

class svExStorageRecordNotFound : public runtime_error
{
public:
    explicit svExStorageRecordNotFound(const string &what)
        : runtime_error(what) { };
    virtual ~svExStorageRecordNotFound() throw() { };
};

class svExStorageInvalidConf : public runtime_error
{
public:
    explicit svExStorageInvalidConf()
        : runtime_error("No storage engines configured") { };
    virtual ~svExStorageInvalidConf() throw() { };
};

class svExStorageUnsupportedMethod : public runtime_error
{
public:
    explicit svExStorageUnsupportedMethod(const string &what)
        : runtime_error("Unsupported method: " + what) { };
    virtual ~svExStorageUnsupportedMethod() throw() { };
};

class svStorageEngine;
class svThreadStorage : public svThread
{
public:
    svThreadStorage(const string &node, const string &org,
        uint32_t hostkey_ttl);
    virtual ~svThreadStorage();

    virtual void Start(void);
    virtual void *Entry(void);
    void AddStorageEngine(const svConfDatabase &conf);

    uint32_t AddHostKeyClient(const string &dev, svEventClient *c);
    void BroadcastHostKeyResult(svEventHostKeyResult *result);

    bool GetHostKeyFromCache(const string &dev, svHostKey &key);
    void CacheHostKey(const string &dev, const svHostKey &key);

protected:
    string node;
    string org;
    uint32_t hostkey_ttl;
    vector<svStorageEngine *> engine;
    map<string, vector<svEventClient *> > client;
    map<string, svHostKey *> hostkey_cache;

    void GetHostKey(svEventHostKeyRequest *request);
    void UpdatePoolClient(svEventPoolClientUpdate *request);
    void PurgePoolClients(void);
};

enum svStorageEngineState
{
    svSES_ONLINE,
    svSES_OFFLINE,
};

class svStorageEngine : public svObject
{
public:
    svStorageEngine(const string &name);
    virtual ~svStorageEngine();

    static svStorageEngine *Create(const svConfDatabase &conf);

    svConfDatabaseType GetType(void) { return type; };
    virtual void GetHostKey(
        const string &dev, const string &org, svHostKey &key);
    virtual void CacheHostKey(
        const string &dev, const string &org, const svHostKey &key);

    virtual void InsertPoolClient(const string &node,
        const string &pool_name, const string &dev,
        const string &org, svPoolClientState state);
    virtual void UpdatePoolClient(const string &node,
        const string &pool_name, const string &dev,
        const string &org, svPoolClientState state);
    virtual void PurgePoolClients(
        const string &node, const string &org);

protected:
    svConfDatabaseType type;
    svStorageEngineState state;
    long page_size;
    char *escape_buffer;
    size_t escape_buffer_pages;

    string sql_query_hostkey;
    string sql_insert_pool_client;
    string sql_update_pool_client;
    string sql_purge_pool_clients;
    map<svPoolClientState, string> pool_client_state;

    virtual void Connect(void);
    virtual void Disconnect(void);

    virtual uint32_t PrepareSQL(string &sql,
        const char *token, const string &value);
    virtual void EscapeString(string &value) { };
};

#ifdef HAVE_LIBDB
#define _SUVA_DB_HKCACHE        "hkcache.dat"
#include <db.h>
struct hostkey_t
{
    time_t age;
    char hostkey[_SUVA_MAX_HOSTKEY_LEN];
};

class svStorageEngineBerkeley : public svStorageEngine
{
public:
    svStorageEngineBerkeley(const svConfDatabase &conf);
    virtual ~svStorageEngineBerkeley();

    virtual void GetHostKey(
        const string &dev, const string &org, svHostKey &key);
    virtual void CacheHostKey(
        const string &dev, const string &org, const svHostKey &key);

protected:
    string db_dir;
    DB_ENV *db_env;
    DB *db_hkcache;

    virtual void Connect(void);
    virtual void Disconnect(void);
};
#endif // HAVE_LIBDB

#ifdef HAVE_LIBPQ
#include <libpq-fe.h>
class svStorageEnginePostgreSQL : public svStorageEngine
{
public:
    svStorageEnginePostgreSQL(const svConfDatabase &conf);
    virtual ~svStorageEnginePostgreSQL();

    virtual void GetHostKey(
        const string &dev, const string &org, svHostKey &key);
    virtual void InsertPoolClient(const string &node,
        const string &pool_name, const string &dev,
        const string &org, svPoolClientState state);
    virtual void UpdatePoolClient(const string &node,
        const string &pool_name, const string &dev,
        const string &org, svPoolClientState state);
    virtual void PurgePoolClients(
        const string &node, const string &org);

protected:
    string pg_cinfo;
    PGconn *pg_conn;
    PGresult *pg_res;

    virtual void Connect(void);
    virtual void Disconnect(void);
    void ExecuteSQL(const string &sql);
    virtual void EscapeString(string &value);
};
#endif // HAVE_LIBPQ

#ifdef HAVE_LIBMYSQLCLIENT
#include <mysql/mysql.h>
#include <mysql/errmsg.h>
class svStorageEngineMySQL : public svStorageEngine
{
public:
    svStorageEngineMySQL(const svConfDatabase &conf);
    virtual ~svStorageEngineMySQL();

    virtual void GetHostKey(
        const string &dev, const string &org, svHostKey &key);
    virtual void InsertPoolClient(const string &node,
        const string &pool_name, const string &dev,
        const string &org, svPoolClientState state);
    virtual void UpdatePoolClient(const string &node,
        const string &pool_name, const string &dev,
        const string &org, svPoolClientState state);
    virtual void PurgePoolClients(
        const string &node, const string &org);

protected:
    string host;
    string user;
    string pass;
    string db;
    uint16_t port;
    uint16_t timeout;
    MYSQL *mysql_conn;
    MYSQL_RES *mysql_res;

    virtual void Connect(void);
    virtual void Disconnect(void);
    void ExecuteSQL(const string &sql);
    virtual void EscapeString(string &value);
};
#endif // HAVE_LIBMYSQLCLIENT

#endif // _SVSTORAGE_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
