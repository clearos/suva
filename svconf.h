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

#ifndef _SVCONF_H
#define _SVCONF_H

#ifndef _SUVA_PROTO_VER_MAJOR
#define _SUVA_PROTO_VER_MAJOR   2
#endif
#ifndef _SUVA_PROTO_VER_MINOR
#define _SUVA_PROTO_VER_MINOR   1
#endif
#ifndef _SUVA_VER_RELEASE
#define _SUVA_VER_RELEASE       "Triton"
#endif
#ifndef _SUVA_PIDDIR
#define _SUVA_PIDDIR            "/var/run/suvad"
#endif
#define _SUVA_MAX_NAME_LEN      255
#define _SUVA_MAX_HOSTKEY_LEN   32
#ifndef _SUVA_DEFAULT_DELAY
#define _SUVA_DEFAULT_DELAY     50
#endif
#ifndef _SUVA_DEFAULT_RETRY
#define _SUVA_DEFAULT_RETRY     5
#endif
#ifndef _SUVA_DEFAULT_CONF
#ifndef __WIN32__
#define _SUVA_DEFAULT_CONF      "/etc/suvad.conf"
#else
#define _SUVA_DEFAULT_CONF      "suvad.xml"
#endif
#endif
#define _SUVA_CONF_VER_MAJOR    1
#define _SUVA_CONF_VER_MINOR    0

using namespace std;

class svExConfUsageRequest : public runtime_error
{
public:
    explicit svExConfUsageRequest(void)
        : runtime_error("") { };
    virtual ~svExConfUsageRequest() throw() { };
};

class svExConfSaveRequest : public runtime_error
{
public:
    explicit svExConfSaveRequest(void)
        : runtime_error("") { };
    virtual ~svExConfSaveRequest() throw() { };
};

class svExConfOpen : public runtime_error
{
public:
    explicit svExConfOpen(const string &filename, const string &what)
        : runtime_error(filename + ": " + what) { };
    virtual ~svExConfOpen() throw() { };
};

class svExConfRead : public runtime_error
{
public:
    explicit svExConfRead(const string &filename, const string &what)
        : runtime_error(filename + ": " + what) { };
    virtual ~svExConfRead() throw() { };
};

class svExConfWrite : public runtime_error
{
public:
    explicit svExConfWrite(const string &filename, const string &what)
        : runtime_error(filename + ": " + what) { };
    virtual ~svExConfWrite() throw() { };
};

class svExConfParse : public runtime_error
{
public:
    explicit svExConfParse(const string &filename,
        const string &what, uint32_t row, uint32_t col, uint8_t byte)
        : runtime_error(filename + ": " + what),
        row(row), col(col), byte(byte) { };
    virtual ~svExConfParse() throw() { };

    uint32_t row;
    uint32_t col;
    uint8_t byte;
};

class svExConfBlockUnknown : public runtime_error
{
public:
    explicit svExConfBlockUnknown()
        : runtime_error("") { };
    virtual ~svExConfBlockUnknown() throw() { };
};

class svExConfBlockParse : public runtime_error
{
public:
    explicit svExConfBlockParse(const string &what)
        : runtime_error(what) { };
    virtual ~svExConfBlockParse() throw() { };
};

class svExConfKeyUnknown : public runtime_error
{
public:
    explicit svExConfKeyUnknown()
        : runtime_error("") { };
    virtual ~svExConfKeyUnknown() throw() { };
};

class svExConfKeyNotFound : public runtime_error
{
public:
    explicit svExConfKeyNotFound(const string &key)
        : runtime_error(key) { };
    virtual ~svExConfKeyNotFound() throw() { };
};

class svExConfPluginNotFound : public runtime_error
{
public:
    explicit svExConfPluginNotFound(const string &what)
        : runtime_error(what) { };
    virtual ~svExConfPluginNotFound() throw() { };
};

class svExConfValueInvalid : public runtime_error
{
public:
    explicit svExConfValueInvalid(const string &what)
        : runtime_error(what) { };
    virtual ~svExConfValueInvalid() throw() { };
};

class svExConfValueDuplicate : public runtime_error
{
public:
    explicit svExConfValueDuplicate(const string &what)
        : runtime_error(what) { };
    virtual ~svExConfValueDuplicate() throw() { };
};

class svExConfSqlVarNotFound : public runtime_error
{
public:
    explicit svExConfSqlVarNotFound(const string &what)
        : runtime_error(what) { };
    virtual ~svExConfSqlVarNotFound() throw() { };
};

enum svConfSocketType
{
    svST_NULL,
    svST_INET,
    svST_PIPE,
    svST_VPN
};

enum svConfSocketMode
{
    svSM_NULL,
    svSM_LISTEN,
    svSM_CONNECT
};

enum svConfVpnType
{
    svVT_NULL,
    svVT_TAP,
    svVT_TUN,
};

class svConfSocket : public svObject
{
public:
    svConfSocket();
    virtual ~svConfSocket() { };

    svConfSocket(svConfSocketType type, svConfSocketMode mode,
        const string &ifn, const string &path,
        const string &host, uint16_t port);

    svConfSocketType GetType(void) { return type; };
    svConfSocketMode GetMode(void) { return mode; };
    const string &GetInterface(void) const { return ifn; };
    const string &GetPath(void) const { return path; };
    const string &GetHost(void) const { return host; };
    uint16_t GetPort(void) { return port; };
    const string &GetAddress(void) const { return addr; };
    const string &GetNetmask(void) const { return netmask; };
    const string &GetMacAddr(void) const { return mac; };
    svConfVpnType GetVpnType(void) const { return vpn_type; };
    bool IsPersistent(void) const { return persist; };

    bool operator==(svConfSocket &skt)
    {
        if (skt.GetType() == type &&
            skt.GetMode() == mode &&
            skt.GetInterface() == ifn &&
            skt.GetPath() == path &&
            skt.GetHost() == host &&
            skt.GetPort() == port &&
            skt.GetAddress() == addr &&
            skt.GetNetmask() == netmask &&
            skt.GetMacAddr() == mac) return true;
        return false;
    };

    bool operator!=(svConfSocket &skt)
    {
        if (skt.GetType() != type ||
            skt.GetMode() != mode ||
            skt.GetInterface() != ifn ||
            skt.GetPath() != path ||
            skt.GetHost() != host ||
            skt.GetPort() != port ||
            skt.GetAddress() == addr ||
            skt.GetNetmask() == netmask ||
            skt.GetMacAddr() == mac) return true;
        return false;
    };

protected:
    svConfSocketType type;
    svConfSocketMode mode;
    string ifn;
    string path;
    string host;
    uint16_t port;
    string addr;
    string netmask;
    string mac;
    svConfVpnType vpn_type;
    bool persist;
};

class svConfInetSocket : public svConfSocket
{
public:
    svConfInetSocket(svConfSocketMode mode,
        const string &ifn, const string &host, uint16_t port);
};

class svConfPipeSocket : public svConfSocket
{
public:
    svConfPipeSocket(svConfSocketMode mode, const string &path);
};

class svConfSocketVpn : public svConfSocket
{
public:
    svConfSocketVpn(const string &ifn);

    void SetAddress(const string &addr) { this->addr = addr; };
    void SetNetmask(const string &netmask) { this->netmask = netmask; };
    void SetMacAddr(const string &mac) { this->mac = mac; };
    void SetVpnType(svConfVpnType vt) { vpn_type = vt; };
    void SetPersistent(bool enable = true) { this->persist = true; };
};

class svConfInetListen : public svConfInetSocket
{
public:
    svConfInetListen(const string &ifn, uint16_t port);
};

class svConfInetConnect : public svConfInetSocket
{
public:
    svConfInetConnect(const string &host, uint16_t port);
};

class svConfPipeListen : public svConfPipeSocket
{
public:
    svConfPipeListen(const string &path);
};

class svConfPipeConnect : public svConfPipeSocket
{
public:
    svConfPipeConnect(const string &path);
};

enum svConfRSAKeyType
{
    svKT_PUBLIC = 1,
    svKT_PRIVATE
};

class svConfRSAKey : public svObject
{
public:
    svConfRSAKey(const string &name, svConfRSAKeyType type, uint32_t bits);

    svConfRSAKeyType GetType(void) { return type; };
    uint32_t GetBits(void) { return bits; };
    time_t GetMtime(void) { return mtime; };
    void UpdateMtime(time_t mtime) { this->mtime = mtime; };

protected:
    svConfRSAKeyType type;
    uint32_t bits;
    time_t mtime;
};

enum svConfSessionType
{
    svSE_NULL,
    svSE_APP,
    svSE_TUNNEL,
    svSE_VPN,
    svSE_SFD,
    svSE_POOL,
};

class svConfSession : public svObject
{
public:
    svConfSession(const string &name,
        svConfSessionType type, bool exclusive = false);
    virtual ~svConfSession() { };

    svConfSessionType GetType(void) const { return type; };
    bool IsExclusive(void) const { return exclusive; };

protected:
    svConfSessionType type;
    bool exclusive;
};

#define TF_SEND_SESSION_INFO    0x01

class svConfSessionTunnel : public svConfSession
{
public:
    svConfSessionTunnel(const string &name,
        const svConfSocket &skt_connect, uint32_t flags = 0);
    svConfSessionTunnel(const string &name,
        const svConfSocket &skt_listen, const svConfSocket &skt_connect);

    const svConfSocket &GetConfSocketListen(void) const { return skt_listen; };
    const svConfSocket &GetConfSocketConnect(void) const { return skt_connect; };
    uint32_t GetConnectFlags(void) const { return flags; };

protected:
    svConfSocket skt_listen;
    svConfSocket skt_connect;
    uint32_t flags;
};

class svConfSessionApp : public svConfSession
{
public:
    svConfSessionApp(const string &name, int fdr, int fdw);
    svConfSessionApp(const string &name, const string &path,
        const string &args, int fdr, int fdw);

    const string &GetPath(void) const { return path; };
    void SetPath(const string &path) { this->path = path; };
    const vector<string> &GetArgs(void) const { return args; };
    void AddArg(const string &arg) { args.push_back(arg); };
    void GetDescriptors(int &fdr, int &fdw) const { fdr = this->fdr; fdw = this->fdw; };

protected:
    string path;
    vector<string> args;
    int fdr;
    int fdw;
};

class svConfSessionVpn : public svConfSession
{
public:
    svConfSessionVpn(const string &name,
        const svConfSocketVpn &skt_vpn);
    svConfSessionVpn(const string &name,
        const svConfSocketVpn &skt_vpn, const svConfSocket &skt_connect);

    uint32_t GetRetryInterval(void) const { return retry; };
    void SetRetryInterval(uint32_t retry) { this->retry = retry; };
    const svConfSocketVpn &GetConfSocketVpn(void) const { return skt_vpn; };
    svConfSocketVpn *GetConfSocketVpnPtr(void) { return &skt_vpn; };
    const svConfSocket &GetConfSocketConnect(void) const { return skt_connect; };

protected:
    svConfSocketVpn skt_vpn;
    svConfSocket skt_connect;
    uint32_t retry;
};

class svConfSessionPool : public svConfSession
{
public:
    svConfSessionPool(const string &name,
        const svConfSocket &skt_connect);

    uint32_t GetRetryInterval(void) const { return retry; };
    void SetRetryInterval(uint32_t retry) { this->retry = retry; };
    const svConfSocket &GetConfSocketConnect(void) const { return skt_connect; };

protected:
    svConfSocket skt_connect;
    uint32_t retry;
};

enum svConfDatabaseType
{
    svDT_BDB = 1,
    svDT_PGSQL,
    svDT_MYSQL
};

class svConfDatabase : public svObject
{
public:
    svConfDatabase(const string &name, svConfDatabaseType type);
    virtual ~svConfDatabase() { };

    svConfDatabaseType GetType(void) const { return type; };
    const string &GetHost(void) const { return host; };
    const string &GetPort(void) const { return port; };
    const string &GetUsername(void) const { return user; };
    const string &GetPassword(void) const { return pass; }; 
    const string &GetDatabaseName(void) const { return dbname; };
    const string &GetDataDir(void) const { return data_dir; };
    const string &GetTimeout(void) const { return timeout; };
    const string &GetSqlQueryHostKey(void) const { return sql_query_hostkey; };
    const string &GetSqlUpdatePoolClient(void) const { return sql_update_pool_client; };
    const string &GetSqlInsertPoolClient(void) const { return sql_insert_pool_client; };
    const string &GetSqlPurgePoolClients(void) const { return sql_purge_pool_clients; };
    const string &GetSqlVariable(const string &key) const;

    void SetHost(const string &host) { this->host = host; };
    void SetPort(const string &port) { this->port = port; };
    void SetUsername(const string &user) { this->user = user; };
    void SetPassword(const string &pass) { this->pass = pass; };
    void SetDatabaseName(const string &dbname) { this->dbname = dbname; };
    void SetDataDir(const string &dir) { data_dir = dir; };
    void SetTimeout(const string &timeout) { this->timeout = timeout; };
    void SetSqlQueryHostKey(const string &sql) { sql_query_hostkey = sql; };
    void SetSqlUpdatePoolClient(const string &sql) { sql_update_pool_client = sql; };
    void SetSqlInsertPoolClient(const string &sql) { sql_insert_pool_client = sql; };
    void SetSqlPurgePoolClients(const string &sql) { sql_purge_pool_clients = sql; };
    void SetSqlVariable(const string &key,
        const string &value) { sql_var[key] = value; };

protected:
    svConfDatabaseType type;
    string host;
    string port;
    string user;
    string pass;
    string dbname;
    string timeout;
    string data_dir;
    string sql_query_hostkey;
    string sql_update_pool_client;
    string sql_insert_pool_client;
    string sql_purge_pool_clients;
    map<string, string> sql_var;
};

class svConfDatabaseBerkeley : public svConfDatabase
{
public:
    svConfDatabaseBerkeley(const string &data_dir);
};

class svConfDatabasePostgreSQL : public svConfDatabase
{
public:
    svConfDatabasePostgreSQL()
        : svConfDatabase("svConfDatabasePostgreSQLLegacy",
        svDT_PGSQL) { };
    svConfDatabasePostgreSQL(const string &host, const string &port,
        const string &user, const string &pass, const string &dbname,
        const string &timeout);
};

class svConfDatabaseMySQL : public svConfDatabase
{
public:
    svConfDatabaseMySQL(const string &host, const string &port,
        const string &user, const string &pass, const string &dbname,
        const string &timeout);
};

class svConfPlugin : public svObject
{
public:
    svConfPlugin(const string &name, const string &library);

    const string &GetLibrary(void) const { return library; };

protected:
    string library;
};

class svConfFrontDoor : public svObject
{
public:
    svConfFrontDoor(const string &name, const string &plugin,
        const string &ifn, uint16_t port);
    svConfFrontDoor(const string &name, const string &plugin,
        const string &path);

    const string &GetPlugin(void) const { return plugin; };
    const svConfSocket &GetConfSocket(void) const { return skt; };

protected:
    string plugin;
    svConfSocket skt;
};

enum svConfLegacyPostgreSQLKey
{
    svPK_HOST,
    svPK_PORT,
    svPK_DBNAME,
    svPK_USER,
    svPK_PASS,
    svPK_TIMEOUT,
    svPK_QUERY_HOSTKEY,
};

class svConfOrganization : public svObject
{
public:
    svConfOrganization(const string &name);
    ~svConfOrganization();

    const string &GetDevice(void) const { return device; };
    const string &GetHostKey(void) const { return hostkey; };
    const string &GetKeyDir(void) const { return key_dir; };
    bool GetAdministrator(void) { return admin; };
    uint32_t GetKeyCacheTTL(void) { return rsa_key_cache_ttl; };
    uint32_t GetKeyPollThreshold(void) { return rsa_key_threshold; };
    uint32_t GetMaxPoolConnections(void) { return max_pool_connection; };
    const vector<svConfRSAKey *> &GetRSAKeyRing(void) const { return rsa_key_ring; };
    const vector<svConfSocket *> &GetRSAKeyServers(void) const { return rsa_key_server; };
    svConfSession *GetSession(const string &name);
    const map<string, svConfSession *> &GetSessions(void) const { return session; };
    const map<svConfDatabaseType, svConfDatabase *> &GetDatabases(void) const { return database; };
    svConfDatabase *GetDatabase(svConfDatabaseType type);

    void SetDevice(const string &device) { this->device = device; };
    void SetHostKey(const string &hostkey) { this->hostkey = hostkey; };
    void SetKeyDir(const string &key_dir) { this->key_dir = key_dir; };
    void SetAdministrator(bool enable) { admin = enable; };
    void SetKeyCacheTTL(uint32_t key_cache_ttl) { rsa_key_cache_ttl = key_cache_ttl; };
    void SetKeyPollThreshold(uint32_t key_threshold) { rsa_key_threshold = key_threshold; };
    void SetMaxPoolConnections(uint32_t max_connection) { max_pool_connection = max_connection; };

    void AddRSAKeyServer(const string &host, uint16_t port)
    {
        svConfInetConnect *server = new svConfInetConnect(host, port);
        rsa_key_server.push_back(server);
    };
    void AddSessionApp(const string &name, const string &path,
        const string &args, int fdr, int fdw);
    void AddSessionTunnel(const string &name,
        const svConfSocket &skt_connect, uint32_t flags = 0);
    void AddSessionTunnel(const string &name,
        const svConfSocket &skt_listen, const svConfSocket &skt_connect);
    svConfSessionVpn *AddSessionVpn(const string &name,
        const svConfSocketVpn &skt_vpn);
    svConfSessionVpn *AddSessionVpn(const string &name,
        const svConfSocketVpn &skt_vpn, const svConfSocket &skt_connect);
    svConfSessionPool *AddSessionPool(const string &name,
        const svConfSocket &skt_connect);
    void AddDatabase(svConfDatabaseType type, const svConfDatabase &db);
    void SetLegacyPostgreSQLValue(svConfLegacyPostgreSQLKey key, const string &value);
    void AddLegacyPostgreSQL(void)
    {
        if (pg_legacy) {
            AddDatabase(svDT_PGSQL, *pg_legacy);
            delete pg_legacy;
            pg_legacy = NULL;
        }
    };

protected:
    friend class svXmlParser;

    string device;
    string hostkey;
    string key_dir;
    bool admin;
    uint32_t rsa_key_cache_ttl;
    uint32_t rsa_key_threshold;
    vector<svConfRSAKey *> rsa_key_ring;
    vector<svConfSocket *> rsa_key_server;
    uint32_t max_pool_connection;
    map<string, svConfSession *> session;
    map<string, svConfSocket *> pool_server;
    map<svConfDatabaseType, svConfDatabase *> database;
    svConfDatabasePostgreSQL *pg_legacy;

    virtual void LoadDefaults(void);
};

class svXmlTag : public svObject
{
public:
    svXmlTag(const char *name, const char **attr);

    bool ParamExists(const string &key);
    string GetParamValue(const string &key);
    string GetText(void) { return text; };
    void SetText(const string &text) { this->text = text; };
    svObject *GetObject(void) { return object; };
    void SetObject(svObject *object) { this->object = object; };

    bool operator==(const char *tag);
    bool operator!=(const char *tag);

protected:
    map<string, string> param;
    string text;
    svObject *object;
};

class svConf;
class svConfOrganization;
class svXmlParser : public svObject
{
public:
    svXmlParser(svConf *conf);
    ~svXmlParser();
    void Parse(void);
    void ParseError(const string &what);
    void ParseElementOpen(svXmlTag *tag);
    void ParseElementClose(svXmlTag *tag);

    svConf *conf;
    FILE *fh;
    long page_size;
    uint8_t *buffer;
    XML_Parser p;
    int version;
    vector<svXmlTag *> stack;
};

class svConf : public svObject
{
public:
    svConf(int argc, char *argv[]);
    virtual ~svConf();

    virtual void Load(void);
    virtual void Save(bool client = true);
    virtual void Usage(bool version = false) = 0;

    const string
        &GetProcessName(void) const { return process_name; };
    const string &GetPidFile(void) const { return pid_file; };
    void GetUidGid(uid_t &uid, gid_t &gid)
    {
        uid = this->uid; gid = this->gid;
    };
    void SetUser(const string &user);
    void SetGroup(const string &group);

    bool GetDebug(void) { return debug; };
    int GetLogFacility(void) { return log_facility; };
    const string &GetLogFile(void) const { return log_file; };
    uint32_t GetKeyTTL(void) { return key_ttl; };
    uint32_t GetPollTTL(void) { return poll_ttl; };
    int32_t GetSessionTTL(void) { return session_ttl; };
    uint32_t GetSocketTTL(void) { return socket_ttl; };
    uint32_t GetAESKeySize(void) { return aes_key_size; };
    const vector<svConfSocket *>
        &GetSTLPorts(void) const { return stl_port; };
    const map<string, svConfPlugin *>
        &GetPlugins(void) const { return plugin; };
    svConfPlugin *GetPlugin(const string &name);
    const map<string, svConfFrontDoor *>
        &GetFrontDoors(void) const { return front_door; };
    svConfFrontDoor *GetFrontDoor(const string &name);
    const map<string, svConfOrganization *>
        &GetOrganizations(void) const { return org; };
    svConfOrganization *GetOrganization(const string &name);

    pthread_mutex_t *GetMutex(void) { return &mutex; };
    void Lock(void) { pthread_mutex_lock(&mutex); };
    void Unlock(void) { pthread_mutex_unlock(&mutex); };

protected:
    friend class svXmlParser;

    int argc;
    char **argv;
    string process_name;
    string filename;
    string filename_save;
    string pid_file;
    uid_t uid;
    gid_t gid;
    string user;
    string group;
    bool debug;
    int32_t log_facility;
    string log_file;
    uint32_t key_ttl;
    uint32_t poll_ttl;
    int32_t session_ttl;
    uint32_t socket_ttl;
    uint32_t aes_key_size;
    vector<svConfSocket *> stl_port;
    map<string, svConfPlugin *> plugin;
    map<string, svConfFrontDoor *> front_door;
    map<string, svConfOrganization *> org;
    pthread_mutex_t mutex;
#ifdef __WIN32__
    bool service_register;
    bool service_unregister;
#endif

    void CommonUsage(void);

    virtual void LoadDefaults(void);

    virtual void ParseOptions(void);
    void ParseCommonOptions(void);
    void ParseConfigurationFile(void);
    void ParseXmlConfigurationFile(void);
    virtual void ParseBlock(const vector<string> &block,
        const string &key);
    virtual void ParseKeyValue(const vector<string> &block,
        const string &key, const string &value);
    bool ParseBooleanValue(const string &value);
    int ParseLogFacility(const string &value);
    void ParseSTLPort(svConfSocketType type, const string &value);
    void ParsePlugin(const string &value);
    void ParseFrontDoor(svConfSocketType type, const string &value);
    void ParseKeyServer(svConfOrganization *org,
        const string &value);
    void ParseApplicationSession(svConfOrganization *org,
        const string &value);
    void ParseTunnelSession(svConfOrganization *org,
        svConfSocketType type, svConfSocketMode mode,
        const string &value);
    void ParsePoolSession(svConfOrganization *org,
        const string &value);

    void AddSTLInetPort(const string &ifn, uint16_t port);
    void AddPlugin(const string &name, const string &library);
    void AddFrontDoor(const string &name, const string &plugin,
        const string &ifn, uint16_t port);
    void AddFrontDoor(const string &name, const string &plugin,
        const string &path);
};

#endif // _SVCONF_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
