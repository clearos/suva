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
#include <syslog.h>
#include <expat.h>
#include <netdb.h>

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
#include "svpool.h"
#include "svevent.h"
#include "svthread.h"
#include "svstorage.h"

svThreadStorage::svThreadStorage(const string &node,
	const string &org, uint32_t hostkey_ttl)
	: svThread("svThreadStorage"),
	node(node), org(org), hostkey_ttl(hostkey_ttl)
{
}

svThreadStorage::~svThreadStorage()
{
	Join();
	PurgePoolClients();
	for (vector<svStorageEngine *>::iterator i = engine.begin();
		i != engine.end(); i++) delete (*i);
	for (map<string, svHostKey *>::iterator i =
		hostkey_cache.begin(); i != hostkey_cache.end(); i++)
		delete i->second;
}

void svThreadStorage::Start(void)
{
	if (!engine.size())
		throw svExStorageInvalidConf();
	svThread::Start();
}

void *svThreadStorage::Entry(void)
{
	PurgePoolClients();

	for ( ;; ) {
		svEvent *event = PopWaitEvent();
		switch (event->GetId()) {
		case svEVT_QUIT:
			return NULL;
		case svEVT_SESSION_QUIT:
			delete event;
			return NULL;
		case svEVT_HOSTKEY_REQUEST:
			GetHostKey((svEventHostKeyRequest *)event);
			break;
		case svEVT_POOLCLIENT_UPDATE:
			UpdatePoolClient((svEventPoolClientUpdate *)event);
			break;
		default:
			break;
		}
		delete event;
	}
}

void svThreadStorage::AddStorageEngine(const svConfDatabase &conf)
{
	svStorageEngine *se = NULL;

	switch (conf.GetType()) {
#ifdef HAVE_LIBDB
	case svDT_BDB:
		se = new svStorageEngineBerkeley(conf);
		break;
#endif // HAVE_LIBDB

#ifdef HAVE_LIBPQ
	case svDT_PGSQL:
		se = new svStorageEnginePostgreSQL(conf);
		break;
#endif // HAVE_LIBPQ

#ifdef HAVE_LIBMYSQLCLIENT
	case svDT_MYSQL:
		se = new svStorageEngineMySQL(conf);
		break;
#endif // HAVE_LIBMYSQLCLIENT
	default:
		svError("%s: WARNING: Unsupported storage engine type: %d",
			name.c_str(), conf.GetType());
		break;
	}

	if (se) engine.push_back(se);
}

uint32_t svThreadStorage::AddHostKeyClient(const string &dev,
	svEventClient *c)
{
	client[dev].push_back(c);
	svDebug("%s: Hostkey clients awaiting device: %s: %d",
		name.c_str(), dev.c_str(), client[dev].size());
	return client[dev].size();
}

void svThreadStorage::BroadcastHostKeyResult(
	svEventHostKeyResult *result)
{
	map<string, vector<svEventClient *> >::iterator i;
	i = client.find(result->GetDevice());
	if (i == client.end()) {
		svDebug("%s: No hostkey clients awaiting device: %s",
			name.c_str(), result->GetDevice().c_str());
		return;
	}

	vector<svEventClient *>::iterator ci = i->second.begin();
	for ( ; ci != i->second.end(); ci++) {
		svEventServer::GetInstance()->Dispatch(
			new svEventHostKeyResult(GetDefaultDest(), (*ci),
				result->GetDevice(), result->GetOrganization(),
				result->GetKey()));
	}
	svDebug("%s: Hostkey client broadcast: %s: %d",
		name.c_str(), result->GetDevice().c_str(),
		client[result->GetDevice()].size());
	client.erase(i);

	svHostKey key(result->GetKey());
	if (key.GetKey().size() && !key.HasExpired(hostkey_ttl)) {
		map<string, svHostKey *>::iterator ki;
		ki = hostkey_cache.find(result->GetDevice());
		if (ki != hostkey_cache.end()) {
			ki->second->SetAge(key.GetAge());
			ki->second->SetKey(key.GetKey());
			return;
		}
		hostkey_cache[result->GetDevice()] = new svHostKey(key);
	}
}

bool svThreadStorage::GetHostKeyFromCache(
	const string &dev, svHostKey &key)
{
	map<string, svHostKey *>::iterator i;

	for (i = hostkey_cache.begin(); i != hostkey_cache.end(); ) {
		if (!i->second->HasExpired(hostkey_ttl)) {
			i++;
			continue;
		}
		delete i->second;
		hostkey_cache.erase(i);
		i = hostkey_cache.begin();
	}

	i = hostkey_cache.find(dev);
	if (i == hostkey_cache.end()) return false;

	key.SetAge(i->second->GetAge());
	key.SetKey(i->second->GetKey());

	return true;
}

void svThreadStorage::CacheHostKey(const string &dev,
	const svHostKey &key)
{
	map<string, svHostKey *>::iterator i;
	i = hostkey_cache.find(dev);
	if (i != hostkey_cache.end()) {
		i->second->SetAge(key.GetAge());
		i->second->SetKey(key.GetKey());
		return;
	}
	svHostKey *hostkey = new svHostKey(key);
	hostkey_cache[dev] = hostkey;
}

void svThreadStorage::GetHostKey(svEventHostKeyRequest *request)
{
	svHostKey key;

	for (vector<svStorageEngine *>::iterator i = engine.begin();
		i != engine.end(); i++) {
		if ((*i)->GetType() != svDT_BDB) continue;
		try {
			(*i)->GetHostKey(request->GetDevice(), org, key);
		} catch (svExStorageRecordNotFound &e) {
			svDebug("%s: %s", org.c_str(), e.what());
			continue;
		} catch (runtime_error &e) {
			svError("%s: %s", org.c_str(), e.what());
			continue;
		}

		if (!key.HasExpired(hostkey_ttl)) {
			svEventServer::GetInstance()->Dispatch(
				new svEventHostKeyResult(this, NULL,
					request->GetDevice(),
					request->GetOrganization(), key));
			svDebug("%s: Using cached hostkey for: %s",
				org.c_str(), request->GetDevice().c_str());
			return;
		}
	}

	for (vector<svStorageEngine *>::iterator i = engine.begin();
		i != engine.end(); i++) {
		if ((*i)->GetType() != svDT_PGSQL &&
			(*i)->GetType() != svDT_MYSQL) continue;
		try {
			(*i)->GetHostKey(request->GetDevice(), org, key);
#if 0
		} catch (svExStorageConnect &e) {
			svError("%s: svExStorageConnect", org.c_str());
			continue;
		} catch (svExStorageDisconnect &e) {
			svError("%s: svExStorageDisconnect", org.c_str());
			continue;
		} catch (svExStorageQuery &e) {
			svError("%s: svExStorageQuery", org.c_str());
			continue;
		} catch (svExStorageEscapeString &e) {
			svError("%s: svExStorageEscapeString", org.c_str());
			continue;
		} catch (svExStorageRecordNotFound &e) {
			svError("%s: svExStorageRecordNotFound", org.c_str());
			continue;
		} catch (svExStorageInvalidConf &e) {
			svError("%s: svExStorageInvalidConf", org.c_str());
			continue;
		} catch (svExStorageUnsupportedMethod &e) {
			svError("%s: svExStorageUsupportedMethod", org.c_str());
			continue;
		} catch (runtime_error &e) {
			//svError("%s: %s", org.c_str(), e.what());
			svError("%s: runtime_error", org.c_str());
			continue;
#endif
		} catch (svExStorageRecordNotFound &e) {
			svDebug("%s: %s", org.c_str(), e.what());
			continue;
		} catch (runtime_error &e) {
			svError("%s: %s", org.c_str(), e.what());
			continue;
		}

		break;
	}

	svEventServer::GetInstance()->Dispatch(
		new svEventHostKeyResult(this, NULL,
			request->GetDevice(), request->GetOrganization(), key));

	if (key.GetKey().size()) {
		if (key.HasExpired(hostkey_ttl)) {
			svDebug("%s: Using expired hostkey for: %s",
				org.c_str(), request->GetDevice().c_str());
			return;
		}

		for (vector<svStorageEngine *>::iterator i = engine.begin();
			i != engine.end(); i++) {
			if ((*i)->GetType() != svDT_BDB) continue;
			try {
				(*i)->CacheHostKey(request->GetDevice(), org, key);
			} catch (runtime_error &e) {
				svError("%s: %s", org.c_str(), e.what());
				continue;
			}
		}

		return;
	}

	svError("%s: Hostkey not found for: %s",
		org.c_str(), request->GetDevice().c_str());
}

void svThreadStorage::UpdatePoolClient(	
	svEventPoolClientUpdate *request)
{
	string state("unknown");
	switch (request->GetState()) {
	case svPCS_IDLE:
		state = "idle";
		break;
	case svPCS_INUSE:
		state = "in-use";
		break;
	case svPCS_OFFLINE:
		state = "offline";
		break;
	};
	
	svDebug("%s: Update pool client: %s %s: %s",
		name.c_str(), request->GetPoolName().c_str(),
		request->GetDevice().c_str(), state.c_str());

	for (vector<svStorageEngine *>::iterator i = engine.begin();
		i != engine.end(); i++) {
		if ((*i)->GetType() != svDT_PGSQL &&
			(*i)->GetType() != svDT_MYSQL) continue;
		try {
			(*i)->UpdatePoolClient(node, request->GetPoolName(),
				request->GetDevice(), org, request->GetState());
			continue;
		} catch (svExStorageRecordNotFound &e) {
		} catch (runtime_error &e) {
			svError("%s: %s", name.c_str(), e.what());
			continue;
		}

		try {
			(*i)->InsertPoolClient(node, request->GetPoolName(),
				request->GetDevice(), org, request->GetState());
		} catch (runtime_error &e) {
			svError("%s: %s", name.c_str(), e.what());
			continue;
		}
	}
}

void svThreadStorage::PurgePoolClients(void)
{
	for (vector<svStorageEngine *>::iterator i = engine.begin();
		i != engine.end(); i++) {
		if ((*i)->GetType() != svDT_PGSQL &&
			(*i)->GetType() != svDT_MYSQL) continue;
		try {
			(*i)->PurgePoolClients(node, org);
		} catch (runtime_error &e) {
			svError("%s: %s", name.c_str(), e.what());
		}
	}
}

svStorageEngine::svStorageEngine(const string &name)
	: svObject(name), state(svSES_OFFLINE),
	escape_buffer(NULL), escape_buffer_pages(0)
{
	page_size = sysconf(_SC_PAGESIZE);
	if (page_size == -1) page_size = 4096;
}

svStorageEngine::~svStorageEngine()
{
	if (escape_buffer) free(escape_buffer);
}

void svStorageEngine::GetHostKey(
	const string &dev, const string &org, svHostKey &key)
{
	throw svExStorageUnsupportedMethod("GetHostKey");
}

void svStorageEngine::CacheHostKey(
	const string &dev, const string &org, const svHostKey &key)
{
	throw svExStorageUnsupportedMethod("CacheHostKey");
}

void svStorageEngine::InsertPoolClient(const string &node,
	const string &pool_name, const string &dev, const string &org,
	svPoolClientState state)
{
	throw svExStorageUnsupportedMethod("InsertPoolClient");
}

void svStorageEngine::UpdatePoolClient(const string &node,
	const string &pool_name, const string &dev, const string &org,
	svPoolClientState state)
{
	throw svExStorageUnsupportedMethod("UpdatePoolClient");
}

void svStorageEngine::PurgePoolClients(
	const string &node, const string &org)
{
	throw svExStorageUnsupportedMethod("PurgePoolClients");
}

void svStorageEngine::Connect(void)
{
	state = svSES_ONLINE;
	svLog("%s: online", name.c_str());
}

void svStorageEngine::Disconnect(void)
{
	state = svSES_OFFLINE;
	svLog("%s: offline", name.c_str());
}

uint32_t svStorageEngine::PrepareSQL(
	string &sql, const char *token, const string &value)
{
	uint32_t matches = 0;
	size_t pos = sql.find(token);
	while (pos != string::npos) {
		matches++;
		sql.replace(pos, strlen(token), value);
		pos = sql.find(token, pos + strlen(token));
	}
	return matches;
}

#ifdef HAVE_LIBDB
#if DB_VERSION_MAJOR == 4 && DB_VERSION_MINOR >= 3
static void db_output(const DB_ENV *dbenv,
	const char *prefix, const char *message)
#else
static void db_output(const char *prefix, char *message)
#endif // DB_VERSION
{
	svLog("%s: %s", prefix, message);
}

static void db_panic(DB_ENV *db_env, int errval)
{
	svError("db: panic: %s", db_strerror(errval));
}

svStorageEngineBerkeley::svStorageEngineBerkeley(
	const svConfDatabase &conf)
	: svStorageEngine("BerkeleyDB"), db_env(NULL), db_hkcache(NULL)
{
	type = svDT_BDB;
	db_dir = conf.GetDataDir();
}

svStorageEngineBerkeley::~svStorageEngineBerkeley()
{
	Disconnect();
}

void svStorageEngineBerkeley::GetHostKey(
	const string &dev, const string &org, svHostKey &key)
{
	if (state != svSES_ONLINE) Connect();

	char device[_SUVA_MAX_NAME_LEN];
	memset(device, 0, _SUVA_MAX_NAME_LEN);
	memcpy(device, dev.c_str(),
		(dev.size() > _SUVA_MAX_NAME_LEN ?
			_SUVA_MAX_NAME_LEN : dev.size()));

	DBT db_key, db_value;
	memset(&db_key, 0, sizeof(DBT));
	memset(&db_value, 0, sizeof(DBT));

	struct hostkey_t hostkey;
	memset(&hostkey, 0, sizeof(struct hostkey_t));

	db_key.data = device;
	db_key.size = _SUVA_MAX_NAME_LEN;
	db_value.data = &hostkey;
	db_value.ulen = sizeof(struct hostkey_t);
	db_value.flags = DB_DBT_USERMEM;

	int rc;
	if ((rc = db_hkcache->get(db_hkcache,
		NULL, &db_key, &db_value, 0)) != 0) {
		if (rc == DB_NOTFOUND) {
			throw svExStorageRecordNotFound(
				name + ": Device not found: " + dev);
		}
		Disconnect();
		throw svExStorageQuery(
			string("DB->get: ") + db_strerror(rc));
	}

	if (db_value.size != sizeof(struct hostkey_t))
		throw svExStorageQuery("DB->get: record size mis-match");

	key.AssignKey(hostkey.hostkey);
	key.SetAge(hostkey.age);
}

void svStorageEngineBerkeley::CacheHostKey(
	const string &dev, const string &org, const svHostKey &key)
{
	if (state != svSES_ONLINE) Connect();

	struct hostkey_t hostkey;
	memset(&hostkey, 0, sizeof(struct hostkey_t));
	hostkey.age = key.GetAge();
	memcpy(hostkey.hostkey,
		key.GetKey().c_str(), _SUVA_MAX_HOSTKEY_LEN);

	DBT db_key, db_value;
	memset(&db_key, 0, sizeof(DBT));
	memset(&db_value, 0, sizeof(DBT));

	char device[_SUVA_MAX_NAME_LEN];
	memset(device, 0, _SUVA_MAX_NAME_LEN);
	memcpy(device, dev.c_str(),
		(dev.size() > _SUVA_MAX_NAME_LEN ?
			_SUVA_MAX_NAME_LEN : dev.size()));

	db_key.data = device;
	db_key.size = _SUVA_MAX_NAME_LEN;
	db_value.data = &hostkey;
	db_value.ulen = db_value.size = sizeof(struct hostkey_t);
	db_value.flags = DB_DBT_USERMEM;

	int rc;
	rc = db_hkcache->put(db_hkcache, NULL, &db_key, &db_value, 0);

	if (rc != 0) {
		throw svExStorageQuery(string("DB->put: ") +
			db_strerror(rc));
	}
	else rc = db_hkcache->sync(db_hkcache, 0);

	if (rc != 0) {
		throw svExStorageQuery(string("DB->sync: ") +
			db_strerror(rc));
	}
}

void svStorageEngineBerkeley::Connect(void)
{
	if (state == svSES_ONLINE) return;

	int rc;
	if ((rc = db_env_create(&db_env, 0)) != 0) {
		throw svExStorageConnect(
			string("db_env_create: ") + db_strerror(rc));
	}

	db_env->set_errpfx(db_env, "bdb");
	db_env->set_errcall(db_env, db_output);
	db_env->set_paniccall(db_env, db_panic);

	if ((rc = db_env->open(db_env, db_dir.c_str(),
		DB_CREATE | DB_INIT_LOCK | DB_INIT_MPOOL | DB_PRIVATE, 0)) != 0) {
		db_env = NULL;
		throw svExStorageConnect(
			string("DB_ENV->open: ") + db_strerror(rc));
	}

	db_env->set_verbose(db_env, DB_VERB_DEADLOCK, 1);
	db_env->set_verbose(db_env, DB_VERB_WAITSFOR, 1);

	if ((rc = db_create(&db_hkcache, db_env, 0)) != 0) {
		db_env->close(db_env, 0);
		db_env = NULL;
		throw svExStorageConnect(
			string("db_create: ") + string(_SUVA_DB_HKCACHE) +
			string(": ") + db_strerror(rc));
	}
#if DB_VERSION_MAJOR == 4 && DB_VERSION_MINOR >= 1
	if ((rc = db_hkcache->open(db_hkcache,
		NULL, _SUVA_DB_HKCACHE, NULL, DB_BTREE, DB_CREATE, 0)) != 0)
#else
	if ((rc = db_hkcache->open(db_hkcache,
		_SUVA_DB_HKCACHE, NULL, DB_BTREE, DB_CREATE, 0)) != 0)
#endif
	{
		db_env->close(db_env, 0);
		db_env = NULL;
		throw svExStorageConnect(
			string("DB->open: ") + string(_SUVA_DB_HKCACHE) +
			string(": ") + db_strerror(rc));
	}

	svStorageEngine::Connect();
}

void svStorageEngineBerkeley::Disconnect(void)
{
	if (state != svSES_ONLINE) return;

	int rc;
	if (db_hkcache && (rc = db_hkcache->close(db_hkcache, 0)) != 0) {
		throw svExStorageDisconnect(string("DB->close: ") +
			db_strerror(rc));
	}
	db_hkcache = NULL;
	if (db_env) db_env->close(db_env, 0);
	db_env = NULL;

	svStorageEngine::Disconnect();
}
#endif // HAVE_LIBDB

#ifdef HAVE_LIBPQ
svStorageEnginePostgreSQL::svStorageEnginePostgreSQL(
	const svConfDatabase &conf)
	: svStorageEngine("PostgreSQL"), pg_conn(NULL), pg_res(NULL)
{
	type = svDT_PGSQL;

	ostringstream os;
	if (conf.GetHost().size())
		os << "host='" << conf.GetHost() << "' ";
	if (conf.GetPort().size())
		os << "port='" << conf.GetPort() << "' ";
	if (conf.GetDatabaseName().size())
		os << "dbname='" << conf.GetDatabaseName() << "' ";
	if (conf.GetUsername().size())
		os << "user='" << conf.GetUsername() << "' ";
	if (conf.GetPassword().size())
		os << "password='" << conf.GetPassword() << "' ";
	if (conf.GetTimeout().size())
		os << "connect_timeout='" << conf.GetTimeout() << "'";
	pg_cinfo = os.str();
	sql_query_hostkey = conf.GetSqlQueryHostKey();
	sql_insert_pool_client = conf.GetSqlInsertPoolClient();
	sql_update_pool_client = conf.GetSqlUpdatePoolClient();
	sql_purge_pool_clients = conf.GetSqlPurgePoolClients();

	try {
		string value;
		value = conf.GetSqlVariable("pool-client-idle");
		pool_client_state[svPCS_IDLE] = value;
	} catch (svExConfSqlVarNotFound &e) { }

	try {
		string value;
		value = conf.GetSqlVariable("pool-client-inuse");
		pool_client_state[svPCS_INUSE] = value;
	} catch (svExConfSqlVarNotFound &e) { }

	try {
		string value;
		value = conf.GetSqlVariable("pool-client-offline");
		pool_client_state[svPCS_OFFLINE] = value;
	} catch (svExConfSqlVarNotFound &e) { }
}

svStorageEnginePostgreSQL::~svStorageEnginePostgreSQL()
{
	Disconnect();
}

void svStorageEnginePostgreSQL::GetHostKey(
	const string &dev, const string &org, svHostKey &key)
{
	string sql(sql_query_hostkey);
	string value(dev);
	EscapeString(value);
	if (PrepareSQL(sql, "%d", value) == 0)
		throw svExStorageQuery("Invalid SQL, missing match token: device");
	value = org;
	EscapeString(value);
	PrepareSQL(sql, "%o", value);

	ExecuteSQL(sql);

	if (PQresultStatus(pg_res) != PGRES_TUPLES_OK) {
		throw svExStorageQuery(string("PQexec: ") +
			PQresultErrorMessage(pg_res));
	}
	if (PQntuples(pg_res) == 0)
		throw svExStorageRecordNotFound(name + ": Device not found: " + dev);

	key.SetAge(time(NULL));
	key.SetKey(PQgetvalue(pg_res, 0, 0));

	PQclear(pg_res);
	pg_res = NULL;
}

void svStorageEnginePostgreSQL::InsertPoolClient(const string &node,
	const string &pool_name, const string &dev, const string &org,
	svPoolClientState state)
{
	if (sql_insert_pool_client.size() == 0)
		throw svExStorageQuery("No SQL query set: insert-pool-client");

	string sql(sql_insert_pool_client);
	string value(dev);
	EscapeString(value);
	if (PrepareSQL(sql, "%d", value) == 0)
		throw svExStorageQuery("Invalid SQL, missing match token: device");
	value = node;
	EscapeString(value);
	PrepareSQL(sql, "%n", value);
	value = pool_name;
	EscapeString(value);
	PrepareSQL(sql, "%p", value);
	value = org;
	EscapeString(value);
	PrepareSQL(sql, "%o", value);

	ostringstream os;
	map<svPoolClientState, string>::iterator i;
	i = pool_client_state.find(state);
	if (i == pool_client_state.end()) os << state;
	else os << i->second;
	PrepareSQL(sql, "%s", os.str());

	ExecuteSQL(sql);

	if (PQresultStatus(pg_res) != PGRES_COMMAND_OK) {
		throw svExStorageQuery(string("PQexec: ") +
			PQresultErrorMessage(pg_res));
	}
}

void svStorageEnginePostgreSQL::UpdatePoolClient(const string &node,
	const string &pool_name, const string &dev, const string &org,
	svPoolClientState state)
{
	if (sql_update_pool_client.size() == 0)
		throw svExStorageQuery("No SQL query set: update-pool-client");

	string sql(sql_update_pool_client);
	string value(dev);
	EscapeString(value);
	if (PrepareSQL(sql, "%d", value) == 0)
		throw svExStorageQuery("Invalid SQL, missing match token: device");
	value = node;
	EscapeString(value);
	PrepareSQL(sql, "%n", value);
	value = pool_name;
	EscapeString(value);
	PrepareSQL(sql, "%p", value);
	value = org;
	EscapeString(value);
	PrepareSQL(sql, "%o", value);

	ostringstream os;
	map<svPoolClientState, string>::iterator i;
	i = pool_client_state.find(state);
	if (i == pool_client_state.end()) os << state;
	else os << i->second;
	PrepareSQL(sql, "%s", os.str());

	ExecuteSQL(sql);

	if (PQresultStatus(pg_res) != PGRES_COMMAND_OK) {
		throw svExStorageQuery(string("PQexec: ") +
			PQresultErrorMessage(pg_res));
	}

	uint32_t affected_rows = (uint32_t)atoi(PQcmdTuples(pg_res));
	if (affected_rows == 0)
		throw svExStorageRecordNotFound("Pool client not found");
}

void svStorageEnginePostgreSQL::PurgePoolClients(
	const string &node, const string &org)
{
	if (sql_purge_pool_clients.size() == 0)
		throw svExStorageQuery("No SQL query set: purge-pool-clients");

	string sql(sql_purge_pool_clients);
	string value(node);
	EscapeString(value);
	if (PrepareSQL(sql, "%n", value) == 0)
		throw svExStorageQuery("Invalid SQL, missing match token: node");
	value = org;
	EscapeString(value);
	PrepareSQL(sql, "%o", value);

	ExecuteSQL(sql);

	if (PQresultStatus(pg_res) != PGRES_COMMAND_OK) {
		throw svExStorageQuery(string("PQexec: ") +
			PQresultErrorMessage(pg_res));
	}
}

void svStorageEnginePostgreSQL::Connect(void)
{
	if (state == svSES_ONLINE &&
		PQstatus(pg_conn) == CONNECTION_OK) return;

	Disconnect();

	pg_conn = PQconnectdb(pg_cinfo.c_str());
	if (!pg_conn || PQstatus(pg_conn) != CONNECTION_OK) {
		string message("Unknown error");
		if (pg_conn) {
			message = PQerrorMessage(pg_conn);
			PQfinish(pg_conn);
			pg_conn = NULL;
		}
		throw svExStorageConnect(
			string("PQconnectdb: ") + message);
	}

	svStorageEngine::Connect();
}

void svStorageEnginePostgreSQL::Disconnect(void)
{
	if (state != svSES_ONLINE) return;

	if (pg_res) PQclear(pg_res);
	pg_res = NULL;
	if (pg_conn) PQfinish(pg_conn);
	pg_conn = NULL;

	svStorageEngine::Disconnect();
}

void svStorageEnginePostgreSQL::ExecuteSQL(const string &sql)
{
	if (state != svSES_ONLINE ||
		PQstatus(pg_conn) != CONNECTION_OK) Connect();

	if (pg_res) PQclear(pg_res);
	pg_res = NULL;

	pg_res = PQexec(pg_conn, sql.c_str());
	if (!pg_res)
		throw svExStorageQuery(string("PQexec: ") + PQerrorMessage(pg_conn));
}

void svStorageEnginePostgreSQL::EscapeString(string &value)
{
#ifdef HAVE_PQESCAPESTRINGCONN
	if (!value.size()) return;
	if (!escape_buffer) {
		escape_buffer_pages = 1;
		escape_buffer = (char *)realloc(NULL,
			escape_buffer_pages * page_size);
	}
	size_t length = value.size() * 2 + 1;
	while (length > escape_buffer_pages * page_size) {
		escape_buffer = (char *)realloc(escape_buffer,
			++escape_buffer_pages * page_size);
	}
	if (state != svSES_ONLINE ||
		PQstatus(pg_conn) != CONNECTION_OK) Connect();
	PQescapeStringConn(pg_conn, escape_buffer, value.c_str(),
		value.size(), NULL);
	value = escape_buffer;
#endif // HAVE_PQESCAPESTRINGCONN
}
#endif // HAVE_LIBPQ

#ifdef HAVE_LIBMYSQLCLIENT
svStorageEngineMySQL::svStorageEngineMySQL(
	const svConfDatabase &conf)
	: svStorageEngine("MySQL"), mysql_conn(NULL), mysql_res(NULL)
{
	type = svDT_MYSQL;

	if (conf.GetHost().size()) host = conf.GetHost();
	if (conf.GetPort().size())
		port = (uint16_t)atoi(conf.GetPort().c_str());
	else
		port = 0;
	if (conf.GetDatabaseName().size())
		db = conf.GetDatabaseName();
	if (conf.GetUsername().size())
		user = conf.GetUsername();
	if (conf.GetPassword().size())
		pass = conf.GetPassword();
	if (conf.GetTimeout().size())
		timeout = (uint16_t)atoi(conf.GetTimeout().c_str());
	else
		timeout = 0;
	sql_query_hostkey = conf.GetSqlQueryHostKey();
	sql_insert_pool_client = conf.GetSqlInsertPoolClient();
	sql_update_pool_client = conf.GetSqlUpdatePoolClient();
	sql_purge_pool_clients = conf.GetSqlPurgePoolClients();

	try {
		string value;
		value = conf.GetSqlVariable("pool-client-idle");
		pool_client_state[svPCS_IDLE] = value;
	} catch (svExConfSqlVarNotFound &e) { }

	try {
		string value;
		value = conf.GetSqlVariable("pool-client-inuse");
		pool_client_state[svPCS_INUSE] = value;
	} catch (svExConfSqlVarNotFound &e) { }

	try {
		string value;
		value = conf.GetSqlVariable("pool-client-offline");
		pool_client_state[svPCS_OFFLINE] = value;
	} catch (svExConfSqlVarNotFound &e) { }
}

svStorageEngineMySQL::~svStorageEngineMySQL()
{
	Disconnect();
}

void svStorageEngineMySQL::GetHostKey(
	const string &dev, const string &org, svHostKey &key)
{
	string sql(sql_query_hostkey);
	string value(dev);
	EscapeString(value);
	if (PrepareSQL(sql, "%d", value) == 0)
		throw svExStorageQuery("Invalid SQL, missing match token: device");
	value = org;
	EscapeString(value);
	PrepareSQL(sql, "%o", value);

	ExecuteSQL(sql);

	if (mysql_num_rows(mysql_res) == 0)
		throw svExStorageRecordNotFound(name + ": Device not found: " + dev);

	MYSQL_ROW row;
	if (!(row = mysql_fetch_row(mysql_res))) {
		throw svExStorageQuery(name +
			string(": mysql_fetch_row: ") + mysql_error(mysql_conn));
	}

	key.SetAge(time(NULL));
	key.SetKey(row[0]);

	mysql_free_result(mysql_res);
	mysql_res = NULL;
}

void svStorageEngineMySQL::InsertPoolClient(const string &node,
	const string &pool_name, const string &dev,
	const string &org, svPoolClientState state)
{
	if (sql_insert_pool_client.size() == 0)
		throw svExStorageQuery("No SQL query set: insert-pool-client");

	string sql(sql_insert_pool_client);
	string value(dev);
	EscapeString(value);
	if (PrepareSQL(sql, "%d", value) == 0)
		throw svExStorageQuery("Invalid SQL, missing match token: device");
	value = node;
	EscapeString(value);
	PrepareSQL(sql, "%n", value);
	value = pool_name;
	EscapeString(value);
	PrepareSQL(sql, "%p", value);
	value = org;
	EscapeString(value);
	PrepareSQL(sql, "%o", value);

	ostringstream os;
	map<svPoolClientState, string>::iterator i;
	i = pool_client_state.find(state);
	if (i == pool_client_state.end()) os << state;
	else os << i->second;
	PrepareSQL(sql, "%s", os.str());

	ExecuteSQL(sql);
}

void svStorageEngineMySQL::UpdatePoolClient(const string &node,
	const string &pool_name, const string &dev,
	const string &org, svPoolClientState state)
{
	if (sql_update_pool_client.size() == 0)
		throw svExStorageQuery("No SQL query set: update-pool-client");

	string sql(sql_update_pool_client);
	string value(dev);
	EscapeString(value);
	if (PrepareSQL(sql, "%d", value) == 0)
		throw svExStorageQuery("Invalid SQL, missing match token: device");
	value = node;
	EscapeString(value);
	PrepareSQL(sql, "%n", value);
	value = pool_name;
	EscapeString(value);
	PrepareSQL(sql, "%p", value);
	value = org;
	EscapeString(value);
	PrepareSQL(sql, "%o", value);

	ostringstream os;
	map<svPoolClientState, string>::iterator i;
	i = pool_client_state.find(state);
	if (i == pool_client_state.end()) os << state;
	else os << i->second;
	PrepareSQL(sql, "%s", os.str());

	ExecuteSQL(sql);

	my_ulonglong affected_rows = mysql_affected_rows(mysql_conn);
	if (affected_rows == 0)
		throw svExStorageRecordNotFound("Pool client not found");
}

void svStorageEngineMySQL::PurgePoolClients(
	const string &node, const string &org)
{
	if (sql_purge_pool_clients.size() == 0)
		throw svExStorageQuery("No SQL query set: purge-pool-clients");

	string sql(sql_purge_pool_clients);
	string value(node);
	EscapeString(value);
	if (PrepareSQL(sql, "%n", value) == 0)
		throw svExStorageQuery("Invalid SQL, missing match token: node");
	value = org;
	EscapeString(value);
	PrepareSQL(sql, "%o", value);

	ExecuteSQL(sql);
}

void svStorageEngineMySQL::Connect(void)
{
	if (state == svSES_ONLINE) return;

	if (mysql_res) mysql_free_result(mysql_res);
	mysql_res = NULL;

	mysql_conn = mysql_init(NULL);
	if (mysql_conn == NULL) {
		throw svExStorageConnect(
			string("mysql_init: insufficient memory"));
	}

	if (!mysql_real_connect(mysql_conn, host.c_str(),
		user.c_str(), pass.c_str(), db.c_str(), port, NULL, 0)) {
		throw svExStorageConnect(
			string("mysql_real_connect: ") + mysql_error(mysql_conn));
	}

	svStorageEngine::Connect();
}

void svStorageEngineMySQL::Disconnect(void)
{
	if (mysql_res) mysql_free_result(mysql_res);
	mysql_res = NULL;

	if (state != svSES_ONLINE) {
		if (mysql_conn) mysql_close(mysql_conn);
		mysql_conn = NULL;
		return;
	}

	if (mysql_conn) mysql_close(mysql_conn);
	mysql_conn = NULL;

	svStorageEngine::Disconnect();
}

void svStorageEngineMySQL::ExecuteSQL(const string &sql)
{
	if (state != svSES_ONLINE) Connect();

	if (mysql_res) mysql_free_result(mysql_res);
	mysql_res = NULL;

	int rc;
	if ((rc = mysql_query(mysql_conn, sql.c_str()))) {
		if (rc == CR_SERVER_GONE_ERROR || rc == CR_SERVER_LOST) {
			Disconnect(); Connect();
			if (mysql_query(mysql_conn, sql.c_str())) {
				throw svExStorageQuery(string("mysql_query: ") +
					mysql_error(mysql_conn));
			}
		}
		else {
			throw svExStorageQuery(string("mysql_query: ") +
				mysql_error(mysql_conn));
		}
	}

	mysql_res = mysql_store_result(mysql_conn);
	if (!mysql_res && mysql_field_count(mysql_conn) != 0) {
		throw svExStorageQuery(string("mysql_query: ") +
			mysql_error(mysql_conn));
	}
}

void svStorageEngineMySQL::EscapeString(string &value)
{
	if (!value.size()) return;
	if (!escape_buffer) {
		escape_buffer_pages = 1;
		escape_buffer = (char *)realloc(NULL,
			escape_buffer_pages * page_size);
	}
	size_t length = value.size() * 2 + 1;
	while (length > escape_buffer_pages * page_size) {
		escape_buffer = (char *)realloc(escape_buffer,
			++escape_buffer_pages * page_size);
	}
	if (state != svSES_ONLINE) Connect();
	if (mysql_real_escape_string(mysql_conn, escape_buffer,
		value.c_str(), value.size())) value = escape_buffer;
}

#endif // HAVE_LIBMYSQLCLIENT

// vi: ts=4
