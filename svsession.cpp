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
#include <stdexcept>
#include <vector>
#include <map>

#include <sys/time.h>

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <expat.h>
#include <pthread.h>

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/dso.h>
#include <openssl/err.h>
#include <openssl/bn.h>

#ifdef USE_CALLGRIND
#include <valgrind/callgrind.h>
#if 0
CALLGRIND_START_INSTRUMENTATION;
...
CALLGRIND_STOP_INSTRUMENTATION;
CALLGRIND_DUMP_STATS;
#endif
#endif

#include "svutil.h"
#include "svoutput.h"
#include "svobject.h"
#include "svconf.h"
#include "svcrypto.h"
#include "svsocket.h"
#include "svpool.h"
#include "svevent.h"
#include "svpacket.h"
#include "svplugin.h"
#include "svpool.h"
#include "svkeyring.h"
#include "svexec.h"
#include "svthread.h"
#include "svsignal.h"
#include "svsession.h"
#include "svservice.h"

static ssize_t sfd_write(
	const struct sfd_conf_t *conf, const void *buffer, size_t length)
{
	ssize_t rc = -1;
	if (conf && conf->private_data) {
		svSession *session = (svSession *)conf->private_data;
		try {
			rc = session->FrontDoorWrite(buffer, length);
		} catch (runtime_error &e) {
		}
	}
	return rc;
}

svSession::svSession(svConfSessionType type)
	: svThread("svSession"), type(type),
	skt_stl(NULL), skt_raw(NULL), sfd(NULL), app(NULL), key_sync(0)
{
	memset(&rversion, 0, sizeof(struct pkt_version_t));

	crypto = new svCrypto(svService::GetConf()->GetAESKeySize());
	pkt_payload_size = crypto->GetMaxPayloadSize();
	memset(pkt_buffer, 0, _SUVA_MAX_PACKET_SIZE);
	pkt_payload = pkt_buffer + _SUVA_PKT_HEADER_SIZE;
}

svSession::~svSession()
{
	if (skt_stl) delete skt_stl;
	if (skt_raw) delete skt_raw;
	if (crypto) delete crypto;
	if (sfd) delete sfd;
	if (app) delete app;
}

ssize_t svSession::FrontDoorWrite(const void *buffer, size_t length)
{
	if (length > pkt_payload_size) return -1;
	memcpy(pkt_payload, buffer, length);

	svPacketData pkt_data(pkt_buffer);
	pkt_data.SetCrypto(crypto);
	pkt_data.SetPayloadLength(length);
	skt_stl->WritePacket(pkt_data);

	return length;
}

void svSession::Exit(void)
{
	if (type == svSE_APP && app) app->Terminate();
	svEventServer::GetInstance()->Dispatch(
		new svEventSessionExit(this));
	pthread_exit(NULL);
}

svEvent *svSession::EventRequest(svEvent *request, svEventId reply)
{
	svEventServer::GetInstance()->Dispatch(request);

	svEvent *event = NULL;
	for ( ;; ) {
		event = PopWaitEvent();
		switch (event->GetId()) {
		case svEVT_QUIT:
			if (type == svSE_SFD) sfd->Close(SFD_CLOSE_TERM);
			pthread_exit(NULL);
		case svEVT_SESSION_QUIT:
			delete event;
			if (type == svSE_SFD) sfd->Close(SFD_CLOSE_TERM);
			Exit();
		default:
			if (event->GetId() == reply &&
				event->GetDest() == this) return event;
			delete event;
		}
	}

	return NULL;
}

void svSession::VersionExchange(
	svPacketAuthVersion &pkt_ver_local,
	svPacketAuthVersion &pkt_ver_remote)
{
	char ipv4_addr[16];
#ifdef HAVE_ARPA_INET_H
	if (inet_ntop(AF_INET,
		&((const struct sockaddr_in *)skt_stl->GetSockAddr())->sin_addr,
		ipv4_addr, sizeof(struct sockaddr_in)) == NULL)
		strcpy(ipv4_addr, "<ERROR>");
#else
	strcpy(ipv4_addr, "<UNKNOWN>");
#endif

	if (skt_stl->IsConnected()) {
		pkt_ver_local.SetDevice(device_local);
		pkt_ver_local.SetOrganization(org);
		skt_stl->WritePacket(pkt_ver_local);
	}

	skt_stl->ReadPacket(pkt_ver_remote, pkt_payload_size);
	if (!pkt_ver_remote.IsValid())
		throw svExSessionInvalidPacket(skt_stl);

	if (type == svSE_SFD &&
		pkt_ver_remote.GetDevice() != sfd->GetDevice())
		throw svExSessionAuthFailure("Device ID mis-match");

	device_remote = pkt_ver_remote.GetDevice();
	memcpy(&rversion, pkt_payload + sizeof(struct pkt_id_t),
		sizeof(struct pkt_version_t));

	if (!skt_stl->IsConnected()) {
		svConfOrganization *conf_org = NULL;
		svService::GetConf()->Lock();
		conf_org = svService::GetConf()->GetOrganization(
			pkt_ver_remote.GetOrganization());
		if (conf_org) {
			org = conf_org->GetName();
			device_local = conf_org->GetDevice();
		}
		svService::GetConf()->Unlock();

		if (conf_org == NULL) {
			throw svExSessionInvalidOrganization(
				pkt_ver_remote.GetOrganization());
		}

		if (pkt_ver_remote.GetArg2() == PKT_ARG_AUTH_KEYPOLL)
			throw svExSessionKeyPollRequest(org);

		pkt_ver_local.SetDevice(device_local);
		pkt_ver_local.SetOrganization(org);
		skt_stl->WritePacket(pkt_ver_local);
	}
	svLog("%s: Remote device: %s (%s) v%d.%d [%s]",
		name.c_str(), device_remote.c_str(), ipv4_addr,
		rversion.major, rversion.minor,
		pkt_ver_remote.GetOrganization().c_str());

	if (pkt_ver_local.GetOrganization()
		!= pkt_ver_remote.GetOrganization()) {
		throw svExSessionOrganizationMismatch(
			pkt_ver_remote.GetOrganization());
	}
}

void svSession::SessionAccept(void)
{
	Authenticate();

	svPacketOpen pkt_open(pkt_buffer);
	pkt_open.SetVersion(rversion);
	pkt_open.SetCrypto(crypto);
	skt_stl->ReadPacket(pkt_open, pkt_payload_size);

	svConfSocket conf_raw;
	svConfSessionApp *conf_app = NULL;
	svConfOrganization *conf_org = NULL;
	svConfSession *conf_session = NULL;
	uint32_t tunnel_flags = 0;

	svService::GetConf()->Lock();
	conf_org = svService::GetConf()->GetOrganization(org);
	if (conf_org)
		conf_session = conf_org->GetSession(pkt_open.GetName());
	if (conf_session) {
		name = conf_session->GetName();
		type = conf_session->GetType();
		if (type == svSE_TUNNEL) {
			svConfSessionTunnel *conf_tunnel =
				(svConfSessionTunnel *)conf_session;
			tunnel_flags = conf_tunnel->GetConnectFlags();
			conf_raw = conf_tunnel->GetConfSocketConnect();
		}
		else if (type == svSE_APP) {
			conf_app = new svConfSessionApp(
				*((svConfSessionApp *)conf_session));
		}
		else if (type == svSE_VPN) {
			svConfSessionVpn *conf_vpn =
				(svConfSessionVpn *)conf_session;
			conf_raw = conf_vpn->GetConfSocketVpn();
		}
	}
	svService::GetConf()->Unlock();

	if (conf_org == NULL)
		throw svExSessionInvalidOrganization(org);
	if (conf_session == NULL)
		throw svExSessionInvalidSession(pkt_open.GetName());

	if (type == svSE_TUNNEL) {
		skt_raw = svSocket::Create(conf_raw);
		skt_raw->SetRaw();
		while (!skt_raw->IsConnected()) {
			skt_raw->Connect();
			svDelay(_SUVA_DEFAULT_DELAY);
		}
		if (tunnel_flags & TF_SEND_SESSION_INFO) {
			struct pkt_id_t id;
			struct pkt_session_t session;
			id.dev_length = device_remote.size();
			id.org_length = org.size();
			session.host_length = skt_stl->GetHostPath().size();
			session.session_length = name.size();

			ssize_t length;
			length = sizeof(struct pkt_id_t);

			skt_raw->Write((uint8_t *)&id, length);
			if (id.dev_length) {
				length = id.dev_length;
				skt_raw->Write(
					(uint8_t *)device_remote.c_str(), length);
			}
			if (id.org_length) {
				length = id.org_length;
				skt_raw->Write(
					(uint8_t *)org.c_str(), length);
			}

			length = sizeof(struct pkt_session_t);
			skt_raw->Write((uint8_t *)&session, length);
			if (session.host_length) {
				length = session.host_length;
				skt_raw->Write(
					(uint8_t *)skt_raw->GetHostPath().c_str(),
					length);
			}
			if (session.session_length) {
				length = session.session_length;
				skt_raw->Write((uint8_t *)name.c_str(), length);
			}
		}
	}
	else if (type == svSE_APP) {
		if (!conf_app)
			throw runtime_error("new conf_app == NULL");
		try {
			app = new svExec(*conf_app,
				device_remote, org, name, skt_stl->GetHostPath());
			skt_raw = app->Execute();
			delete conf_app;
		} catch (runtime_error &e) {
			delete conf_app;
			throw;
		}
	}
	else if (type == svSE_VPN) {
		skt_raw = svSocket::Create(conf_raw);
		skt_raw->SetRaw();
	}
	else {
		ostringstream os;
		os << "0x" << hex << type;
		throw svExSessionInvalidSessionType(os.str());
	}
}

void svSession::SessionConnect(void)
{
	try {
		if (type == svSE_VPN)
			VpnConnect();
		else {
			while (!skt_stl->IsConnected()) {
				skt_stl->Connect();
				svDelay(_SUVA_DEFAULT_DELAY);
			}
			Authenticate();
		}

		svPacketOpen pkt_open(pkt_buffer);
		pkt_open.SetName(name);
		pkt_open.SetVersion(rversion);
		pkt_open.SetCrypto(crypto);
		skt_stl->WritePacket(pkt_open);

		if (type == svSE_SFD) {
			sfd->SetWriteFunc(sfd_write);
			sfd->SetPrivateData((void *)this);
			sfd->Answer();
			sfd->SetWriteFunc(NULL);
			sfd->SetPrivateData(NULL);
		}
		
		SessionRun();
	} catch (svExSocketTimeout &e) {
		svError("%s: Socket %s time-out",
			name.c_str(), e.what());
		if (type == svSE_SFD) sfd->Close(SFD_CLOSE_ERROR);
	} catch (svExSocketPayloadTooLarge &e) {
		svError("%s: %s", name.c_str(), e.what());
		if (type == svSE_SFD) sfd->Close(SFD_CLOSE_ERROR);
	} catch (svExSocketHangup &e) {
		if (type == svSE_SFD) sfd->Close(SFD_CLOSE_HANGUP);
	} catch (svExSocketRead &e) {
		if (type == svSE_SFD) sfd->Close(SFD_CLOSE_ERROR);
	} catch (svExSocketWrite &e) {
		if (type == svSE_SFD) sfd->Close(SFD_CLOSE_ERROR);
	} catch (svExSocketInvalidParam &e) {
		svError("%s: Invalid socket parameter: %s",
			name.c_str(), e.what());
		if (type == svSE_SFD) sfd->Close(SFD_CLOSE_ERROR);
	} catch (svExSocketSelect &e) {
		svError("%s: Error selecting on sockets: %s",
			name.c_str(), e.what());
		if (type == svSE_SFD) sfd->Close(SFD_CLOSE_ERROR);
	} catch (svExSessionInvalidPacket &e) {
		svError("%s: Invalid packet: %s",
			name.c_str(), e.what());
		if (type == svSE_SFD) sfd->Close(SFD_CLOSE_ERROR);
	} catch (svExSessionKeyPollFailed &e) {
		svError("%s: %s", name.c_str(), e.what());
		if (type == svSE_SFD) sfd->Close(SFD_CLOSE_ERROR);
	} catch (svExSessionInvalidOrganization &e) {
		svError("%s: Invalid organization: %s",
			name.c_str(), e.what());
		if (type == svSE_SFD) sfd->Close(SFD_CLOSE_ERROR);
	} catch (svExSessionAuthFailure &e) {
		svError("%s: Authentication failed: %s",
			name.c_str(), e.what());
		if (type == svSE_SFD) sfd->Close(SFD_CLOSE_AUTH);
	} catch (svExCryptoHostKeyParseError &e) {
		svError("%s: Error parsing host key", name.c_str());
		if (type == svSE_SFD) sfd->Close(SFD_CLOSE_ERROR);
	} catch (runtime_error &e) {
		svError("%s: %s", name.c_str(), e.what());
		if (type == svSE_SFD) sfd->Close(SFD_CLOSE_ERROR);
	}
}

void svSession::SessionRun(void)
{
	int rc;
	ssize_t buffer_length;
	svSocketSet skt_set;
	svPacket pkt(pkt_buffer);
	pkt.SetCrypto(crypto);
	svPacketData pkt_data(pkt_buffer);
	pkt_data.SetCrypto(crypto);
	svPacketSessionKeyAck pkt_key_ack(pkt_buffer);
	svPacketHangup pkt_hangup(pkt_buffer);
	svPacketError pkt_error(pkt_buffer);

	svEvent *event;
	for ( ;; ) {
		while ((event = PopEvent())) {
			switch (event->GetId()) {
			case svEVT_QUIT:
				if (type == svSE_SFD) sfd->Close(SFD_CLOSE_TERM);
				pthread_exit(NULL);
			case svEVT_SESSION_QUIT:
				delete event;
				if (type == svSE_SFD) sfd->Close(SFD_CLOSE_TERM);
				return;
			case svEVT_CHILD_EXIT:
				if (type == svSE_APP && app) {
					svEventChildExit *event_child;
					event_child = (svEventChildExit *)event;
					if (event_child->GetPid() != app->GetPid()) break;
					app->Exited(event_child->GetStatus());
					delete event;
					svError("%s: RAW closed, application exited.", name.c_str());
					throw svExSocketHangup();
				}
				break;
			default:
				break;
			}
			delete event;
		}

		UpdateTimer();

		skt_set.Reset();

		if ((buffer_length = skt_raw->GetBufferLength() > 0))
			skt_set.SelectForWrite(skt_raw);

		if (buffer_length < _SUVA_SOCKET_MAX_BUFFER)
			skt_set.SelectForRead(skt_stl);

		if (!key_sync)
			skt_set.SelectForRead(skt_raw);

		//rc = skt_set.Select(_SUVA_DEFAULT_DELAY);
		rc = skt_set.Select(_SUVA_DEFAULT_DELAY * 10);

		if (rc == 0) continue;
		else if (rc == -1) {
			svDebug("%s: select: %s", name.c_str(), strerror(errno));
			svDelay(_SUVA_DEFAULT_DELAY);
			continue;
		}

		if (skt_set.IsReadyForWrite(skt_raw)) {
			skt_raw->FlushBuffer();
			if (rc == 1) continue;
			rc--;
		}

		if (skt_set.IsReadyForRead(skt_raw)) {
			ssize_t length = crypto->GetMaxPayloadSize();
			try {
				skt_raw->Read(pkt_payload, length);
			} catch (svExSocketHangup &e) {
				svError("%s: RAW closed", name.c_str());
				skt_stl->WritePacket(pkt_hangup);
				throw;
			} catch (svExSocketRead &e) {
				svErrorSessionSocket(name.c_str(), "RAW read", e.errid);
				skt_stl->WritePacket(pkt_error);
				throw;
			} catch (svExSocketTimeout &e) {
				svError("%s: RAW %s time-out", name.c_str(), e.what());
				skt_stl->WritePacket(pkt_error);
				throw;
			}

			pkt_data.SetPayloadLength(length);
			try {
				skt_stl->WritePacket(pkt_data);
			} catch (svExSocketHangup &e) {
				svError("%s: STL closed", name.c_str());
				skt_raw->FlushBuffer();
				throw;
			} catch (svExSocketWrite &e) {
				svErrorSessionSocket(name.c_str(), "STL write", e.errid);
				skt_raw->FlushBuffer();
				throw;
			} catch (svExSocketTimeout &e) {
				svError("%s: STL %s time-out", name.c_str(), e.what());
				skt_raw->FlushBuffer();
				throw;
			}
			rc--;
		}

		if (rc == 0) continue;

		if (skt_set.IsReadyForRead(skt_stl)) {
			try {
				skt_stl->ReadPacket(pkt, pkt_payload_size);
			} catch (svExSocketHangup &e) {
				svError("%s: STL closed", name.c_str());
				skt_raw->FlushBuffer();
				throw;
			} catch (svExSocketRead &e) {
				svErrorSessionSocket(name.c_str(), "STL read", e.errid);
				skt_raw->FlushBuffer();
				throw;
			} catch (svExSocketTimeout &e) {
				svError("%s: STL %s time-out", name.c_str(), e.what());
				skt_raw->FlushBuffer();
				throw;
			}

			if (pkt.GetId() == PKT_ID_HANGUP) {
				svError("%s: Remote RAW closed", name.c_str());
				skt_raw->FlushBuffer();
				throw svExSocketHangup();
			} else if (pkt.GetId() == PKT_ID_ERROR) {
				svError("%s: Remote RAW error", name.c_str());
				skt_raw->FlushBuffer();
				throw svExSocketHangup();
			} else if (pkt.GetId() == PKT_ID_KEY &&
				pkt.GetArg1() == PKT_ARG_KEY_ACK) {
				try {
					KeyChange();
					key_sync = 0;
					continue;
				} catch (runtime_error &e) {
					svError("%s: Error changing session key", name.c_str());
					throw;
				}
			} else if (pkt.GetId() == PKT_ID_KEY &&
				pkt.GetArg1() == PKT_ARG_KEY_SYNC) {
				try {
					skt_stl->WritePacket(pkt_key_ack);
				} catch (svExSocketHangup &e) {
					svError("%s: STL closed", name.c_str());
					skt_raw->FlushBuffer();
					throw;
				} catch (svExSocketWrite &e) {
					svErrorSessionSocket(name.c_str(), "STL write", e.errid);
					skt_raw->FlushBuffer();
					throw;
				} catch (svExSocketTimeout &e) {
					svError("%s: STL %s time-out", name.c_str(), e.what());
					skt_raw->FlushBuffer();
					throw;
				}
				try {
					KeyChange();
					key_sync = 0;
					continue;
				} catch (runtime_error &e) {
					svError("%s: Error changing session key", name.c_str());
					throw;
				}
			} else if (pkt.GetId() != PKT_ID_DATA) {
				svError("%s: Unexpected packet: 0x%02x 0x%02x 0x%02x",
					name.c_str(), pkt.GetId(), pkt.GetArg1(), pkt.GetArg2());
				throw svExSessionInvalidPacket(skt_stl);
			}

			if (type == svSE_APP && app->HasExited()) {
				svDebug("%s: Discarding RAW bytes: %d",
					name.c_str(), pkt.GetPayloadLength());
				continue;
			}

			try {
				ssize_t length = (ssize_t)pkt.GetPayloadLength();
				skt_raw->Write(pkt_payload, length);
			} catch (svExSocketHangup &e) {
				svError("%s: RAW closed", name.c_str());
				throw;
			} catch (svExSocketWrite &e) {
				svErrorSessionSocket(name.c_str(), "RAW write", e.errid);
				throw;
			} catch (svExSocketTimeout &e) {
				svError("%s: RAW %s time-out", name.c_str(), e.what());
				throw;
			}
		}
	}
}

void svSession::VpnAccept(void)
{
}

void svSession::VpnConnect(void)
{
	//svDelay(retry_interval * 1000);

	struct timeval tv_retry, tv_now;
	gettimeofday(&tv_retry, NULL);

	svEvent *event;
	for ( ;; ) {
		while ((event = PopEvent())) {
			switch (event->GetId()) {
			case svEVT_QUIT:
				pthread_exit(NULL);
			case svEVT_SESSION_QUIT:
				delete event;
				Exit();
			default:
				break;
			}
			delete event;
		}

		if (skt_stl->IsConnected()) break;

		gettimeofday(&tv_now, NULL);
		if (tv_retry.tv_sec > tv_now.tv_sec) {
			svDelay(_SUVA_DEFAULT_DELAY);
			continue;
		}

		try {
			while (!skt_stl->IsConnected()) {
				skt_stl->Connect();
				svDelay(_SUVA_DEFAULT_DELAY);
			}

			Authenticate();
		} catch (runtime_error &e) {
			svError("%s: %s: %s:%d: %s",
				name.c_str(), org.c_str(),
				skt_stl->GetHostPath().c_str(), skt_stl->GetPort(),
				e.what());
			gettimeofday(&tv_retry, NULL);
			tv_retry.tv_sec += retry_interval;

			if (skt_stl->IsConnected()) skt_stl->Close();
		}
	}
}

svSessionClient::svSessionClient(svConfSessionType type)
	: svSession(type)
{
	key_ttl = svService::GetConf()->GetKeyTTL();
}

svSessionClient::~svSessionClient() { }

void svSessionClient::KeyChange(void)
{
	svPacketSessionKey pkt_key(pkt_buffer);

	crypto->GenerateAESKey();
	crypto->RSACrypt(svRSA_PUBLIC_ENCRYPT, crypto->GetAESRawKey(),
		crypto->GetAESKeyBytes(), pkt_payload);
	pkt_key.SetPayloadLength(
		(uint16_t)crypto->GetRSAPublicKeySize());
	skt_stl->WritePacket(pkt_key);

	gettimeofday(&tv_key_change, NULL);
}

void svSessionClient::Authenticate(void)
{
	svPacketAuthVersion pkt_ver_local(pkt_buffer);
	pkt_ver_local.SetVersion(
		_SUVA_PROTO_VER_MAJOR, _SUVA_PROTO_VER_MINOR);
	if (type == svSE_POOL)
		pkt_ver_local.SetVersionFlags(PKT_VER_FLAG_POOL);
	svPacketAuthVersion pkt_ver_remote(pkt_buffer);

	VersionExchange(pkt_ver_local, pkt_ver_remote);

	if (!skt_stl->IsConnected()) {
		svConfOrganization *conf_org = NULL;
		svService::GetConf()->Lock();
		conf_org = svService::GetConf()->GetOrganization(org);
		if (conf_org) device_hostkey = conf_org->GetHostKey();
		svService::GetConf()->Unlock();

		if (conf_org == NULL) {
			throw svExSessionInvalidOrganization(
				pkt_ver_remote.GetOrganization());
		}
	}

	svEventKeyPollResult *evt_result;
	evt_result = (svEventKeyPollResult *)EventRequest(
		new svEventKeyPollRequest(this, org), svEVT_KEYPOLL_RESULT);
	if (evt_result->GetKey()) {
		crypto->SetRSAPublicKey(evt_result->GetKey());
		delete evt_result;
	} else {
		delete evt_result;
		throw svExSessionKeyPollFailed(org);
	}

	crypto->SetHostKey(device_hostkey.c_str());
	crypto->SetAESKeySize(pkt_ver_remote.GetAESKeySize());
	pkt_payload_size = crypto->GetMaxPayloadSize();

	crypto->GenerateAESKey();
	uint8_t challenge[crypto->GetAESKeyBytes()];
	memcpy(challenge,
		crypto->GetAESRawKey(), crypto->GetAESKeyBytes());

	crypto->RSACrypt(svRSA_PUBLIC_ENCRYPT,
		challenge, crypto->GetAESKeyBytes(), pkt_payload);

	uint8_t *hostkey = crypto->GetAESRawKey();
	memset(hostkey, 'f', crypto->GetAESKeyBytes());
	memcpy(hostkey, crypto->GetHostKey(), _SUVA_MAX_HOSTKEY_LEN / 2);

	svPacketAuthKeySync pkt_key_sync(pkt_buffer);
	pkt_key_sync.SetCrypto(crypto);
	pkt_key_sync.SetPayloadLength(
		(uint16_t)crypto->GetRSAPublicKeySize());
	crypto->SetAESKey(svAES_ENCRYPT, hostkey);
	skt_stl->WritePacket(pkt_key_sync);

	svPacketAuthKeyAck pkt_key_ack(pkt_buffer);
	pkt_key_ack.SetCrypto(crypto);
	crypto->SetAESKey(svAES_DECRYPT, hostkey);
	skt_stl->ReadPacket(pkt_key_ack, pkt_payload_size);

	if (!pkt_key_ack.IsValid()) {
		if (pkt_key_ack.GetId() == PKT_ID_AUTH &&
			pkt_key_ack.GetArg1() == PKT_ARG_AUTH_SYNC) {
			svError("%s: Client-to-client connections"
				" are not possible", name.c_str());
		}
		throw svExSessionInvalidPacket(skt_stl);
	}

	if (memcmp(challenge,
		pkt_payload, crypto->GetAESKeyBytes()))
		throw svExSessionAuthFailure("Challenge key mis-match");
	
	KeyChange();
}

void svSessionClient::UpdateTimer(void)
{
	gettimeofday(&tv, NULL);
	if (uint32_t(tv.tv_sec - tv_key_change.tv_sec) > key_ttl) {
		if (!key_sync) {
			svPacketSessionKeySync pkt_key_sync(pkt_buffer);
			skt_stl->WritePacket(pkt_key_sync);
			key_sync++;
		} else {
			if (key_sync == 3) {
				svError("%s: Session key sync time-out",
					name.c_str());
				Exit();
			}
			svError("%s: Still waiting on session key sync (+%ds)",
				name.c_str(), (key_sync++ * key_ttl));
		}
		gettimeofday(&tv_key_change, NULL);
	}
}

svSessionClientConnect::svSessionClientConnect(
	svSocket *skt_raw, const svConfSessionTunnel &conf)
	: svSessionClient(svSE_TUNNEL)
{
	name = conf.GetName();

	this->skt_raw = skt_raw;
	org = skt_raw->GetOrganization();

	svConfOrganization *conf_org;
	conf_org = svService::GetConf()->GetOrganization(org);
	if (!conf_org) throw svExSessionInvalidOrganization(org);
	device_local = conf_org->GetDevice();
	device_hostkey = conf_org->GetHostKey();

	svConfSocket conf_skt;
	conf_skt = conf.GetConfSocketConnect();
	skt_stl = svSocket::Create(conf_skt);
}

svSessionClientConnect::svSessionClientConnect(svSocket *skt_raw,
	const svConfFrontDoor &conf) : svSessionClient(svSE_SFD)
{
	this->skt_raw = skt_raw;
	name = conf.GetName();

	svConfPlugin *plugin;
	plugin = svService::GetConf()->GetPlugin(conf.GetPlugin());
	if (!plugin) throw svExSessionInvalidPlugin(conf.GetPlugin());

	sfd = new svPluginFrontDoor(*plugin, skt_raw);
}

svSessionClientConnect::svSessionClientConnect(
	const string &org, const svConfSessionVpn &conf)
	: svSessionClient(svSE_VPN)
{
	name = conf.GetName();
	this->org = org;

	svConfOrganization *conf_org;
	conf_org = svService::GetConf()->GetOrganization(org);
	if (!conf_org) throw svExSessionInvalidOrganization(org);
	device_local = conf_org->GetDevice();
	device_hostkey = conf_org->GetHostKey();

	svConfSocket conf_skt;
	conf_skt = conf.GetConfSocketVpn();
	skt_raw = svSocket::Create(conf_skt);
	conf_skt = conf.GetConfSocketConnect();
	skt_stl = svSocket::Create(conf_skt);
	
	retry_interval = conf.GetRetryInterval();
}

svSessionClientConnect::~svSessionClientConnect()
{
	Join();
}

void *svSessionClientConnect::Entry(void)
{
	try {
		if (type == svSE_SFD) {
			sfd->Knock();

			name = sfd->GetSession();
			org = sfd->GetOrganization();
			// XXX: SFD client-side was never supported in Suva/2
			// ...but why not?  The device ID is ignored for client-
			// side connections and is replaced by the config value.
			svConfOrganization *conf_org = NULL;
			svService::GetConf()->Lock();
			conf_org = svService::GetConf()->GetOrganization(org);
			if (conf_org) {
				device_local = conf_org->GetDevice();
				device_hostkey = conf_org->GetHostKey();
			}
			svService::GetConf()->Unlock();
			if (!conf_org) throw svExSessionInvalidOrganization(org);

			skt_stl = new svSocketInetConnect(
				sfd->GetHost(), sfd->GetPort());
		}

		SessionConnect();

	} catch (runtime_error &e) {
		svError("%s: %s", name.c_str(), e.what());
		if (type == svSE_SFD) sfd->Close(SFD_CLOSE_ERROR);
	}

	Exit();
	return NULL;
}

svSessionClientAccept::svSessionClientAccept(svSocket *skt_stl)
	: svSessionClient(svSE_NULL)
{
	this->skt_stl = skt_stl;
}

svSessionClientAccept::svSessionClientAccept(const string &org,
	const svConfSessionPool &conf)
	: svSessionClient(svSE_POOL)
{
	name = conf.GetName();
	this->org = org;

	svConfOrganization *conf_org;
	conf_org = svService::GetConf()->GetOrganization(org);
	if (!conf_org) throw svExSessionInvalidOrganization(org);
	device_local = conf_org->GetDevice();
	device_hostkey = conf_org->GetHostKey();

	svConfSocket conf_skt;
	conf_skt = conf.GetConfSocketConnect();
	skt_stl = svSocket::Create(conf_skt);

	retry_interval = conf.GetRetryInterval();
}

svSessionClientAccept::~svSessionClientAccept()
{
	Join();
}

void *svSessionClientAccept::Entry(void)
{
	try {
		if (type == svSE_POOL) PoolConnect();
		else SessionAccept();
		SessionRun();
	} catch (svExSocketTimeout &e) {
		svError("%s: Socket %s time-out", name.c_str(), e.what());
		if (type == svSE_SFD) sfd->Close(SFD_CLOSE_ERROR);
	} catch (svExSocketPayloadTooLarge &e) {
		svError("%s: %s", name.c_str(), e.what());
		if (type == svSE_SFD) sfd->Close(SFD_CLOSE_ERROR);
	} catch (svExSocketHangup &e) {
		if (type == svSE_SFD) sfd->Close(SFD_CLOSE_HANGUP);
	} catch (svExSocketRead &e) {
		if (type == svSE_SFD) sfd->Close(SFD_CLOSE_ERROR);
	} catch (svExSocketWrite &e) {
		if (type == svSE_SFD) sfd->Close(SFD_CLOSE_ERROR);
	} catch (svExSocketInvalidParam &e) {
		svError("%s: Invalid socket parameter: %s",
			name.c_str(), e.what());
		if (type == svSE_SFD) sfd->Close(SFD_CLOSE_ERROR);
	} catch (svExSocketSelect &e) {
		svError("%s: Error selecting on sockets: %s",
			name.c_str(), e.what());
		if (type == svSE_SFD) sfd->Close(SFD_CLOSE_ERROR);
	} catch (svExSessionInvalidPacket &e) {
		svError("%s: Invalid packet: %s",
			name.c_str(), e.what());
		if (type == svSE_SFD) sfd->Close(SFD_CLOSE_ERROR);
	} catch (svExSessionKeyPollFailed &e) {
		svError("%s: %s", name.c_str(), e.what());
		if (type == svSE_SFD) sfd->Close(SFD_CLOSE_ERROR);
	} catch (svExSessionInvalidOrganization &e) {
		svError("%s: Invalid organization: %s",
			name.c_str(), e.what());
		if (type == svSE_SFD) sfd->Close(SFD_CLOSE_ERROR);
	} catch (svExSessionAuthFailure &e) {
		svError("%s: Authentication failed: %s",
			name.c_str(), e.what());
		if (type == svSE_SFD) sfd->Close(SFD_CLOSE_AUTH);
	} catch (svExCryptoHostKeyParseError &e) {
		svError("%s: Error parsing host key", name.c_str());
		if (type == svSE_SFD) sfd->Close(SFD_CLOSE_ERROR);
	} catch (runtime_error &e) {
		svError("%s: %s", name.c_str(), e.what());
		if (type == svSE_SFD) sfd->Close(SFD_CLOSE_ERROR);
	}

	Exit();
	return NULL;
}

void svSessionClientAccept::PoolConnect(void)
{
	struct timeval tv_retry, tv_now;
	gettimeofday(&tv_retry, NULL);

	svEvent *event;
	for ( ;; ) {
		while ((event = PopEvent())) {
			switch (event->GetId()) {
			case svEVT_QUIT:
				pthread_exit(NULL);
			case svEVT_SESSION_QUIT:
				delete event;
				Exit();
			default:
				break;
			}
			delete event;
		}

		if (skt_stl->IsConnected()) {
			svSocketSet skt_set;
			skt_set.SelectForRead(skt_stl);

			//int rc = skt_set.Select(_SUVA_DEFAULT_DELAY);
			int rc = skt_set.Select(_SUVA_DEFAULT_DELAY * 10);

			if (rc == 0) continue;
			else if (rc == -1) {
				svDelay(_SUVA_DEFAULT_DELAY);
				continue;
			}

			if (skt_set.IsReadyForRead(skt_stl)) {
				string pool_name(name);
				try {
					type = svSE_NULL;
					SessionAccept();
					svEventServer::GetInstance()->Dispatch(
						new svEventPoolClientDelete(
							this, pool_name, org));
					break;
				} catch (runtime_error &e) {
					name = pool_name;
					svError("%s: %s: Error accepting pool connection: %s",
						name.c_str(), org.c_str(), e.what());
					skt_stl->Close();
					type = svSE_POOL;
					gettimeofday(&tv_retry, NULL);
					tv_retry.tv_sec += retry_interval;
				}
			}
		}

		gettimeofday(&tv_now, NULL);
		if (tv_retry.tv_sec > tv_now.tv_sec) {
			svDelay(_SUVA_DEFAULT_DELAY);
			continue;
		}

		try {
			while (!skt_stl->IsConnected()) {
				skt_stl->Connect();
				svDelay(_SUVA_DEFAULT_DELAY);
			}

			Authenticate();

			svPacketPool pkt_pool(pkt_buffer);
			pkt_pool.SetCrypto(crypto);
			pkt_pool.SetName(name);
			skt_stl->WritePacket(pkt_pool);

		} catch (svExSocketTimeout &e) {
			skt_stl->UpdateLastActive();
		} catch (runtime_error &e) {
			svError("%s: %s: %s:%d: %s",
				name.c_str(), org.c_str(),
				skt_stl->GetHostPath().c_str(), skt_stl->GetPort(),
				e.what());
			gettimeofday(&tv_retry, NULL);
			tv_retry.tv_sec += retry_interval;

			if (skt_stl->IsConnected()) skt_stl->Close();
		}
	}
}

svSessionServer::svSessionServer(svConfSessionType type)
	: svSession(type)
{
	session_ttl = svService::GetConf()->GetSessionTTL();
}

svSessionServer::~svSessionServer()
{
	for (vector<RSA *>::iterator i = key_ring.begin();
		i != key_ring.end(); i++) RSA_free(*i);
}

void svSessionServer::KeyChange(void)
{
	svPacketSessionKey pkt_key(pkt_buffer);

	skt_stl->ReadPacket(pkt_key, pkt_payload_size);
	if (!pkt_key.IsValid())
		throw svExSessionInvalidPacket(skt_stl);
	if (pkt_key.GetPayloadLength() !=
		crypto->GetRSAPrivateKeySize())
		throw svExSessionInvalidPacket(skt_stl);

	uint8_t *dst = pkt_payload + pkt_payload_size -
		pkt_key.GetPayloadLength();

	uint32_t length = crypto->RSACrypt(svRSA_PRIVATE_DECRYPT,
		pkt_payload, pkt_key.GetPayloadLength(), dst);
	if (length != crypto->GetAESKeyBytes())
		throw svExSessionInvalidPacket(skt_stl);

	crypto->SetAESKey(svAES_ENCRYPT, dst);
	crypto->SetAESKey(svAES_DECRYPT, dst);
}

void svSessionServer::Authenticate(void)
{
	svPacketAuthVersion pkt_ver_local(pkt_buffer);
	pkt_ver_local.SetVersion(
		_SUVA_PROTO_VER_MAJOR, _SUVA_PROTO_VER_MINOR);
	pkt_ver_local.SetAESKeySize(crypto->GetAESKeySize());
	svPacketAuthVersion pkt_ver_remote(pkt_buffer);

	try {
		VersionExchange(pkt_ver_local, pkt_ver_remote);
		if (rversion.major > (uint8_t)_SUVA_PROTO_VER_MAJOR ||
			(rversion.major == (uint8_t)_SUVA_PROTO_VER_MAJOR &&
			rversion.minor > (uint8_t)_SUVA_PROTO_VER_MINOR))
			throw svExSessionInvalidVersion();
	}
	catch (svExSessionKeyPollRequest &e) {
		svEventKeyRingResult *evt_result;
		evt_result = (svEventKeyRingResult *)EventRequest(
			new svEventKeyRingRequest(this, org, svRSA_TYPE_PUBLIC),
			svEVT_KEYRING_RESULT);
		key_ring = evt_result->GetKeyRing();
		delete evt_result;
		if (!key_ring.size())
			throw svExSessionKeyRingRequestFailed(org);

		BIO *mem = BIO_new(BIO_s_mem());
		if (!mem) {
			svError("%s: Error creating BIO", name.c_str());
			Exit();
		}

		if (PEM_write_bio_RSA_PUBKEY(mem, key_ring.front()) == 1) {
			int length = BIO_pending(mem);
			if (BIO_read(mem, pkt_payload, length) != length) {
				length = 0;
				svError("%s: Error reading from BIO", name.c_str());
			}
			BIO_free(mem);
			if (length > 0) {
				svPacket pkt(pkt_buffer);
				pkt.SetId(PKT_ID_AUTH);
				pkt.SetArg1(PKT_ARG_AUTH_KEYPOLL);
				pkt.SetPayloadLength((uint16_t)length);
				skt_stl->WritePacket(pkt);
			}
		}
		else svError(
			"%s: Error writing public RSA key", name.c_str());
		Exit();
	}

	svEventHostKeyResult *evt_hostkey;
	evt_hostkey = (svEventHostKeyResult *)EventRequest(
		new svEventHostKeyRequest(this, device_remote, org),
		svEVT_HOSTKEY_RESULT);
	device_hostkey.clear();
	if (evt_hostkey->GetDevice() == device_remote &&
		evt_hostkey->GetOrganization() == org) {
		svHostKey key(evt_hostkey->GetKey());
		device_hostkey = key.GetKey();
	}
	delete evt_hostkey;
	if (!device_hostkey.size())
		throw svExSessionHostKeyRequestFailed(device_remote, org);
	crypto->SetHostKey(device_hostkey.c_str());

	uint8_t *hostkey = crypto->GetAESRawKey();
	memset(hostkey, 'f', crypto->GetAESKeyBytes());
	memcpy(hostkey, crypto->GetHostKey(), _SUVA_MAX_HOSTKEY_LEN / 2);
	crypto->SetAESKey(svAES_DECRYPT, hostkey);

	svPacketAuthKeySync pkt_key_sync(pkt_buffer);
	pkt_key_sync.SetCrypto(crypto);
	skt_stl->ReadPacket(pkt_key_sync, pkt_payload_size);
	if (!pkt_key_sync.IsValid())
		throw svExSessionInvalidPacket(skt_stl);

	svEventKeyRingResult *evt_keyring;
	evt_keyring = (svEventKeyRingResult *)EventRequest(
		new svEventKeyRingRequest(this, org, svRSA_TYPE_PRIVATE),
		svEVT_KEYRING_RESULT);
	key_ring = evt_keyring->GetKeyRing();
	delete evt_keyring;
	if (!key_ring.size())
		throw svExSessionKeyRingRequestFailed(org);

	uint8_t *dst = NULL;
	for (vector<RSA *>::iterator i = key_ring.begin();
		i != key_ring.end(); i++) {
		if (BN_num_bits((*i)->n) !=
			pkt_key_sync.GetPayloadLength() * 8) continue;

		crypto->SetRSAPrivateKey(RSAPrivateKey_dup((*i)));
		dst = pkt_payload + pkt_payload_size - RSA_size((*i));

		try {
			crypto->RSACrypt(svRSA_PRIVATE_DECRYPT,
				pkt_payload, RSA_size((*i)), dst);
			break;
		} catch (runtime_error &e) {
			dst = NULL;
			continue;
		}
	}

	if (dst == NULL)
		throw svExSessionAuthFailure(
			"Challenge key decryption failed");

	crypto->SetAESKey(svAES_ENCRYPT, hostkey);

	svPacketAuthKeyAck pkt_key_ack(pkt_buffer);
	pkt_key_ack.SetCrypto(crypto);

	pkt_key_ack.SetPayloadLength(crypto->GetAESKeyBytes());
	memcpy(pkt_payload, dst, crypto->GetAESKeyBytes());

	skt_stl->WritePacket(pkt_key_ack);

	KeyChange();

	if (rversion.flags & (uint8_t)PKT_VER_FLAG_POOL) {
		svPacketPool pkt_pool(pkt_buffer);
		pkt_pool.SetCrypto(crypto);
		skt_stl->ReadPacket(pkt_pool, pkt_payload_size);

		// TODO: values here should be configurable
		skt_stl->SetKeepalive(true, 60, 30, 3);

		svPoolClient *client = new svPoolClient(skt_stl,
			pkt_pool.GetName(), device_remote, org);
		skt_stl = NULL;
		svEventServer::GetInstance()->Dispatch(
			new svEventPoolClientSave(this, client));
		Exit();
	}
}

void svSessionServer::UpdateTimer(void)
{
	if (session_ttl == 0) return;
	gettimeofday(&tv, NULL);
	if ((uint32_t)tv.tv_sec >
		skt_raw->GetLastActive() + session_ttl) {
		svLog("%s: Session TTL expired", name.c_str());
		Exit();
	}
}

svSessionServerConnect::svSessionServerConnect(svSocket *skt_raw,
	const svConfSessionTunnel &conf)
	: svSessionServer(svSE_TUNNEL)
{
	name = conf.GetName();

	this->skt_raw = skt_raw;
	org = skt_raw->GetOrganization();

	svConfOrganization *conf_org;
	conf_org = svService::GetConf()->GetOrganization(org);
	if (!conf_org) throw svExSessionInvalidOrganization(org);
	device_local = conf_org->GetDevice();

	svConfSocket conf_skt;
	conf_skt = conf.GetConfSocketConnect();
	skt_stl = svSocket::Create(conf_skt);
}

svSessionServerConnect::svSessionServerConnect(svSocket *skt_raw,
	const svConfFrontDoor &conf)
	: svSessionServer(svSE_SFD)
{
	this->skt_raw = skt_raw;
	name = conf.GetName();

	svConfPlugin *plugin;
	plugin = svService::GetConf()->GetPlugin(conf.GetPlugin());
	if (!plugin) throw svExSessionInvalidPlugin(conf.GetPlugin());

	sfd = new svPluginFrontDoor(*plugin, skt_raw);
}

svSessionServerConnect::svSessionServerConnect(
	const svConfSessionVpn &conf) : svSessionServer(svSE_VPN)
{
	name = conf.GetName();
}

svSessionServerConnect::~svSessionServerConnect()
{
	Join();
}

void *svSessionServerConnect::Entry(void)
{
	try {
		if (type == svSE_SFD) {
			sfd->Knock();

			name = sfd->GetSession();
			org = sfd->GetOrganization();

			svConfOrganization *conf_org = NULL;
			svService::GetConf()->Lock();
			conf_org = svService::GetConf()->GetOrganization(org);
			if (conf_org)
				device_local = conf_org->GetDevice();
			svService::GetConf()->Unlock();
			if (!conf_org) throw svExSessionInvalidOrganization(org);

			svEventPoolClientLoad *evt_result;
			evt_result = (svEventPoolClientLoad *)EventRequest(
				new svEventPoolClientLoad(
					this, sfd->GetDevice(), org),
						svEVT_POOLCLIENT_LOAD);
			svPoolClient *client = evt_result->GetClient();
			delete evt_result;

			if (client) {
				skt_stl = client->GetSocket(true);
				skt_stl->SetKeepalive(false);
				delete client;
			}
			else skt_stl = new svSocketInetConnect(
				sfd->GetHost(), sfd->GetPort());
		}

		SessionConnect();

	} catch (runtime_error &e) {
		svError("%s: %s", name.c_str(), e.what());
		if (type == svSE_SFD) sfd->Close(SFD_CLOSE_ERROR);
	}

	Exit();
	return NULL;
}

svSessionServerAccept::svSessionServerAccept(svSocket *skt_stl)
	: svSessionServer(svSE_NULL)
{
	this->skt_stl = skt_stl;
}

svSessionServerAccept::~svSessionServerAccept()
{
	Join();
}

void *svSessionServerAccept::Entry(void)
{
	try {
		SessionAccept();
		if (type == svSE_VPN) session_ttl = 0;
		SessionRun();
	} catch (svExSocketTimeout &e) {
		svError("%s: Socket %s time-out", name.c_str(), e.what());
		if (type == svSE_SFD) sfd->Close(SFD_CLOSE_ERROR);
	} catch (svExSocketPayloadTooLarge &e) {
		svError("%s: %s", name.c_str(), e.what());
		if (type == svSE_SFD) sfd->Close(SFD_CLOSE_ERROR);
	} catch (svExSocketHangup &e) {
		if (type == svSE_SFD) sfd->Close(SFD_CLOSE_HANGUP);
	} catch (svExSocketRead &e) {
		if (type == svSE_SFD) sfd->Close(SFD_CLOSE_ERROR);
	} catch (svExSocketWrite &e) {
		if (type == svSE_SFD) sfd->Close(SFD_CLOSE_ERROR);
	} catch (svExSocketInvalidParam &e) {
		svError("%s: Invalid socket parameter: %s",
			name.c_str(), e.what());
		if (type == svSE_SFD) sfd->Close(SFD_CLOSE_ERROR);
	} catch (svExSocketSelect &e) {
		svError("%s: Error selecting on sockets: %s",
			name.c_str(), e.what());
		if (type == svSE_SFD) sfd->Close(SFD_CLOSE_ERROR);
	} catch (svExSessionInvalidPacket &e) {
		svError("%s: Invalid packet: %s",
			name.c_str(), e.what());
		if (type == svSE_SFD) sfd->Close(SFD_CLOSE_ERROR);
	} catch (svExSessionKeyPollFailed &e) {
		svError("%s: %s", name.c_str(), e.what());
		if (type == svSE_SFD) sfd->Close(SFD_CLOSE_ERROR);
	} catch (svExSessionInvalidOrganization &e) {
		svError("%s: Invalid organization: %s",
			name.c_str(), e.what());
		if (type == svSE_SFD) sfd->Close(SFD_CLOSE_ERROR);
	} catch (svExSessionAuthFailure &e) {
		svError("%s: Authentication failed: %s",
			name.c_str(), e.what());
		if (type == svSE_SFD) sfd->Close(SFD_CLOSE_AUTH);
	} catch (svExCryptoHostKeyParseError &e) {
		svError("%s: Error parsing host key", name.c_str());
		if (type == svSE_SFD) sfd->Close(SFD_CLOSE_ERROR);
	} catch (runtime_error &e) {
		svError("%s: %s", name.c_str(), e.what());
		if (type == svSE_SFD) sfd->Close(SFD_CLOSE_ERROR);
	}

	Exit();
	return NULL;
}

// vi: ts=4
