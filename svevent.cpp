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
#include <sstream>
#include <stdexcept>
#include <map>
#include <vector>

#include <sys/time.h>

#include <stdint.h>
#include <errno.h>
#include <expat.h>
#include <string.h>
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
#include "svthread.h"
#include "svexec.h"
#include "svsession.h"

svEventServer *svEventServer::instance = NULL;

svEventClient::svEventClient(const string &name)
	: svObject(name), evt_dst_default(NULL)
{
	evt_server = svEventServer::GetInstance();
	if (evt_server == NULL)
		throw svExEventInstanceNotFound();

	pthread_cond_init(&evt_cond, NULL);
	pthread_mutex_init(&evt_cond_lock, NULL);
	pthread_mutex_init(&evt_mutex, NULL);

	evt_server->Register(this, name);
}

svEventClient::~svEventClient()
{
	evt_server->Unregister(this);

	pthread_cond_destroy(&evt_cond);
	pthread_mutex_destroy(&evt_cond_lock);
	pthread_mutex_destroy(&evt_mutex);

	for (vector<svEvent *>::iterator i = evt_queue.begin();
		i != evt_queue.end(); i++) delete (*i);
	evt_queue.clear();
}

svEvent *svEventClient::PopEvent(void)
{
	svEvent *event = NULL;
	pthread_mutex_lock(&evt_mutex);
	if (evt_queue.size()) {
		event = evt_queue.front();
		if (!event->IsPermanent())
			evt_queue.erase(evt_queue.begin());
		else
			event = event->Clone();

		switch (event->GetId()) {
		case svEVT_STATE_REQUEST:
			HandleStateRequest();
			delete event;
			event = NULL;
		default:
			break;
		}
	}
	pthread_mutex_unlock(&evt_mutex);
	return event;
}

svEvent *svEventClient::PopWaitEvent(uint32_t wait_ms)
{
	int rc;
	svEvent *event = NULL;

	struct timespec ts;
	if (wait_ms > 0) {
		struct timespec delay;
		delay.tv_sec = wait_ms / 1000;
		delay.tv_nsec = (wait_ms - delay.tv_sec * 1000) * 1000 * 1000;
		struct timespec now;
#if defined(HAVE_CLOCK_GETTIME)
		clock_gettime(CLOCK_REALTIME, &now);
#elif defined(HAVE_GETTIMEOFDAY)
		struct timeval gtod_now;
		gettimeofday(&gtod_now, NULL);
		now.tv_sec = gtod_now.tv_sec;
		now.tv_nsec = gtod_now.tv_usec * 1000;
#else
#error "No system clock available!"
#endif
		ts.tv_sec = now.tv_sec + delay.tv_sec;
		ts.tv_nsec = now.tv_nsec + delay.tv_nsec;
		if (ts.tv_nsec >= 1000000000L) {
			ts.tv_sec++;
			ts.tv_nsec = ts.tv_nsec - 1000000000L;
		}
	}

	for ( ;; ) {
		event = PopEvent();
		if (event != NULL) break;

		pthread_mutex_lock(&evt_cond_lock);
		if (wait_ms == 0) {
			rc = pthread_cond_wait(&evt_cond, &evt_cond_lock);
			pthread_mutex_unlock(&evt_cond_lock);
		}
		else {
			rc = pthread_cond_timedwait(
				&evt_cond, &evt_cond_lock, &ts);
			pthread_mutex_unlock(&evt_cond_lock);
			if (rc == ETIMEDOUT) break;
		}
		if (rc != 0) throw svExEventCondWait(rc);
	}
	return event;
}

void svEventClient::PushEvent(svEvent *event)
{
	pthread_mutex_lock(&evt_mutex);
	if (event->IsExclusive()) {
		vector<svEvent *>::iterator i;
		for (i = evt_queue.begin(); i != evt_queue.end(); i++) {
			if ((*i)->GetId() != event->GetId()) continue;
			delete (*i);
			evt_queue.erase(i);
			break;
		}
	}
	if (event->IsHighPriority())
		evt_queue.insert(evt_queue.begin(), event);
	else
		evt_queue.push_back(event);

	pthread_cond_broadcast(&evt_cond);
	pthread_mutex_unlock(&evt_mutex);
}

void svEventClient::HandleStateRequest(void)
{
	svDebug("%s: No state information", name.c_str());
}

svEventServer::svEventServer()
	: svObject("svEventServer")
{
	if (instance != NULL)
		throw svExEventInstance();

	instance = this;
	pthread_mutex_init(&client_mutex, NULL);
}

svEventServer::~svEventServer()
{
	if (instance == this) {
		instance = NULL;
		pthread_mutex_destroy(&client_mutex);
	}
}

void svEventServer::Dispatch(svEvent *event)
{
	pthread_mutex_lock(&client_mutex);
	map<svEventClient *, string>::iterator i;
	if (event->GetDest() == svEVT_BROADCAST) {
		for (i = client.begin(); i != client.end(); i++)
			i->first->PushEvent(event->Clone());
		delete event;
	}
	else {
		i = client.find(event->GetDest());
		if (i == client.end() && event->GetSource() != NULL) {
			map<svEventClient *, string>::iterator src;
			src = client.find(event->GetSource());
			if (src != client.end()) {
				event->SetDest(src->first->GetDefaultDest());
				i = client.find(src->first->GetDefaultDest());
			}
		}
		if (i != client.end())
			i->first->PushEvent(event);
		else delete event;
	}
	pthread_mutex_unlock(&client_mutex);
}

void svEventServer::Register(svEventClient *client, const string &name)
{
	pthread_mutex_lock(&client_mutex);
	this->client[client] = name;
	pthread_mutex_unlock(&client_mutex);
}

void svEventServer::Unregister(svEventClient *client)
{
	pthread_mutex_lock(&client_mutex);
	map<svEventClient *, string>::iterator i;
	if ((i = this->client.find(client)) != this->client.end())
		this->client.erase(i);
	pthread_mutex_unlock(&client_mutex);
}

// vi: ts=4
