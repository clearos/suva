// Legacy SCL Front Door Plug-in
// $Id: scl.c,v 1.5 2006/01/11 21:03:45 darryl Exp $
// This plug-in will read SCL "connection open" and "suvlet create" packets
// from the old SCL C/Java API.  Using this, Suva 2 can be dropped in place
// of Suva 1 servers with minimal fuss.
#define _GNU_SOURCE

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>

#include "sfd.h"

extern int errno;

static unsigned char *payload = NULL;

int sfd_load(sfd_output_t sfd_output)
{
	fprintf(stderr, "%s:%s(): v0x%08x\n", __FILE__, __func__, SFD_VERSION);

	return SFD_VERSION;
}

void sfd_unload(void)
{
	if(payload) free(payload);

	payload = NULL;

	fprintf(stderr, "%s:%s()\n", __FILE__, __func__);
	return;
}

#define MAX_DEV					256
#define MAX_ORG					256
#define MAX_HOST				1024

struct scl_open_t
{
	unsigned int ttl;
	unsigned long port;
	char dev[MAX_DEV];
	char host[MAX_HOST];
	char organization[MAX_ORG];
};

#define MAX_SUVLETN 			1024

struct scl_create_t
{
	unsigned int ttl;
	unsigned int encrypted;		// Not used anymore...
	unsigned int exclusive;		// Not used anymore...
	char name[MAX_SUVLETN];
};

struct scl_packet_t
{
	unsigned int id;
	unsigned int flags;
	unsigned int reserved;
	unsigned int length;
};

#define MAX_TIMEOUT				10

static int scl_read(int sd, ssize_t length, unsigned char *buffer)
{
	ssize_t bytes_read;
	unsigned char *ptr = buffer;
	time_t timeout = time(NULL);
	register ssize_t bytes = length;

	while(bytes > 0)
	{
		bytes_read = read(sd, ptr, bytes);

		if(!bytes_read)
		{
			fprintf(stderr, "%s:%s(): hung-up.\n",
				__FILE__, __func__);
			return 0;
		}
		else if(bytes_read == -1)
		{
			if(errno == EAGAIN)
			{
				if(time(NULL) - timeout < MAX_TIMEOUT)
				{
					usleep(250);
					continue;
				}

				fprintf(stderr, "%s:%s(): read timed-out.\n",
					__FILE__, __func__);
			}
			else
			{
				fprintf(stderr, "%s:%s(): read: %s.\n",
					__FILE__, __func__, strerror(errno));
			}

			return -1;
		}

		ptr += bytes_read;
		bytes -= bytes_read;
		timeout = time(NULL);
	}

	return 1;
}

static int scl_write(int sd, ssize_t length, unsigned char *buffer)
{
	ssize_t bytes_wrote;
	unsigned char *ptr = buffer;
	time_t timeout = time(NULL);
	register ssize_t bytes = length;

	while(bytes > 0)
	{
		bytes_wrote = write(sd, ptr, bytes);

		if(!bytes_wrote)
		{
			fprintf(stderr, "%s:%s(): hung-up.\n",
				__FILE__, __func__);
			return 0;
		}
		else if(bytes_wrote == -1)
		{
			if(errno == EAGAIN)
			{
				if(time(NULL) - timeout < MAX_TIMEOUT)
				{
					usleep(250);
					continue;
				}

				fprintf(stderr, "%s:%s(): write timed-out.\n",
					__FILE__, __func__);
			}
			else
			{
				fprintf(stderr, "%s:%s(): write: %s.\n",
					__FILE__, __func__, strerror(errno));
			}

			return -1;
		}

		ptr += bytes_wrote;
		bytes -= bytes_wrote;
		timeout = time(NULL);
	}

	return 1;
}

#define MAX_ERRSTR				256

static int scl_error(int sd, unsigned int id, const char *format, ...)
{
	va_list ap;
	unsigned int len;
	struct scl_packet_t scl_pkt;
	unsigned char *buffer = NULL, *ptr;

#define SCL_RETURN				0x00
	scl_pkt.id = SCL_RETURN;
	scl_pkt.length = sizeof(unsigned int) * 2;

	if(format)
	{
		payload = realloc(payload, MAX_ERRSTR);
		memset(payload, 0, MAX_ERRSTR);

		va_start(ap, format);
		vsnprintf((char *)payload, MAX_ERRSTR - 1, format, ap);
		va_end(ap);

		buffer = (unsigned char *)strdup((char *)payload);
		scl_pkt.length += strlen((char *)buffer) + 1;
	}

	payload = realloc(payload, scl_pkt.length);

	memcpy(payload, (void *)&id, sizeof(unsigned int));
	ptr = payload + sizeof(unsigned int);

	len = strlen((char *)buffer);
	memcpy(ptr, (void *)&len, sizeof(unsigned int));

	if(format)
	{
		ptr += sizeof(unsigned int);
		memcpy(ptr, buffer, len + 1);

		free(buffer);
	}

	if(scl_write(sd, sizeof(struct scl_packet_t),
		(unsigned char *)&scl_pkt) != 1) return -1;
	if(scl_write(sd, scl_pkt.length, payload) != 1) return -1;

	return 0;
}

// XXX: The following was ripped from the series 1
// Suva functions; suvlet_open(), and suvlet_create().
int sfd_knock(struct sfd_conf_t *p_conf)
{
	unsigned char *ptr;
	struct scl_open_t scl_open;
	struct scl_packet_t scl_pkt;
	struct scl_create_t scl_create;
	unsigned int len, plen = sizeof(struct scl_open_t) - (MAX_DEV + MAX_HOST + MAX_ORG);

	if(scl_read(p_conf->sd, sizeof(struct scl_packet_t),
		(unsigned char *)&scl_pkt) != 1) return -1;

	// XXX: A bogus check really...
	if(scl_pkt.length > MAX_HOST + MAX_ORG + 16)
	{
		fprintf(stderr, "%s:%s(): invalid packet length: 0x%08x\n",
			__FILE__, __func__, scl_pkt.length);
		return -1;
	}

	payload = realloc(payload, scl_pkt.length);

	if(scl_read(p_conf->sd, scl_pkt.length, payload) != 1) return -1;

	memset(&scl_open, '\0', sizeof(struct scl_open_t));

	ptr = payload;
	memcpy(&scl_open, ptr, plen);

	ptr += plen;
	memcpy(&len, ptr, sizeof(unsigned int));
	ptr += sizeof(unsigned int);
#if SCL_OPEN_VER >= 2
	strncpy(scl_open.dev, (char *)ptr,
		(len >= MAX_DEV) ? MAX_DEV - 1 : len);

	ptr += len;
	memcpy(&len, ptr, sizeof(unsigned int));
	ptr += sizeof(unsigned int);
#endif
	strncpy(scl_open.host, (char *)ptr,
		(len >= MAX_HOST) ? MAX_HOST - 1 : len);

	ptr += len;
	memcpy(&len, ptr, sizeof(unsigned int));
	ptr += sizeof(unsigned int) + 1;

	strncpy(scl_open.organization, (char *)ptr,
		(len >= MAX_ORG) ? MAX_ORG - 1 : len);

	// LIES!  Send fake CONNECT and CONNECTED responses in order to get the suvlet
	// name from the calling program, needed to fill in the session name.
#define SRC_CONNECT				0x02
#define SRC_CONNECTED			0x07
	if(scl_error(p_conf->sd, SRC_CONNECT,
		"Connecting to %s:%ld...",
		scl_open.host, scl_open.port) != 0) return -1;
	if(scl_error(p_conf->sd, SRC_CONNECTED,
		"Connection to %s:%ld established.",
		scl_open.host, scl_open.port) != 0) return -1;

	if(scl_read(p_conf->sd, sizeof(struct scl_packet_t),
		(unsigned char *)&scl_pkt) != 1) return -1;

#define SCL_CSUVLET				0x03
	if(scl_pkt.id != SCL_CSUVLET)
	{
		fprintf(stderr, "%s:%s: invalid packet id: %u\n",
			__FILE__, __func__, scl_pkt.id);
		return -1;
	}

	// XXX: A bogus check really...
	if(scl_pkt.length > MAX_SUVLETN + 16)
	{
		fprintf(stderr, "%s:%s(): invalid packet length: 0x%08x\n",
			__FILE__, __func__, scl_pkt.length);
		return -1;
	}

	payload = realloc(payload, scl_pkt.length);

	if(scl_read(p_conf->sd, scl_pkt.length, payload) != 1) return -1;

	memset(&scl_create, 0, sizeof(struct scl_create_t));
	memcpy(&scl_create, payload,
		sizeof(struct scl_create_t) - MAX_SUVLETN);

	ptr = payload + sizeof(struct scl_create_t) - MAX_SUVLETN;

	memcpy(&len, ptr, sizeof(unsigned int));
	ptr += sizeof(unsigned int);

	strncpy(scl_create.name, (char *)ptr,
		(len >= MAX_SUVLETN) ? MAX_SUVLETN - 1 : len);

	p_conf->dev = strndup(scl_open.dev, MAX_DEV - 1);
	p_conf->session = strndup(scl_create.name, MAX_SUVLETN - 1);
	p_conf->session_ttl = scl_open.ttl;
	p_conf->org = strndup(scl_open.organization, MAX_ORG - 1);
	p_conf->dst_host = strndup(scl_open.host, MAX_HOST - 1);
	p_conf->dst_port = (u_short)scl_open.port;

	fprintf(stderr, "%s:%s(): SCL open %s as %s [%s] on %s:%hu, ttl: %u\n",
		__FILE__, __func__, p_conf->session, p_conf->dev, p_conf->org,
		p_conf->dst_host, p_conf->dst_port, p_conf->session_ttl);

	return 0;
}

void sfd_answer(const struct sfd_conf_t *p_conf)
{
	// More LIES!
#define SRC_OKAY				0x01
	scl_error(p_conf->sd, SRC_OKAY,
		"Spawned remote suvlet: %s.", p_conf->session);
}

void sfd_close(const struct sfd_conf_t *p_conf, u_int reason)
{
	if (p_conf->dev) free(p_conf->dev);
	if (p_conf->session) free(p_conf->session);
	if (p_conf->org) free(p_conf->org);
	if (p_conf->dst_host) free(p_conf->dst_host);
}

// vi: ts=4

