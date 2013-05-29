/* Interactive SFD plug-in
 * $Id: isfd.c,v 1.4 2006/01/19 02:57:34 darryl Exp $ */
#define _GNU_SOURCE

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/types.h>

#include "sfd.h"

extern int errno;

int sfd_load(sfd_output_t sfd_output)
{
	//syslog(LOG_DAEMON | LOG_INFO, "iSFD plug-in loaded.");
	return SFD_VERSION;
}

void sfd_unload(void)
{
	//syslog(LOG_DAEMON | LOG_INFO, "iSFD plug-in un-loaded.");
}

static int isfd_read(int sd)
{
	char c;
	ssize_t byte;

	while(1)
	{
		if((byte = read(sd, &c, sizeof(char))) == sizeof(char)) break;
		if(!byte) return -1;
        else if(byte == -1)
        {
			if(errno == EAGAIN)
			{
				usleep(250);
				continue;
			}

			return -1;
		}
	}

	return (int)c;
}

#define CHAR_LEGAL_NAME(c)		isalnum(c) || c == '.' || c == '-'

static size_t isfd_prompt(int sd, const char *prompt, char *buffer, size_t length)
{
	size_t c;
	FILE *sh = fdopen(dup(sd), "w");

	if(!sh) return -1;
	fprintf(sh, "%s ", prompt); fflush(sh);

	memset(buffer, 0, length);

	for(c = 0; c < length; )
	{
		if((buffer[c] = (char)isfd_read(sd)) == -1) return -1;
		if(buffer[c] == '\n')
		{
			buffer[c] = 0;
			break;
		}

		if(CHAR_LEGAL_NAME(buffer[c])) c++;
	}

	fclose(sh);
	return c;
}

#define CONF_MAX_NAME_LEN		255
#define CONF_DEFAULT_ORG		"pointclark.net"

int sfd_knock(struct sfd_conf_t *p_conf)
{
	int len;
	char buffer[CONF_MAX_NAME_LEN + 1];
	FILE *sh = fdopen(dup(p_conf->sd), "w");
	if(!sh) return -1;

	fprintf(sh, "iSFD: Interactive SFD [%s %s]\n", __DATE__, __TIME__);
	fprintf(sh, "iSFD: Copyright (C) 2005 Point Clark Networks\niSFD:\n"); fflush(sh);

	if(isfd_prompt(p_conf->sd, "iSFD: Device name:", buffer, CONF_MAX_NAME_LEN))
		p_conf->dev = strndup(buffer, CONF_MAX_NAME_LEN);
	else goto _sfd_knock_error;
	if(isfd_prompt(p_conf->sd, "iSFD: Session name:", buffer, CONF_MAX_NAME_LEN))
		p_conf->session = strndup(buffer, CONF_MAX_NAME_LEN);
	else goto _sfd_knock_error;
	if((len = isfd_prompt(p_conf->sd, "iSFD: Session TTL:", buffer, CONF_MAX_NAME_LEN)) != -1)
	{
		if(len != 0) p_conf->session_ttl = atoi(buffer);
	}
	else goto _sfd_knock_error;
	if((len = isfd_prompt(p_conf->sd, "iSFD: Organization:", buffer, CONF_MAX_NAME_LEN)) != -1)
	{
		if(len != 0) p_conf->org = strndup(buffer, CONF_MAX_NAME_LEN);
		else p_conf->org = strndup(CONF_DEFAULT_ORG, CONF_MAX_NAME_LEN);
	}
	else goto _sfd_knock_error;
	if(isfd_prompt(p_conf->sd, "iSFD: Destination host name:", buffer, CONF_MAX_NAME_LEN))
		p_conf->dst_host = strndup(buffer, CONF_MAX_NAME_LEN);
	else goto _sfd_knock_error;
	if((len = isfd_prompt(p_conf->sd, "iSFD: Destination port address:", buffer, CONF_MAX_NAME_LEN)) != -1)
	{
		if(len != 0) p_conf->dst_port = (u_short)atoi(buffer);
	}
	else goto _sfd_knock_error;

	fprintf(sh, "iSFD:\n");
	fclose(sh);
	return 0;

_sfd_knock_error:
	fclose(sh);
	return -1;
}

void sfd_answer(const struct sfd_conf_t *p_conf)
{
	FILE *sh = fdopen(dup(p_conf->sd), "w");
	if(!sh) return;

	fprintf(sh, "iSFD: Connection established.\n");
	fclose(sh);
}

void sfd_close(const struct sfd_conf_t *p_conf, u_int reason)
{
	FILE *sh = fdopen(dup(p_conf->sd), "w");
	if(!sh) return;

	fprintf(sh, "iSFD: Connection closed, ");
	if(reason & SFD_CLOSE_HANGUP) fprintf(sh, "socket hung-up.\n");
	else if(reason & SFD_CLOSE_TTL) fprintf(sh, "time out.\n");
	else if(reason & SFD_CLOSE_AUTH) fprintf(sh, "authentication failure.\n");
	else if(reason & SFD_CLOSE_ERROR) fprintf(sh, "unknown error.\n");
	else if(reason & SFD_CLOSE_TERM) fprintf(sh, "terminated.\n");
	fclose(sh);

	if (p_conf->dev) free(p_conf->dev);
	if (p_conf->session) free(p_conf->session);
	if (p_conf->org) free(p_conf->org);
	if (p_conf->dst_host) free(p_conf->dst_host);

	//syslog(LOG_DAEMON | LOG_INFO, "iSFD plug-in closed.");
}

/*
 * vi: ts=4
*/
