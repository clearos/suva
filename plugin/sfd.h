/* Suva Front Door plug-in interface
 * Copyright (C) 2004-2008 Point Clark Networks
 * Copyright (C) 2009-2010 ClearFoundation
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *****************************************************************************/

#ifndef _SFD_H
#define _SFD_H

#include <sys/types.h>
#include <stdint.h>

#define SFD_VERSION	0x20100127

#ifdef __cplusplus
extern "C" {
#endif

/* See sfd_write below */
struct sfd_conf_t;
typedef ssize_t (*sfd_write_t)(const struct sfd_conf_t *p_conf,
	const void *buffer, size_t length);

/* Logging function */
typedef void (*sfd_output_t)(uint32_t level,
	const char *prefix, char *format, ...);

/* The Suva Front Door configuration structure */
struct sfd_conf_t
{
	/* Socket descriptor of the the new connection accepted by Suva.
	 * The plug-in uses this to communicate with the connecting protocol.
	 * Do not close this socket, or enable blocking. */
	int32_t sd;

	/* The following members are NULL and must be allocated by the plug-in
	 * when it has collected the answers from the connecting protocol.

	 * Deivce name.  This is the name of the destination device. This is
	 * only used to do a connection pool look-up. */
	char *dev;

	/* Session name.  This is the name of the application requesting
	 * the Suva network service.  This name must be present in the Suva
	 * configuration file on both ends of the connection. */
	char *session;

	/* Organization.  Must not be NULL. */
	char *org;

	/* The hostname or IP address of the desired destination device.  Must
	 * not be NULL. */
	char *dst_host;

	/* The TCP port address of the desired destination device.  If this is
	 * 0, then the default Suva STL port address will be used. */
	uint16_t dst_port;

	/* Session TTL in seconds.  If the connection is inactive for longer
	 * than this number of seconds, the connection will be closed.  If
	 * left to 0, then the default session-ttl will be used. */
	uint16_t session_ttl;

	/* This function can be called from sfd_answer if you need to
	 * write to the other side of the authenticated Suva connection. */
	sfd_write_t sfd_write;

	/* This is an address of a logging function that can be used to
	 * send output to a pre-configured location (suvad.conf) */
	sfd_output_t sfd_output;

	/* Private data.  Used internally by Suva. */
	void *private_data;
};

/* Suva will call this plug-in function when it initializes.  You can use this
 * function to perform any special initialization the plug-in may require.
 * Return SFD_VERSION upon success and -1 on error. */
int sfd_load(sfd_output_t);
typedef int (*sfd_load_t)(sfd_output_t);

/* Called just before Suva terminates.  Perform any clean-up if required. */
void sfd_unload(void);
typedef void (*sfd_unload_t)(void);

/* Front door knock.  Suva will call this function after accepting a new
 * incoming connection.  If you return 0 from this function then Suva will 
 * attempt to complete the connection to the destination device.  Return -1
 * on error */
int sfd_knock(struct sfd_conf_t *p_conf);
typedef int (*sfd_knock_t)(struct sfd_conf_t *);

/* Front door answer.  This is an optional call-back.  Suva will call this
 * function after the connection was authenticated.  You should not modify
 * the contents of the passed sfd_conf_t structure. */
void sfd_answer(const struct sfd_conf_t *p_conf);
typedef void (*sfd_answer_t)(const struct sfd_conf_t *);

/* Suva connection close event.  This is an optional call-back that Suva will
 * call when either end of a connection closes.  If you have any session
 * clean-up to do, it should be done before returning from this function. */
void sfd_close(const struct sfd_conf_t *p_conf, uint32_t reason);
typedef void (*sfd_close_t)(const struct sfd_conf_t *, uint32_t);

/* Connection closed because either end has hung-up. */
#define SFD_CLOSE_HANGUP		0x00000001
/* Connection closed because the session TTL has expired. */
#define SFD_CLOSE_TTL			0x00000002
/* Connection closed because of some unknown error. */
#define SFD_CLOSE_ERROR			0x00000004
/* Connection closed because authentication failed. */
#define SFD_CLOSE_AUTH			0x00000008
/* Connection closed because Suva has been terminated. */
#define SFD_CLOSE_TERM			0x00000010

#ifdef __cplusplus
}
#endif // __cplusplus
#endif // _SFD_H
