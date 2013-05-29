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

#ifndef _SVOUTPUT_H
#define _SVOUTPUT_H

using namespace std;

enum svLogLevel
{
	svLOG_DEBUG,
	svLOG_INFO,
	svLOG_ERR,
};

class svOutput
{
public:
	svOutput();
	virtual ~svOutput();

	static void SetDebug(bool debug = true) { svOutput::debug = debug; };
	static void ToggleDebug(void) { svOutput::debug = svOutput::debug ? false : true; };
	static void OpenLogFile(const string &filename);
	static void OpenSyslog(
		const char *prefix, int32_t facility, bool debug);
	static void OpenEventLog(void);
	static void Printf(svLogLevel level, const char *format, va_list ap); 

protected:
	static bool debug;
	static int log_facility;
	static pthread_mutex_t mutex;
	static FILE *log_file;
#ifdef __WIN32__
	static HANDLE el_source;
#endif
};

void svDebug(const char *format, ...);
void svLog(const char *format, ...);
void svError(const char *format, ...);

#ifdef __WIN32__
#define svErrorSessionSocket(n, t, e) svError("%s: %s error: %d", n, t, e)
#else
#define svErrorSessionSocket(n, t, e) svError("%s: %s error: %s", n, t, strerror(e))
#endif

#define svTrace(s) svDebug(">>> TRACE: %s:%d: %s", __FILE__, __LINE__, s)

#endif // _SVOUTPUT_H
// vi: ts=4
