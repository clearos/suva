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

#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>

#ifdef HAVE_EXECINFO_H
#include <execinfo.h>
#endif

#include "svutil.h"

// Illegal ascii characters (+ !isprint())
static int svIllegalAscii[12] = {
    /* ! */ 0x21, /* " */ 0x22, /* % */ 0x25, /* & */ 0x26, /* ' */ 0x27,
    /* * */ 0x2A, /* : */ 0x3A, /* < */ 0x3C, /* > */ 0x3E, /* \ */ 0x5C,
    /* ` */ 0x60, /* ~ */ 0x7E
};

inline bool svIsLegalAscii(int c)
{
    for (size_t i = 0; i < sizeof(svIllegalAscii); i++)
        if (c == svIllegalAscii[i]) return false;
    if (!isprint(c)) return false;
    return true;
}

void svLegalizeString(string &dst, const char *src, size_t src_len)
{
    dst.clear();
    for (size_t i = 0; i < src_len; i++) {
        if (!svIsLegalAscii(src[i])) continue;
        dst.append(1, (char)src[i]);
    }
}

void svHexDump(FILE *fh, const void *data, uint32_t length)
{
    uint8_t c, *p = (uint8_t *)data;
    char bytestr[4] = { 0 };
    char addrstr[10] = { 0 };
    char hexstr[16 * 3 + 5] = { 0 };
    char charstr[16 * 1 + 5] = { 0 };

    for (uint32_t n = 1; n <= length; n++) {
        if (n % 16 == 1) {
            // Store address for this line
            snprintf(addrstr, sizeof(addrstr),
                "%.5x", (uint32_t)(p - (uint8_t *)data));
        }
            
        c = *p;
        if (isprint(c) == 0) c = '.';

        // Store hex str (for left side)
        snprintf(bytestr, sizeof(bytestr), "%02X ", *p);
        strncat(hexstr, bytestr, sizeof(hexstr) - strlen(hexstr) - 1);

        // Store char str (for right side)
        snprintf(bytestr, sizeof(bytestr), "%c", c);
        strncat(charstr, bytestr, sizeof(charstr) - strlen(charstr) - 1);

        if(n % 16 == 0) { 
            // Line completed
            fprintf(fh, "%5.5s:  %-49.49s %s\n", addrstr, hexstr, charstr);
            hexstr[0] = 0;
            charstr[0] = 0;
        } else if(n % 8 == 0) {
            // Half line: add whitespaces
            strncat(hexstr, " ", sizeof(hexstr) - strlen(hexstr) -1);
        }
        // Next byte...
        p++;
    }

    if (strlen(hexstr) > 0) {
        // Print rest of buffer if not empty
        fprintf(fh, "%5.5s:  %-49.49s %s\n", addrstr, hexstr, charstr);
    }
}

#define _SUVA_BACKTRACE_DEPTH   100

void svBacktrace(void)
{
#ifdef HAVE_BACKTRACE
    int nptrs;
    void *buffer[_SUVA_BACKTRACE_DEPTH];

    nptrs = backtrace(buffer, _SUVA_BACKTRACE_DEPTH);
    backtrace_symbols_fd(buffer, nptrs, STDERR_FILENO);
#endif
}

long svGetPageSize(void)
{
    long page_size = 4096;
#if defined(HAVE_SYSCONF) && defined(_SC_PAGESIZE)
    page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) page_size = 4096;
#elif defined(HAVE_GETPAGESIZE)
    page_size = getpagesize();
#endif
    return page_size;
}

#ifndef HAVE_USLEEP
int svDelay(int ms)
{
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    struct timespec ts_expire;

    if (ms <= 0) return 0; 
    if (pthread_mutex_init(&mutex, NULL)) return -1;
    if (pthread_cond_init(&cond, NULL)) {
        pthread_mutex_destroy(&mutex);
        return -1;
    }

//  ts_expire.tv_sec = (unsigned int)time(NULL) + seconds;
//  ts_expire.tv_nsec = 0;
    struct timespec delay;
    delay.tv_sec = ms / 1000;
    delay.tv_nsec = (ms - delay.tv_sec * 1000) * 1000 * 1000;

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
    ts_expire.tv_sec = now.tv_sec + delay.tv_sec;
    ts_expire.tv_nsec = now.tv_nsec + delay.tv_nsec;
    if (ts_expire.tv_nsec >= 1000000000L) {
        ts_expire.tv_sec++;
        ts_expire.tv_nsec = ts_expire.tv_nsec - 1000000000L;
    }
 
    int rc = pthread_cond_timedwait(&cond, &mutex, &ts_expire);
    pthread_cond_destroy(&cond);
    pthread_mutex_destroy(&mutex);
    return rc;
}
#endif

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
