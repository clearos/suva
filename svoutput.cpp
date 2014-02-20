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
#include <streambuf>
#include <sstream>
#include <stdexcept>
#include <map>

#include <sys/types.h>
#ifdef __linux__
#include <sys/syscall.h>
#endif

#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <pthread.h>

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

#ifdef __ANDROID__
#include <android/log.h>
#endif

#include "svoutput.h"
#include "svobject.h"
#include "svutil.h"

int32_t svOutput::log_facility = 0;
pthread_mutex_t svOutput::mutex;
bool svOutput::debug = false;
FILE *svOutput::log_file = NULL;
#ifdef __WIN32__
HANDLE svOutput::el_source = NULL;
#endif

svOutput::svOutput()
{
    pthread_mutex_init(&mutex, NULL);
}

svOutput::~svOutput()
{
    pthread_mutex_destroy(&mutex);
#ifdef HAVE_SYSLOG_H
    if (log_facility) {
        log_facility = 0;
        closelog();
    }
#endif
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
#ifdef __WIN32__
    if (el_source) {
        DeregisterEventSource(el_source);
        el_source = NULL;
    }
#endif
}

void svOutput::OpenLogFile(const string &filename)
{
    if (log_file != NULL)
        fclose(log_file);
    log_file = fopen(filename.c_str(), "w");
}

void svOutput::OpenSyslog(
    const char *prefix, int32_t facility, bool debug)
{
#ifdef HAVE_SYSLOG_H
    closelog();
    log_facility = facility;
    int option = LOG_PID;
    if (debug) option |= LOG_PERROR;
    openlog(prefix, option, facility);
#endif
}

void svOutput::OpenEventLog(void)
{
#ifdef __WIN32__
    if (el_source == NULL) {
        el_source = RegisterEventSource(NULL, "Suva");
    }
#endif
}

void svOutput::Printf(
    svLogLevel level, const char *format, va_list ap)
{
    if (!debug && level == svLOG_DEBUG) return;

    pthread_mutex_lock(&mutex);
#ifndef __WIN32__

    if (log_file != NULL) {
        switch (level) {
        case svLOG_DEBUG:
            fprintf(log_file, "DEBUG: ");
            break;
        case svLOG_ERR:
            fprintf(log_file, "ERROR: ");
            break;
        default:
            break;
        }
        vfprintf(log_file, format, ap);
        fputc('\n', log_file);
    }
#ifdef __ANDROID__
    int priority;
    switch (level) {
    case svLOG_DEBUG:
        priority = ANDROID_LOG_DEBUG;
        break;
    case svLOG_INFO:
        priority = ANDROID_LOG_INFO;
        break;
    case svLOG_ERR:
        priority = ANDROID_LOG_ERROR;
        break;
    }
    __android_log_vprint(priority, "Suva", format, ap);
#elif defined(HAVE_SYSLOG_H)
    if (log_facility == 0) {
        switch (level) {
        case svLOG_DEBUG:
            fprintf(stderr, "DEBUG: ");
            break;
        case svLOG_ERR:
            fprintf(stderr, "ERROR: ");
            break;
        default:
            break;
        }
        vfprintf(stderr, format, ap);
        fputc('\n', stderr);
        pthread_mutex_unlock(&mutex);
        return;
    }

    int priority = log_facility;
    switch (level) {
    case svLOG_DEBUG:
        priority |= LOG_DEBUG;
        break;
    case svLOG_INFO:
        priority |= LOG_INFO;
        break;
    case svLOG_ERR:
        priority |= LOG_ERR;
        break;
    }
    vsyslog(priority, format, ap);
#endif // __ANDROID__
#else
#define MSG_EVENT       0x00000064L
    if (el_source) {
        char message[512];
        vsnprintf(message, sizeof(message), format, ap);
        char *log_str[1];
        log_str[0] = message;
        DWORD el_type = EVENTLOG_INFORMATION_TYPE;
        switch (level) {
        case svLOG_DEBUG:
            el_type = EVENTLOG_WARNING_TYPE;
        case svLOG_ERR:
            el_type = EVENTLOG_ERROR_TYPE;
        }
        ReportEvent(el_source, el_type, 0,
            MSG_EVENT,
            NULL, 1, 0, (const char **)log_str, NULL);
    }
    else {
        switch (level) {
        case svLOG_DEBUG:
            fprintf(stdout, "DEBUG: ");
            break;
        case svLOG_ERR:
            fprintf(stdout, "ERROR: ");
            break;
        default:
            break;
        }
        vfprintf(stdout, format, ap);
        fputc('\n', stdout);
    }
#endif
    pthread_mutex_unlock(&mutex);
}

void svDebug(const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    svOutput::Printf(svLOG_DEBUG, format, ap);
    va_end(ap);
}

void svLog(const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    svOutput::Printf(svLOG_INFO, format, ap);
    va_end(ap);
}

void svError(const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    svOutput::Printf(svLOG_ERR, format, ap);
    va_end(ap);
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
