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

#ifndef _SVEXEC_H
#define _SVEXEC_H

#ifndef _SUVA_APP_WAIT
#define _SUVA_APP_WAIT      60
#endif

using namespace std;

class svExExecFork : public runtime_error
{
public:
    explicit svExExecFork()
        : runtime_error("") { };
    virtual ~svExExecFork() throw() { };
};

class svExec : public svEventClient
{
public:
    svExec(const svConfSessionApp &conf_app,
        const string &dev, const string &org, const string &session,
        const string &remote_host);
    virtual ~svExec();

    pid_t GetPid(void) { return pid; };
    svSocket *Execute(void);
    void Exited(int status);
    void Terminate(void);
    bool HasExited(void) { return exited; };

protected:
    pid_t pid;
    svSocketPair *skt;
    string path;
    vector<string> args;
    bool exited;
    char **argv;
    char **envp;
    int fd_read;
    int fd_write;
};

#endif // _SVEXEC_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
