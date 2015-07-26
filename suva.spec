# Suva RPM spec

# Default vendor configuration file
%define vendor_config suvad.conf
%define vendor_sysvinit suvad

Name: suva
Version: 3.1
Release: 14%{dist}
Vendor: ClearFoundation
Group: System Environment/Daemons
License: GPL
Packager: ClearFoundation
Source: %{name}-%{version}.tar.gz
BuildRoot: /var/tmp/%{name}-%{version}
Requires: /usr/sbin/useradd /sbin/service
BuildRequires: autoconf >= 2.63
BuildRequires: automake
BuildRequires: libtool
BuildRequires: systemd
BuildRequires: expat-devel
BuildRequires: openssl-devel
Summary: Cloud Service Client/Server
%description
http://www.clearcenter.com
Report bugs to: http://www.clearfoundation.com/docs/developer/bug_tracker/

%package sdn
Summary: Cloud Services Delivery Network
Group: System Environment/Base
BuildRequires: libdb-devel
BuildRequires: postgresql-devel
%description sdn
http://www.clearcenter.com
Report bugs to: http://www.clearfoundation.com/docs/developer/bug_tracker/

%package client
Summary: Cloud Services Client
Group: System Environment/Base
%description client
http://www.clearcenter.com
Report bugs to: http://www.clearfoundation.com/docs/developer/bug_tracker/

%package server
Summary: Cloud Services Server
Group: System Environment/Base
BuildRequires: libdb-devel
#BuildRequires: mysql-devel
BuildRequires: postgresql-devel
%description server
http://www.clearcenter.com
Report bugs to: http://www.clearfoundation.com/docs/developer/bug_tracker/

%package devel
Summary: SFD Plug-in API
Group: Development/Libraries
%description devel
Development header for the Suva "front door" API.
http://www.clearcenter.com
Report bugs to: http://www.clearfoundation.com/docs/developer/bug_tracker/

# Build
%prep
%setup -q
./autogen.sh
%{configure}

%build
make %{?_smp_mflags}
make %{?_smp_mflags} -C plugin/scl
make %{?_smp_mflags} -C plugin/isfd

# Install
%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
make -C plugin install DESTDIR=$RPM_BUILD_ROOT
make -C plugin/scl install DESTDIR=$RPM_BUILD_ROOT
make -C plugin/isfd install DESTDIR=$RPM_BUILD_ROOT

mkdir -p -m 755 $RPM_BUILD_ROOT%{_sysconfdir}
%if "0%{dist}" == "0.v6"
mkdir -p -m 755 $RPM_BUILD_ROOT%{_sysconfdir}/init.d
%endif
mkdir -p -m 755 $RPM_BUILD_ROOT%{_var}/run/suvad
mkdir -p -m 750 $RPM_BUILD_ROOT%{_var}/lib/suva/clearcenter.com

mkdir -p -m 755 $RPM_BUILD_ROOT%{_bindir}
cp util/scripts/setdev.sh $RPM_BUILD_ROOT%{_bindir}
cp util/scripts/setkey.sh $RPM_BUILD_ROOT%{_bindir}
cp util/scripts/mkhost.sh $RPM_BUILD_ROOT%{_bindir}
cp util/scripts/mkrsa.sh $RPM_BUILD_ROOT%{_bindir}

cp config/%{vendor_config} $RPM_BUILD_ROOT%{_sysconfdir}/suvad.conf

%if "0%{dist}" == "0.v6"
cp config/init.d/%{vendor_sysvinit} $RPM_BUILD_ROOT%{_sysconfdir}/init.d/suvad
cp config/init.d/%{vendor_sysvinit}-server $RPM_BUILD_ROOT%{_sysconfdir}/init.d/suvad-server
%else
install -D -m 644 config/systemd/suva.service %{buildroot}/lib/systemd/system/suva.service
install -D -m 644 config/tmpfiles.d/suva.conf %{buildroot}/%{_tmpfilesdir}/suva.conf
%endif

# Add suva system user
%pre sdn
/usr/sbin/useradd -M -c "Suva" -s /sbin/nologin -d %{_var}/lib/suva -r suva 2> /dev/null || :

%pre server
/usr/sbin/useradd -M -c "Suva" -s /sbin/nologin -d %{_var}/lib/suva -r suva 2> /dev/null || :

%pre client
/usr/sbin/useradd -M -c "Suva" -s /sbin/nologin -d %{_var}/lib/suva -r suva 2> /dev/null || :

# Post install
%post client
/sbin/ldconfig

# XXX: Hack for upgrades.  When the old suvlets RPM is un-installed, it will call
# suvactl to de-register the suvlets.  This fails because we've just removed
# suvactl.  So we're re-creating a dummy below so the old suvlets RPM postun
# exits clean.  The compat-suvlets RPM will remove this.
if [ -d "/usr/local/suva" -a ! -d "/usr/local/suva/bin" ]; then
    mkdir -p /usr/local/suva/bin
    suvactl=/usr/local/suva/bin/suvactl
    echo "#!/bin/bash" > $suvactl
    echo "exit 0" >> $suvactl
    chmod a+rx $suvactl
fi

%if "0%{dist}" == "0.v6"
/sbin/chkconfig --add suvad >/dev/null 2>&1 || :
/sbin/service suvad condrestart >/dev/null 2>&1 || :
%else
/sbin/chkconfig --add suva >/dev/null 2>&1 || :
/usr/bin/systemctl enable suva.service -q
/usr/bin/systemctl reload-or-restart suva.service -q
%endif

# Pre un-install
%preun
%if "0%{dist}" == "0.v6"
if [ "$1" = 0 ]; then
    /sbin/chkconfig --del suvad
fi
%else
if [ "$1" = 0 ]; then
    /sbin/chkconfig --del suva
    /usr/bin/systemctl stop suva.service -q
    /usr/bin/systemctl disable suva.service -q
fi
%endif

# Post un-install
%postun
/sbin/ldconfig

# Clean-up
%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

# SDN files
%files sdn
%defattr(-,root,root)
%attr(0755,suva,suva) %{_var}/run/suvad
%dir %attr(0750,suva,suva) %{_var}/lib/suva
%dir %attr(0750,suva,suva) %{_var}/lib/suva/clearcenter.com
%{_libdir}/libscl.so
%{_libdir}/libscl.so.0
%{_libdir}/libscl.so.0.0.0
%{_libdir}/libscl.a
%{_libdir}/libscl.la
%{_libdir}/libisfd.so
%{_libdir}/libisfd.so.0
%{_libdir}/libisfd.so.0.0.0
%{_libdir}/libisfd.a
%{_libdir}/libisfd.la
%attr(0755,root,root) %{_bindir}/mkrsa.sh
%attr(0755,root,root) %{_bindir}/mkhost.sh
%attr(0755,root,root) %{_bindir}/setdev.sh
%attr(0755,root,root) %{_sbindir}/suvad
%attr(0755,root,root) %{_sbindir}/suvad-server
%if "0%{dist}" == "0.v6"
%attr(0755,root,root) %{_sysconfdir}/init.d/suvad-server
%endif
#%config(noreplace) %attr(0600,suva,suva) %{_sysconfdir}/suvad.conf

# Client files
%files client
%defattr(-,root,root)
%attr(0755,suva,suva) %{_var}/run/suvad
%dir %attr(0750,suva,suva) %{_var}/lib/suva
%dir %attr(0750,suva,suva) %{_var}/lib/suva/clearcenter.com
%attr(0755,root,root) %{_bindir}/mkhost.sh
%attr(0755,root,root) %{_bindir}/setdev.sh
%attr(0755,root,root) %{_bindir}/setkey.sh
%attr(0755,root,root) %{_sbindir}/suvad
%if "0%{dist}" == "0.v6"
%attr(0755,root,root) %{_sysconfdir}/init.d/suvad
%else
%attr(755,root,root) /lib/systemd/system
%attr(755,root,root) %{_tmpfilesdir}
%endif
%config(noreplace) %attr(0600,suva,suva) %{_sysconfdir}/suvad.conf

# Server files
%files server
%defattr(-,root,root)
%attr(0755,suva,suva) %{_var}/run/suvad
%dir %attr(0755,suva,suva) %{_var}/lib/suva
%dir %attr(0750,suva,suva) %{_var}/lib/suva/clearcenter.com
%{_libdir}/libscl.so
%{_libdir}/libscl.so.0
%{_libdir}/libscl.so.0.0.0
%{_libdir}/libscl.a
%{_libdir}/libscl.la
%{_libdir}/libisfd.so
%{_libdir}/libisfd.so.0
%{_libdir}/libisfd.so.0.0.0
%{_libdir}/libisfd.a
%{_libdir}/libisfd.la
%attr(0755,root,root) %{_bindir}/mkrsa.sh
%attr(0755,root,root) %{_sbindir}/suvad-server
#%attr(0755,root,root) %{_sysconfdir}/init.d/suvad-server
#%config(noreplace) %attr(0600,suva,suva) %{_sysconfdir}/suvad.conf

# Developer files
%files devel
%defattr(-,root,root)
%{_includedir}/sfd.h

# vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
