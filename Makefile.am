AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

noinst_LIBRARIES = libsuva.a
libsuva_a_SOURCES = svconf.cpp svcrypto.cpp svexec.cpp \
	svevent.cpp svkeypoll.cpp svkeyring.cpp svobject.cpp \
	svoutput.cpp svpacket.cpp svplugin.cpp svpool.cpp \
	svservice.cpp svsession.cpp svsignal.cpp svsocket.cpp \
	svthread.cpp svutil.cpp suva.spec

sbin_PROGRAMS = suvad suvad-server

suvad_SOURCES = svclient.cpp
if USE_RESOURCES_RC
suvad_DEPENDENCIES = libsuva.a resources.o
suvad_LDADD = libsuva.a resources.o $(EXTRA_LIBS)
else
suvad_LDADD = libsuva.a $(EXTRA_LIBS)
endif
suvad_server_SOURCES = svstorage.cpp svserver.cpp
suvad_server_LDADD = libsuva.a $(SERVER_LIBS)

EXTRA_DIST = autogen.sh svclient.h svconf.h svcrypto.h svevent.h svexec.h svkeypoll.h svkeyring.h svobject.h svoutput.h svpacket.h svplugin.h svpool.h svserver.h svservice.h svsession.h svsignal.h svsocket.h svstorage.h svthread.h svutil.h deploy/init.d/suvad-server deploy/init.d/suvad deploy/init.d/suvad.gentoo deploy/suvad.conf deploy/suvad-server.conf deploy/tmpfiles.d/suvad.conf deploy/systemd/suvad.service deploy/systemd/suvad-server.service plugin/isfd/isfd.c plugin/isfd/Makefile.am plugin/isfd/Makefile.in plugin/sfd.h plugin/scl/scl.c plugin/scl/Makefile.am plugin/scl/Makefile.in plugin/Makefile.am plugin/Makefile.in util/scripts/setkey.sh util/scripts/mkrsa.sh util/scripts/rotate.sh util/scripts/setdev.sh util/scripts/mkhost.sh

doxygen::
	doxygen ./doc/doxygen.conf

resources.o: resources.rc
	$(WINDRES) $< $@

# vi: ts=4
