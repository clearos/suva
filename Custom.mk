PREFIX?=/usr
SYSCONF?=/etc
PIDDIR?=/var/run/suvad
RPMDIR=~/rpms
VER_MAJOR?=3
VER_MINOR?=0
VERSION=$(VER_MAJOR).$(VER_MINOR)
CFLAGS?=-pipe -g -pg -rdynamic
INCLUDE=-I.
LDFLAGS=-L/usr/lib
LIBS=-lpthread -lssl -lcrypto -lexpat -lpopt
CLIENT_LIBS=
SERVER_LIBS=-ldb -lpq
DEFS=-D_SUVA_VERSION=\"$(VERSION)\" -D_SUVA_DEFAULT_DELAY=10 \
	-D_SUVA_ENABLE_BDB=1 -D_SUVA_ENABLE_PGSQL=1 -D_SUVA_ENABLE_MYSQL=1 \
	-D_SUVA_PIDDIR=\"$(PIDDIR)\" -D_SUVA_USE_POPT=1
SOURCE=svconf.cpp svcrypto.cpp svexec.cpp svevent.cpp svkeypoll.cpp \
	svkeyring.cpp svobject.cpp svoutput.cpp svpacket.cpp \
	svplugin.cpp svpool.cpp svservice.cpp svsession.cpp \
	svsignal.cpp svsocket.cpp svthread.cpp svutil.cpp

CXXFLAGS=$(CFLAGS)
DEPS=$(patsubst %.cpp,%.d,$(SOURCE)) svclient.d svserver.d svstorage.d
OBJECTS=$(patsubst %.cpp,%.o,$(SOURCE))
TARGETS=suvad-client suvad-server

all:
	@echo "Compiler: $(CXX) $(CXXFLAGS) $(INCLUDE)"
	@echo "Defines: $(DEFS)"
	@echo "Client libs: $(LDFLAGS) $(LIBS) $(CLIENT_LIBS)"
	@echo "Server libs: $(LDFLAGS) $(LIBS) $(SERVER_LIBS)"
	$(MAKE) deps
	$(MAKE) $(TARGETS)

deps: $(SOURCE) svclient.cpp svserver.cpp
	@echo "[D] $^"
	@$(CXX) -MD -E $(CXXFLAGS) $(INCLUDE) $(DEFS) $^ > /dev/null

-include $(DEPS)

%.o : %.cpp
	@echo "[C] $@"
	@$(CXX) -c $(CXXFLAGS) $(INCLUDE) $(DEFS) -o $@ $<

suvad-client: $(OBJECTS) svclient.o Makefile
	@echo "[L] $@"
	@$(CXX) $(CXXFLAGS) $(INCLUDE) $(DEFS) $(LDFLAGS) svclient.o \
		$(OBJECTS) $(LIBS) $(CLIENT_LIBS) -o $@

suvad-server: $(OBJECTS) svserver.o svstorage.o Makefile
	@echo "[L] $@"
	@$(CXX) $(CXXFLAGS) $(INCLUDE) $(DEFS) $(LDFLAGS) svserver.o \
		svstorage.o $(OBJECTS) $(LIBS) $(SERVER_LIBS) -o $@

suva.spec: suva.spec.in
	@sed -e "s|@RPM_BINDIR@|$(PREFIX)/bin|g" -e "s|@RPM_INCLUDEDIR@|$(PREFIX)/include|g" \
		-e "s|@RPM_LIBDIR@|$(PREFIX)/lib|g" -e "s|@RPM_SBINDIR@|$(PREFIX)/sbin|g" \
		-e "s|@RPM_SYSCONFDIR@|$(SYSCONF)|g" -e "s|@RPM_VERSION@|$(VERSION)|g" \
		suva.spec.in > suva.spec

rpm: suva.spec
	(cd .. && rm -f suva-$(VERSION))
	(PWD=`pwd` cd .. && ln -sf $(PWD) suva-$(VERSION))
	(PWD=`pwd` cd .. && tar --exclude "\.svn" -cvhzf suva-$(VERSION).tar.gz \
		suva-$(VERSION) && mv suva-$(VERSION).tar.gz $(PWD))
	mv suva-$(VERSION).tar.gz $(RPMDIR)/SOURCES
	rpmbuild -ba suva.spec

install: all
	install -d $(SYSCONF)
	install -d $(PREFIX)/sbin
	install -d $(PIDDIR)
	install $(TARGETS) $(PREFIX)/sbin

clean:
	rm -f $(TARGETS) *.o *.d suva.spec gmon.out

dist-clean:
	$(MAKE) clean
	$(MAKE) -C plugin/scl clean
	$(MAKE) -C plugin/isfd clean

# vi: ts=4
