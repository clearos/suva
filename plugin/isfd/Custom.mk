PREFIX?=/usr
CFLAGS?=-pipe -g
INCLUDE=-I. -I..
VERSION=0
LDFLAGS=-Wl,-soname
LIBS=
SOURCE=isfd.c
DEPS=$(patsubst %.c,%.d,$(SOURCE))
OBJECTS=$(patsubst %.c,%.o,$(SOURCE))
TARGETS=libisfd.so

all:
	@echo "Compiler: $(CC) $(CFLAGS) $(INCLUDE)"
	@echo "Defines: $(DEFS)"
	@echo "Linker: $(LDFLAGS) $(LIBS)"
	$(MAKE) deps
	$(MAKE) $(TARGETS)

deps: $(SOURCE)
	@echo "[D] $^"
	@$(CC) -MD -E $(CFLAGS) $(INCLUDE) $(DEFS) $^ > /dev/null

-include $(DEPS)

%.o : %.c
	@echo "[C] $@"
	@$(CC) -c $(CFLAGS) -fpic $(INCLUDE) $(DEFS) -o $@ $<

$(TARGETS): $(OBJECTS)
	@echo "[L] $@"
	@$(CC) -shared $(LDFLAGS) -Wl,$@.$(VERSION) $(OBJECTS) $(LIBS) -o $@.$(VERSION).0.0

install: all
	install -d $(PREFIX)/lib
	install $(TARGETS) $(PREFIX)/lib

clean:
	rm -f $(TARGETS).$(VERSION).0.0 *.o *.d

dist-clean:
	$(MAKE) clean

# vi: ts=4
