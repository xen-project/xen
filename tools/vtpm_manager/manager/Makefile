XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/vtpm_manager/Rules.mk

BIN		= vtpm_managerd

.PHONY: all
all: build

.PHONY: build
build: $(BIN)

.PHONY: install
install: build
	if [ ! -d "$(DESTDIR)/var/vtpm/fifos" ]; \
		then mkdir -p $(DESTDIR)/var/vtpm/fifos; \
	fi
	if [ ! -d "$(DESTDIR)/var/vtpm/socks" ]; \
		then mkdir -p $(DESTDIR)/var/vtpm/socks; \
	fi
	$(INSTALL_PROG) $(BIN) $(DESTDIR)$(BINDIR)

.PHONY: clean
clean:
	rm -f $(BIN)
	rm -f *.a *.so *.o *.rpm $(DEP_FILES)

.PHONY: mrproper
mrproper: clean
	rm -f *~

$(BIN): $(OBJS)
	$(CC) $(LDFLAGS) $^ $(LIBS) -o $@

# libraries
LIBS += ../tcs/libTCS.a ../util/libTCGUtils.a ../crypto/libtcpaCrypto.a
LIBS += -lcrypto $(PTHREAD_LIBS) -lm
CFLAGS += $(PTHREAD_CFLAGS)
LDFLAGS += $(PTHREAD_LDFLAGS)
