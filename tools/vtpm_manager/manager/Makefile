XEN_ROOT = ../../..
include $(XEN_ROOT)/tools/vtpm_manager/Rules.mk

BIN		= vtpm_managerd

all: build

build: $(BIN)

install: build
	if [ ! -d "$(DESTDIR)/var/vtpm/fifos" ]; \
		then mkdir -p $(DESTDIR)/var/vtpm/fifos; \
	fi
	$(INSTALL_PROG) $(BIN) $(TOOLS_INSTALL_DIR)

clean:
	rm -f *.a *.so *.o *.rpm $(DEP_FILES)

mrproper: clean
	rm -f $(BIN) *~

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ $(LIBS) -o $@

# libraries
LIBS += ../tcs/libTCS.a ../util/libTCGUtils.a ../crypto/libtcpaCrypto.a
LIBS += -lcrypto -lpthread -lm
