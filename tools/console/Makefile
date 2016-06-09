XEN_ROOT=$(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS  += -Werror

CFLAGS  += $(CFLAGS_libxenctrl)
CFLAGS  += $(CFLAGS_libxenstore)
LDLIBS += $(LDLIBS_libxenctrl)
LDLIBS += $(LDLIBS_libxenstore)
LDLIBS += $(SOCKET_LIBS)

LDLIBS_xenconsoled += $(UTIL_LIBS)
LDLIBS_xenconsoled += -lrt

BIN      = xenconsoled xenconsole

.PHONY: all
all: $(BIN)

.PHONY: clean
clean:
	$(RM) *.a *.so *.o *.rpm $(BIN) $(DEPS)
	$(RM) client/*.o daemon/*.o
	$(RM) client/_paths.h
	$(RM) daemon/_paths.h

.PHONY: distclean
distclean: clean

daemon/main.o: daemon/_paths.h
daemon/io.o: CFLAGS += $(CFLAGS_libxenevtchn) $(CFLAGS_libxengnttab)
xenconsoled: $(patsubst %.c,%.o,$(wildcard daemon/*.c))
	$(CC) $(LDFLAGS) $^ -o $@ $(LDLIBS) $(LDLIBS_libxenevtchn) $(LDLIBS_libxengnttab) $(LDLIBS_xenconsoled) $(APPEND_LDFLAGS)

client/main.o: client/_paths.h
xenconsole: $(patsubst %.c,%.o,$(wildcard client/*.c))
	$(CC) $(LDFLAGS) $^ -o $@ $(LDLIBS) $(LDLIBS_xenconsole) $(APPEND_LDFLAGS)

genpath-target = $(call buildmakevars2header,client/_paths.h)
$(eval $(genpath-target))

genpath-target = $(call buildmakevars2header,daemon/_paths.h)
$(eval $(genpath-target))

.PHONY: install
install: $(BIN)
	$(INSTALL_DIR) $(DESTDIR)/$(sbindir)
	$(INSTALL_PROG) xenconsoled $(DESTDIR)/$(sbindir)
	$(INSTALL_DIR) $(DESTDIR)$(LIBEXEC_BIN)
	$(INSTALL_PROG) xenconsole $(DESTDIR)$(LIBEXEC_BIN)

-include $(DEPS)
