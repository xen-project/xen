XEN_ROOT=$(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS += $(CFLAGS_libxentoollog) $(CFLAGS_libxenevtchn) $(CFLAGS_libxenctrl) $(CFLAGS_libxenstore) $(PTHREAD_CFLAGS) $(CFLAGS_libxencall)
LDLIBS += $(LDLIBS_libxentoollog) $(LDLIBS_libxenevtchn) $(LDLIBS_libxenctrl) $(LDLIBS_libxenstore) $(PTHREAD_LIBS)
LDFLAGS += $(PTHREAD_LDFLAGS)

POLICY   := default

OBJS-y   := file_ops.o
OBJS-y   += xenpaging.o
OBJS-y   += policy_$(POLICY).o
OBJS-y   += pagein.o

CFLAGS   += -Wno-unused

TARGETS := xenpaging

all: $(TARGETS)

xenpaging: $(OBJS-y)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS) $(APPEND_LDFLAGS)

install: all
	$(INSTALL_DIR) -m 0700 $(DESTDIR)$(XEN_PAGING_DIR)
	$(INSTALL_DIR) $(DESTDIR)$(LIBEXEC_BIN)
	$(INSTALL_PROG) $(TARGETS) $(DESTDIR)$(LIBEXEC_BIN)

uninstall:
	rm -f $(addprefix $(DESTDIR)$(LIBEXEC_BIN)/, $(TARGETS))

clean:
	rm -f *.o *~ $(DEPS_RM) TAGS $(TARGETS)

distclean: clean

.PHONY: clean install distclean uninstall

.PHONY: TAGS
TAGS:
	etags -t *.c *.h

-include $(DEPS_INCLUDE)
