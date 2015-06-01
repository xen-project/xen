XEN_ROOT=$(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

# xenpaging.c and file_ops.c incorrectly use libxc internals
CFLAGS += $(CFLAGS_libxentoollog) $(CFLAGS_libxenevtchn) $(CFLAGS_libxenctrl) $(CFLAGS_libxenstore) $(PTHREAD_CFLAGS) -I$(XEN_ROOT)/tools/libxc $(CFLAGS_libxencall)
LDLIBS += $(LDLIBS_libxentoollog) $(LDLIBS_libxenevtchn) $(LDLIBS_libxenctrl) $(LDLIBS_libxenstore) $(PTHREAD_LIBS)
LDFLAGS += $(PTHREAD_LDFLAGS)

POLICY    = default

SRC      :=
SRCS     += file_ops.c xenpaging.c policy_$(POLICY).c
SRCS     += pagein.c

CFLAGS   += -Werror
CFLAGS   += -Wno-unused

OBJS     = $(SRCS:.c=.o)
IBINS    = xenpaging

all: $(IBINS)

xenpaging: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS) $(APPEND_LDFLAGS)

install: all
	$(INSTALL_DIR) -m 0700 $(DESTDIR)$(XEN_PAGING_DIR)
	$(INSTALL_DIR) $(DESTDIR)$(LIBEXEC_BIN)
	$(INSTALL_PROG) $(IBINS) $(DESTDIR)$(LIBEXEC_BIN)

clean:
	rm -f *.o *~ $(DEPS) xen TAGS $(IBINS) $(LIB)

distclean: clean

.PHONY: clean install distclean

.PHONY: TAGS
TAGS:
	etags -t $(SRCS) *.h

-include $(DEPS)
