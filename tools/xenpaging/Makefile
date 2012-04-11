XEN_ROOT=$(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS += $(CFLAGS_libxenctrl) $(CFLAGS_libxenstore) $(PTHREAD_CFLAGS)
LDLIBS += $(LDLIBS_libxenctrl) $(LDLIBS_libxenstore) $(PTHREAD_LIBS)
LDFLAGS += $(PTHREAD_LDFLAGS)

POLICY    = default

SRC      :=
SRCS     += file_ops.c xenpaging.c policy_$(POLICY).c
SRCS     += pagein.c

CFLAGS   += -Werror
CFLAGS   += -Wno-unused
CFLAGS   += -g

OBJS     = $(SRCS:.c=.o)
IBINS    = xenpaging

all: $(IBINS)

xenpaging: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS) $(APPEND_LDFLAGS)

install: all
	$(INSTALL_DIR) $(DESTDIR)$(XEN_PAGING_DIR)
	$(INSTALL_DIR) $(DESTDIR)$(LIBEXEC)
	$(INSTALL_PROG) $(IBINS) $(DESTDIR)$(LIBEXEC)

clean:
	rm -f *.o *~ $(DEPS) xen TAGS $(IBINS) $(LIB)

.PHONY: clean install

.PHONY: TAGS
TAGS:
	etags -t $(SRCS) *.h

-include $(DEPS)
