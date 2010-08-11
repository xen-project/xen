XEN_ROOT=../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS   += -I $(XEN_XC)
CFLAGS   += -I ./
CFLAGS   += $(CFLAGS_libxenctrl) $(CFLAGS_libxenstore)
LDLIBS  += $(LDLIBS_libxenctrl) $(LDLIBS_libxenstore)

POLICY    = default

SRC      :=
SRCS     += file_ops.c xc.c xenpaging.c policy_$(POLICY).c

CFLAGS   += -Werror
CFLAGS   += -Wno-unused
CFLAGS   += -g

CFLAGS   += -Wp,-MD,.$(@F).d
DEPS     = .*.d

OBJS     = $(SRCS:.c=.o)
IBINS    = xenpaging

all: $(IBINS)

xenpaging: $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

install: all
	$(INSTALL_DIR) $(DESTDIR)$(SBINDIR)
	$(INSTALL_PROG) $(IBINS) $(DESTDIR)$(SBINDIR)

clean:
	rm -f *.o *~ $(DEPS) xen TAGS $(IBINS) $(LIB)

.PHONY: clean install

.PHONY: TAGS
TAGS:
	etags -t $(SRCS) *.h

-include $(DEPS)
