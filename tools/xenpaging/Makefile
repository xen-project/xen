XEN_ROOT=../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS   += -I $(XEN_XC)
CFLAGS   += -I ./
CFLAGS   += $(CFLAGS_libxenctrl) $(CFLAGS_libxenstore)
LDFLAGS  += $(LDFLAGS_libxenctrl) $(LDFLAGS_libxenstore)

POLICY    = default

SRC      :=
SRCS     += file_ops.c xc.c xenpaging.c policy_$(POLICY).c

CFLAGS   += -Werror
CFLAGS   += -Wno-unused
CFLAGS   += -g

#CFLAGS   += -Wl,-rpath,..
CFLAGS   += -Wp,-MD,.$(@F).d
DEPS     = .*.d

#LDFLAGS  += $(LDFLAGS_libxenctrl) $(LDFLAGS_libxenguest)

OBJS     = $(SRCS:.c=.o)
IBINS    = xenpaging

all: $(IBINS)

xenpaging: $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

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
