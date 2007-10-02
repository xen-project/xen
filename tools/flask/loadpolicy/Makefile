XEN_ROOT=../../..
include $(XEN_ROOT)/tools/Rules.mk
XEN_LIBXC          = $(XEN_ROOT)/tools/libxc

LIBXC_ROOT = $(XEN_ROOT)/tools/libxc
LIBFLASK_ROOT = $(XEN_ROOT)/tools/flask/libflask

PROFILE=#-pg
BASECFLAGS=-Wall -g -Werror
# Make gcc generate dependencies.
BASECFLAGS += -Wp,-MD,.$(@F).d
PROG_DEP = .*.d
BASECFLAGS+= $(PROFILE)
#BASECFLAGS+= -I$(XEN_ROOT)/tools
BASECFLAGS+= -I$(LIBXC_ROOT)
BASECFLAGS+= -I$(LIBFLASK_ROOT)/include
BASECFLAGS+= -I.

CFLAGS  += $(BASECFLAGS)
LDFLAGS += $(PROFILE) -L$(XEN_LIBXC) -L$(LIBFLASK_ROOT)
TESTDIR  = testsuite/tmp
TESTFLAGS= -DTESTING
TESTENV  = XENSTORED_ROOTDIR=$(TESTDIR) XENSTORED_RUNDIR=$(TESTDIR)

CLIENTS := flask-loadpolicy
CLIENTS_SRCS := $(patsubst flask-%,%.c,$(CLIENTS))
CLIENTS_OBJS := $(patsubst flask-%,%.o,$(CLIENTS))

.PHONY: all
all: $(CLIENTS)

$(CLIENTS): flask-%: %.o
	$(CC) $(CFLAGS) $(LDFLAGS) $< $(LOADLIBES) $(LDLIBS) -L. -lflask -lxenctrl -o $@

$(CLIENTS_OBJS): $(CLIENTS_SRCS)
	$(COMPILE.c) -o $@ $<

.PHONY: clean
clean: 
	rm -f *.o *.opic *.so
	rm -f $(CLIENTS)
	$(RM) $(PROG_DEP)

.PHONY: print-dir
print-dir:
	@echo -n tools/flask/loadpolicy: 

.PHONY: print-end
print-end:
	@echo

.PHONY: install
install: all
	$(INSTALL_DIR) -p $(DESTDIR)/usr/sbin
	$(INSTALL_PROG) $(CLIENTS) $(DESTDIR)/usr/sbin

-include $(PROG_DEP)

# never delete any intermediate files.
.SECONDARY:
