XEN_ROOT=../../..
include $(XEN_ROOT)/tools/Rules.mk
XEN_LIBXC          = $(XEN_ROOT)/tools/libxc

LIBXC_ROOT = $(XEN_ROOT)/tools/libxc
LIBFLASK_ROOT = $(XEN_ROOT)/tools/flask/libflask

PROFILE=#-pg
BASECFLAGS=-Wall -g -Werror
BASECFLAGS+= $(PROFILE)
#BASECFLAGS+= -I$(XEN_ROOT)/tools
BASECFLAGS+= $(CFLAGS_libxenctrl)
BASECFLAGS+= -I$(LIBFLASK_ROOT)/include
BASECFLAGS+= -I.

CFLAGS  += $(BASECFLAGS)
LDLIBS += $(PROFILE) -L$(XEN_LIBXC) -L$(LIBFLASK_ROOT)
TESTDIR  = testsuite/tmp
TESTFLAGS= -DTESTING
TESTENV  = XENSTORED_ROOTDIR=$(TESTDIR) XENSTORED_RUNDIR=$(TESTDIR)

CLIENTS := flask-loadpolicy flask-setenforce flask-getenforce
CLIENTS_SRCS := $(patsubst flask-%,%.c,$(CLIENTS))
CLIENTS_OBJS := $(patsubst flask-%,%.o,$(CLIENTS))

.PHONY: all
all: $(CLIENTS)

$(CLIENTS): flask-%: %.o
	$(CC) $(CFLAGS) $(LDFLAGS) $< $(LOADLIBES) $(LDLIBS) -L. -lflask $(LDLIBS_libxenctrl) -o $@

.PHONY: clean
clean: 
	rm -f *.o *.opic *.so
	rm -f $(CLIENTS)
	$(RM) $(DEPS)

.PHONY: print-dir
print-dir:
	@echo -n tools/flask/utils: 

.PHONY: print-end
print-end:
	@echo

.PHONY: install
install: all
	$(INSTALL_DIR) $(DESTDIR)$(SBINDIR)
	$(INSTALL_PROG) $(CLIENTS) $(DESTDIR)$(SBINDIR)

-include $(DEPS)

# never delete any intermediate files.
.SECONDARY:
