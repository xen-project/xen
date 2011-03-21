XEN_ROOT=$(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

LIBFLASK_ROOT = $(XEN_ROOT)/tools/flask/libflask

PROFILE=#-pg
BASECFLAGS=-Wall -g -Werror
BASECFLAGS+= $(PROFILE)
BASECFLAGS+= $(CFLAGS_libxenctrl)
BASECFLAGS+= -I$(LIBFLASK_ROOT)/include

CFLAGS  += $(BASECFLAGS)
LDLIBS += $(PROFILE)
TESTDIR  = testsuite/tmp
TESTFLAGS= -DTESTING
TESTENV  = XENSTORED_ROOTDIR=$(TESTDIR) XENSTORED_RUNDIR=$(TESTDIR)

CLIENTS := flask-loadpolicy flask-setenforce flask-getenforce
CLIENTS_SRCS := $(patsubst flask-%,%.c,$(CLIENTS))
CLIENTS_OBJS := $(patsubst flask-%,%.o,$(CLIENTS))

.PHONY: all
all: $(CLIENTS)

$(CLIENTS): flask-%: %.o
	$(CC) $(CFLAGS) $(LDFLAGS) $< $(LOADLIBES) $(LDLIBS) -L$(LIBFLASK_ROOT) -lflask $(LDLIBS_libxenctrl) -o $@

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
