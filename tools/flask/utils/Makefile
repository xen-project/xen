XEN_ROOT=$(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

LIBFLASK_ROOT = $(XEN_ROOT)/tools/flask/libflask

CFLAGS += -Wall -g -Werror
CFLAGS += $(CFLAGS_libxenctrl)
CFLAGS += -I$(LIBFLASK_ROOT)/include

TESTDIR  = testsuite/tmp
TESTFLAGS= -DTESTING
TESTENV  = XENSTORED_ROOTDIR=$(TESTDIR) XENSTORED_RUNDIR=$(TESTDIR)

CLIENTS := flask-loadpolicy flask-setenforce flask-getenforce flask-label-pci flask-get-bool flask-set-bool
CLIENTS_SRCS := $(patsubst flask-%,%.c,$(CLIENTS))
CLIENTS_OBJS := $(patsubst flask-%,%.o,$(CLIENTS))

.PHONY: all
all: $(CLIENTS)

flask-loadpolicy: loadpolicy.o
	$(CC) $(LDFLAGS) $< $(LDLIBS) -L$(LIBFLASK_ROOT) -lflask $(LDLIBS_libxenctrl) -o $@

flask-setenforce: setenforce.o
	$(CC) $(LDFLAGS) $< $(LDLIBS) -L$(LIBFLASK_ROOT) -lflask $(LDLIBS_libxenctrl) -o $@

flask-getenforce: getenforce.o
	$(CC) $(LDFLAGS) $< $(LDLIBS) -L$(LIBFLASK_ROOT) -lflask $(LDLIBS_libxenctrl) -o $@

flask-label-pci: label-pci.o
	$(CC) $(LDFLAGS) $< $(LDLIBS) -L$(LIBFLASK_ROOT) -lflask $(LDLIBS_libxenctrl) -o $@

flask-get-bool: get-bool.o
	$(CC) $(LDFLAGS) $< $(LDLIBS) -L$(LIBFLASK_ROOT) -lflask $(LDLIBS_libxenctrl) -o $@

flask-set-bool: set-bool.o
	$(CC) $(LDFLAGS) $< $(LDLIBS) -L$(LIBFLASK_ROOT) -lflask $(LDLIBS_libxenctrl) -o $@

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
