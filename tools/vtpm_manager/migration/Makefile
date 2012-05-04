XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/vtpm_manager/Rules.mk

VPATH = ../manager

BIND		= vtpm_migratord
BINC		= vtpm_migrator

SRCSD    = vtpm_manager_if.c vtpm_migratord.c vtpm_migratord_handler.c vtpm_ipc.c
SRCSC    = vtpm_manager_if.c vtpm_migrator_if.c vtpm_migratorc.c vtpm_ipc.c

OBJSD    = $(patsubst %.c,%.o,$(SRCSD))
OBJSC    = $(patsubst %.c,%.o,$(SRCSC))

.PHONY: all
all: build

.PHONY: build
build: $(BIND) $(BINC)

.PHONY: install
install: build
	$(INSTALL_PROG) $(BIND) $(DESTDIR)$(BINDIR)
	$(INSTALL_PROG) $(BINC) $(DESTDIR)$(BINDIR)

.PHONY: clean
clean:
	rm -f $(BINC) $(BIND)
	rm -f *.a *.so *.o *.rpm $(DEP_FILES)

.PHONY: mrproper
mrproper: clean
	rm -f *~

$(BIND): $(OBJSD)
	$(CC) $(LDFLAGS) $^ $(LIBS) -o $@

$(BINC): $(OBJSC)
	$(CC) $(LDFLAGS) $^ $(LIBS) -o $@

# libraries
LIBS += ../util/libTCGUtils.a
