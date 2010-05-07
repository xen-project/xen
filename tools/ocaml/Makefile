XEN_ROOT = ../..
include $(XEN_ROOT)/tools/Rules.mk

SUBDIRS_LIBS = \
	libs/uuid libs/mmap \
	libs/log libs/xc libs/eventchn \
	libs/xb libs/xs

SUBDIRS_PROGRAMS = xenstored

SUBDIRS = $(SUBDIRS_LIBS) $(SUBDIRS_PROGRAMS)

.PHONY: all
all: build

.PHONY: build
build: SUBDIRS

.PHONY: SUBDIRS SUBDIRS_PROGRAMS SUBDIRS_LIBS
SUBDIRS SUBDIRS_PROGRAMS SUBDIRS_LIBS:
	@set -e; for d in $($@); do			\
		echo " === building $$d";		\
		$(MAKE) --no-print-directory -C $$d;	\
	done

.PHONY: install install-libs install-program
install: install-libs install-program

install-program: SUBDIRS_PROGRAMS
	$(INSTALL_DIR) $(DESTDIR)$(SBINDIR)
	$(INSTALL_PROG) xenstored/oxenstored $(DESTDIR)$(SBINDIR)

install-libs: SUBDIRS_LIBS

.PHONY: clean
clean:
	@for dir in $(SUBDIRS); do \
		$(MAKE) --no-print-directory -C $$dir clean; \
	done
