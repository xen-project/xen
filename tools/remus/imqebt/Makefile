# ebtables Makefile (reworked for Remus IMQ control)

XEN_ROOT=../../..
include $(XEN_ROOT)/tools/Rules.mk

PROGNAME:=ebtables
PROGRELEASE:=1
PROGVERSION_:=2.0.9
PROGVERSION:=$(PROGVERSION_)-$(PROGRELEASE)
PROGDATE:=June\ 2009

ifeq ($(shell uname -m),sparc64)
CFLAGS+=-DEBT_MIN_ALIGN=8 -DKERNEL_64_USERSPACE_32
endif

include extensions/Makefile

OBJECTS2:=getethertype.o communication.o libebtc.o \
useful_functions.o ebtables.o

OBJECTS:=$(OBJECTS2) $(EXT_OBJS) $(EXT_LIBS)

KERNEL_INCLUDES?=include/

ETHERTYPESPATH?=$(ETCDIR)
ETHERTYPESFILE:=$(ETHERTYPESPATH)/ethertypes

PIPE_DIR?=/tmp/$(PROGNAME)-v$(PROGVERSION)
PIPE=$(PIPE_DIR)/ebtablesd_pipe
EBTD_CMDLINE_MAXLN?=2048
EBTD_ARGC_MAX?=50

PROGSPECS:=-DPROGVERSION=\"$(PROGVERSION)\" \
	-DPROGNAME=\"$(PROGNAME)\" \
	-DPROGDATE=\"$(PROGDATE)\" \
	-D_PATH_ETHERTYPES=\"$(ETHERTYPESFILE)\" \
	-DEBTD_ARGC_MAX=$(EBTD_ARGC_MAX) \
	-DEBTD_CMDLINE_MAXLN=$(EBTD_CMDLINE_MAXLN)

# Uncomment for debugging (slower)
#PROGSPECS+=-DEBT_DEBUG
#CFLAGS+=-ggdb

PROGRAMS = imqebt

.PHONY: all
all: build

.PHONY: build
build: $(PROGRAMS)

# a little scripting for a static binary, making one for ebtables-restore
# should be completely analogous
imqebt: extensions/ebt_*.c extensions/ebtable_*.c ebtables.c communication.c ebtables-standalone.c getethertype.c libebtc.c useful_functions.c
	cp ebtables-standalone.c ebtables-standalone.c_ ; \
	cp include/ebtables_u.h include/ebtables_u.h_ ; \
	sed "s/ main(/ pseudomain(/" ebtables-standalone.c > ebtables-standalone.c__ ; \
	mv ebtables-standalone.c__ ebtables-standalone.c ; \
	printf "\nint main(int argc, char *argv[])\n{\n "  >> ebtables-standalone.c ; \
	for arg in $(EXT_FUNC) \
	; do \
	sed s/_init/_$${arg}_init/ extensions/ebt_$${arg}.c > extensions/ebt_$${arg}.c_ ; \
	mv extensions/ebt_$${arg}.c_ extensions/ebt_$${arg}.c ; \
	printf "\t%s();\n" _$${arg}_init >> ebtables-standalone.c ; \
	printf "extern void %s(void);\n" _$${arg}_init >> include/ebtables_u.h ; \
	done ; \
	for arg in $(EXT_TABLES) \
	; do \
	sed s/_init/_t_$${arg}_init/ extensions/ebtable_$${arg}.c > extensions/ebtable_$${arg}.c_ ; \
	mv extensions/ebtable_$${arg}.c_ extensions/ebtable_$${arg}.c ; \
	printf "\t%s();\n" _t_$${arg}_init >> ebtables-standalone.c ; \
	printf "extern void %s(void);\n" _t_$${arg}_init >> include/ebtables_u.h ; \
	done ; \
	printf "\n\tpseudomain(argc, argv);\n\treturn 0;\n}\n" >> ebtables-standalone.c ;\
	$(CC) $(CFLAGS) $(PROGSPECS) -o $@ $^ -I$(KERNEL_INCLUDES) -Iinclude ; \
	for arg in $(EXT_FUNC) \
	; do \
	sed "s/ .*_init/ _init/" extensions/ebt_$${arg}.c > extensions/ebt_$${arg}.c_ ; \
	mv extensions/ebt_$${arg}.c_ extensions/ebt_$${arg}.c ; \
	done ; \
	for arg in $(EXT_TABLES) \
	; do \
	sed "s/ .*_init/ _init/" extensions/ebtable_$${arg}.c > extensions/ebtable_$${arg}.c_ ; \
	mv extensions/ebtable_$${arg}.c_ extensions/ebtable_$${arg}.c ; \
	done ; \
	mv ebtables-standalone.c_ ebtables-standalone.c ; \
	mv include/ebtables_u.h_ include/ebtables_u.h

.PHONY: install
install: build
	$(INSTALL_DIR) $(DESTDIR)$(PRIVATE_BINDIR)
	$(INSTALL_PROG) $(PROGRAMS) $(DESTDIR)$(PRIVATE_BINDIR)

.PHONY: clean
clean:
	rm -f imqebt
	rm -f *.o *~ *.so
