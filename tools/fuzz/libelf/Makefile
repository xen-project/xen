XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

# libelf fuzz target
vpath %.c ../../../xen/common/libelf
CFLAGS += -I../../../xen/common/libelf
ELF_SRCS-y += libelf-tools.c libelf-loader.c libelf-dominfo.c
ELF_LIB_OBJS := $(patsubst %.c,%.o,$(ELF_SRCS-y))

$(patsubst %.c,%.o,$(ELF_SRCS-y)): CFLAGS += -Wno-pointer-sign

$(ELF_LIB_OBJS): CFLAGS += -DFUZZ_NO_LIBXC $(CFLAGS_xeninclude)

libelf-fuzzer.o: CFLAGS += $(CFLAGS_xeninclude)

libelf.a: libelf-fuzzer.o $(ELF_LIB_OBJS)
	$(AR) rc $@ $^

.PHONY: libelf-fuzzer-all
libelf-fuzzer-all: libelf.a libelf-fuzzer.o

afl-libelf-fuzzer: afl-libelf-fuzzer.o libelf-fuzzer.o $(ELF_LIB_OBJS)
	$(CC) $(CFLAGS) $^ -o $@

# Common targets
.PHONY: all
all: libelf-fuzzer-all

.PHONY: distclean
distclean: clean

.PHONY: clean
clean:
	rm -f *.o .*.d *.a *-libelf-fuzzer

.PHONY: install
install: all

.PHONY: uninstall

.PHONY: afl
afl: afl-libelf-fuzzer
