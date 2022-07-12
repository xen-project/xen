XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

LIBELF_OBJS := libelf-tools.o libelf-loader.o libelf-dominfo.o

CFLAGS += -iquote ../../../xen/common/libelf
$(LIBELF_OBJS): CFLAGS += -Wno-pointer-sign
$(LIBELF_OBJS): CFLAGS += -DFUZZ_NO_LIBXC $(CFLAGS_xeninclude)

libelf-fuzzer.o: CFLAGS += $(CFLAGS_xeninclude)

$(LIBELF_OBJS:.o=.c): libelf-%.c: ../../../xen/common/libelf/libelf-%.c FORCE
	ln -nsf $< $@

libelf.a: libelf-fuzzer.o $(LIBELF_OBJS)
	$(AR) rc $@ $^

.PHONY: libelf-fuzzer-all
libelf-fuzzer-all: libelf.a libelf-fuzzer.o

afl-libelf-fuzzer: afl-libelf-fuzzer.o libelf-fuzzer.o $(LIBELF_OBJS)
	$(CC) $(CFLAGS) $^ -o $@

# Common targets
.PHONY: all
all: libelf-fuzzer-all

.PHONY: distclean
distclean: clean

.PHONY: clean
clean:
	rm -f *.o .*.d *.a *-libelf-fuzzer $(LIBELF_OBJS:.o=.c)

.PHONY: install
install: all

.PHONY: uninstall

.PHONY: afl
afl: afl-libelf-fuzzer
