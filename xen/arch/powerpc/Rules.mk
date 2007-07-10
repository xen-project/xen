HAS_PPC64 := y

CC := $(CROSS_COMPILE)gcc
LD := $(CROSS_COMPILE)ld

# These are goodess that applies to all source.
C_WARNINGS := -Wredundant-decls

# _no_ common code can have packed data structures or we are in touble.
C_WARNINGS += -Wpacked

CFLAGS := -m64 -ffreestanding -fno-builtin -fno-common
CFLAGS += -iwithprefix include -Wall -Werror -pipe
CFLAGS += -I$(BASEDIR)/include
CFLAGS += -I$(BASEDIR)/include/asm-powerpc/mach-generic
CFLAGS += -I$(BASEDIR)/include/asm-powerpc/mach-default
CFLAGS += $(C_WARNINGS)
CFLAGS += -msoft-float -O2
CFLAGS-$(debug) += -O0 # last one wins
CFLAGS-$(papr_vterm) += -DPAPR_VDEVICE -DPAPR_VTERM

LDFLAGS += -m elf64ppc

#
# command to embed a binary inside a .o
#
%.o: %.bin
	$(CROSS_COMPILE)objcopy --input-target=binary \
		--output-target=elf64-powerpc \
		--binary-architecture=powerpc \
		--redefine-sym _binary_$*_bin_start=$*_start \
		--redefine-sym _binary_$*_bin_end=$*_end \
		--redefine-sym _binary_$*_bin_size=$*_size \
		$< $@

# Test for at least GCC v3.2.x.
gcc-ver = $(shell $(CC) -dumpversion | sed -e 's/^\(.\)\.\(.\)\.\(.\)/\$(1)/')
ifeq ($(call gcc-ver,1),1)
$(error gcc-1.x.x unsupported - upgrade to at least gcc-3.2.x)
endif
ifeq ($(call gcc-ver,1),2)
$(error gcc-2.x.x unsupported - upgrade to at least gcc-3.2.x)
endif
ifeq ($(call gcc-ver,1),3)
ifeq ($(call gcc-ver,2),0)
$(error gcc-3.0.x unsupported - upgrade to at least gcc-3.2.x)
endif
ifeq ($(call gcc-ver,2),1)
$(error gcc-3.1.x unsupported - upgrade to at least gcc-3.2.x)
endif
endif
