
include $(BASEDIR)/Rules.mk

ifneq ($(debugger),y)
OBJS := $(subst pdb-linux.o,,$(OBJS))
OBJS := $(subst pdb-stub.o,,$(OBJS))
endif

OBJS += $(patsubst %.S,%.o,$(wildcard $(TARGET_SUBARCH)/*.S))
OBJS += $(patsubst %.c,%.o,$(wildcard $(TARGET_SUBARCH)/*.c))
OBJS += $(patsubst %.c,%.o,$(wildcard mtrr/*.c))

OBJS := $(subst $(TARGET_SUBARCH)/asm-offsets.o,,$(OBJS))

ifneq ($(TARGET_SUBARCH),i386)
OBJS := $(subst vmx.o,,$(OBJS))
OBJS := $(subst vmx_io.o,,$(OBJS))
OBJS := $(subst vmx_vmcs.o,,$(OBJS))
endif ($(TARGET_SUBARCH),i386)

default: boot/$(TARGET_SUBARCH).o $(OBJS) boot/mkelf32
	$(LD) $(LDFLAGS) -r -o arch.o $(OBJS)
	$(LD) $(LDFLAGS) -T $(TARGET_SUBARCH)/xen.lds -N \
	    boot/$(TARGET_SUBARCH).o $(ALL_OBJS) -o $(TARGET)-syms
	./boot/mkelf32 $(TARGET)-syms $(TARGET) 0x100000

asm-offsets.s: $(TARGET_SUBARCH)/asm-offsets.c
	$(CC) $(CFLAGS) -S -o $@ $<

boot/mkelf32: boot/mkelf32.c
	$(HOSTCC) $(HOSTCFLAGS) -o $@ $<

clean:
	rm -f *.o *.s *~ core boot/*.o boot/*~ boot/core boot/mkelf32
	rm -f x86_32/*.o x86_32/*~ x86_32/core
	rm -f x86_64/*.o x86_64/*~ x86_64/core

.PHONY: default clean
