
include $(BASEDIR)/Rules.mk

ifneq ($(debugger),y)
OBJS := $(subst pdb-linux.o,,$(OBJS))
OBJS := $(subst pdb-stub.o,,$(OBJS))
endif

OBJS += $(patsubst %.S,%.o,$(wildcard $(TARGET_SUBARCH)/*.S))
OBJS += $(patsubst %.c,%.o,$(wildcard $(TARGET_SUBARCH)/*.c))

ifeq ($(TARGET_SUBARCH),x86_32)
LINK_BASE := 0xFC500000 # Xen is linked here
LOAD_BASE := 0x00100000 # Xen is loaded here
endif

ifeq ($(TARGET_SUBARCH),x86_64)
LINK_BASE := 0xFFFF830000100000 # Xen is linked here
LOAD_BASE := 0x0000000000100000 # Xen is loaded here
endif

# What happens here? We link object files together, starting at LINK_BASE
# (a very high address). But the bootloader cannot put things there, so we
# initially load at LOAD_BASE. A tool called `elf-reloc' is used to modify
# segment offsets from LINK_BASE-relative to LOAD_BASE-relative.
# (NB. Linux gets round this by turning its image into raw binary, then 
# wrapping that with a low-memory bootstrapper.)
default: boot/$(TARGET_SUBARCH).o $(OBJS)
	$(LD) $(LDFLAGS) -r -o arch.o $(OBJS)
	$(LD) $(LDFLAGS) -T $(TARGET_SUBARCH)/xen.lds -N \
	    boot/$(TARGET_SUBARCH).o $(ALL_OBJS) -o $(TARGET)-syms
	objcopy -R .note -R .comment -S $(TARGET)-syms $(TARGET)
	$(BASEDIR)/tools/elf-reloc $(LINK_BASE) $(LOAD_BASE) $(TARGET)

clean:
	rm -f *.o *~ core boot/*.o boot/*~ boot/core
	rm -f $(TARGET_SUBARCH)/*.o $(TARGET_SUBARCH)/*~
	rm -f $(TARGETSUBARCH)/core
