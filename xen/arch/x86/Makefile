
include $(BASEDIR)/Rules.mk

ifneq ($(debugger),y)
OBJS := $(subst pdb-linux.o,,$(OBJS))
OBJS := $(subst pdb-stub.o,,$(OBJS))
endif

LINK_BASE := 0xFC500000 # Xen is linked here
LOAD_BASE := 0x00100000 # Xen is loaded here

# What happens here? We link object files together, starting at LINK_BASE
# (a very high address). But the bootloader cannot put things there, so we
# initially load at LOAD_BASE. A tool called `elf-reloc' is used to modify
# segment offsets from LINK_BASE-relative to LOAD_BASE-relative.
# (NB. Linux gets round this by turning its image into raw binary, then 
# wrapping that with a low-memory bootstrapper.)
default: boot/boot.o $(OBJS)
	$(LD) -r -o arch.o $(OBJS)
	$(LD) $(LDFLAGS) boot/boot.o $(ALL_OBJS) -o $(TARGET)-syms
	objcopy -R .note -R .comment -S $(TARGET)-syms $(TARGET)
	$(BASEDIR)/tools/elf-reloc $(LINK_BASE) $(LOAD_BASE) $(TARGET)

clean:
	rm -f *.o *~ core boot/*.o boot/*~ boot/core
