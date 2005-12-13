
include $(BASEDIR)/Rules.mk

OBJS += $(patsubst %.S,%.o,$(wildcard $(TARGET_SUBARCH)/*.S))
OBJS += $(patsubst %.c,%.o,$(wildcard $(TARGET_SUBARCH)/*.c))
OBJS += $(patsubst %.c,%.o,$(wildcard acpi/*.c))
OBJS += $(patsubst %.c,%.o,$(wildcard dm/*.c))
OBJS += $(patsubst %.c,%.o,$(wildcard mtrr/*.c))
OBJS += $(patsubst %.c,%.o,$(wildcard genapic/*.c))
OBJS += $(patsubst %.c,%.o,$(wildcard cpu/*.c))

ifeq ($(TARGET_SUBARCH),x86_64) 
OBJS := $(subst cpu/centaur.o,,$(OBJS))
OBJS := $(subst cpu/cyrix.o,,$(OBJS))
OBJS := $(subst cpu/rise.o,,$(OBJS))
OBJS := $(subst cpu/transmeta.o,,$(OBJS))
endif

OBJS := $(patsubst shadow%.o,,$(OBJS))	# drop all
ifeq ($(TARGET_SUBARCH),x86_64) 
 OBJS += shadow.o shadow_public.o shadow_guest32.o	# x86_64: new code
endif
ifeq ($(TARGET_SUBARCH),x86_32) 
 ifneq ($(pae),n)
  OBJS += shadow.o shadow_public.o	# x86_32p: new code
 else
  OBJS += shadow32.o			# x86_32: old code
 endif
endif

OBJS := $(subst $(TARGET_SUBARCH)/asm-offsets.o,,$(OBJS))

ifneq ($(crash_debug),y)
OBJS := $(patsubst cdb%.o,,$(OBJS))
endif

default: $(TARGET)

$(TARGET): $(TARGET)-syms boot/mkelf32
	./boot/mkelf32 $(TARGET)-syms $(TARGET) 0x100000 \
	`nm $(TARGET)-syms | sort | tail -n 1 | sed -e 's/^\([^ ]*\).*/0x\1/'`

$(CURDIR)/arch.o: $(OBJS)
	$(LD) $(LDFLAGS) -r -o $@ $(OBJS)

$(TARGET)-syms: boot/$(TARGET_SUBARCH).o $(ALL_OBJS) $(TARGET_SUBARCH)/xen.lds
	$(LD) $(LDFLAGS) -T $(TARGET_SUBARCH)/xen.lds -N \
	    boot/$(TARGET_SUBARCH).o $(ALL_OBJS) -o $@
	$(NM) -n $@ | $(BASEDIR)/tools/symbols >$(BASEDIR)/xen-syms.S
	$(MAKE) $(BASEDIR)/xen-syms.o
	$(LD) $(LDFLAGS) -T $(TARGET_SUBARCH)/xen.lds -N \
	    boot/$(TARGET_SUBARCH).o $(ALL_OBJS) $(BASEDIR)/xen-syms.o -o $@
	$(NM) -n $@ | $(BASEDIR)/tools/symbols >$(BASEDIR)/xen-syms.S
	$(MAKE) $(BASEDIR)/xen-syms.o
	$(LD) $(LDFLAGS) -T $(TARGET_SUBARCH)/xen.lds -N \
	    boot/$(TARGET_SUBARCH).o $(ALL_OBJS) $(BASEDIR)/xen-syms.o -o $@
	rm -f $(BASEDIR)/xen-syms.S $(BASEDIR)/xen-syms.o

asm-offsets.s: $(TARGET_SUBARCH)/asm-offsets.c $(HDRS)
	$(CC) $(CFLAGS) -S -o $@ $<

boot/mkelf32: boot/mkelf32.c
	$(HOSTCC) $(HOSTCFLAGS) -o $@ $<

shadow_guest32.o: shadow.c

clean:
	rm -f *.o *.s *~ core boot/*.o boot/*~ boot/core boot/mkelf32
	rm -f x86_32/*.o x86_32/*~ x86_32/core
	rm -f x86_64/*.o x86_64/*~ x86_64/core
	rm -f mtrr/*.o mtrr/*~ mtrr/core
	rm -f acpi/*.o acpi/*~ acpi/core
	rm -f dm/*.o dm/*~ dm/core
	rm -f genapic/*.o genapic/*~ genapic/core
	rm -f cpu/*.o cpu/*~ cpu/core

.PHONY: default clean
