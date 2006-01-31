
include $(BASEDIR)/Rules.mk

OBJS += $(patsubst %.S,%.o,$(wildcard $(TARGET_SUBARCH)/*.S))
OBJS += $(patsubst %.c,%.o,$(wildcard $(TARGET_SUBARCH)/*.c))
OBJS += $(patsubst %.c,%.o,$(wildcard acpi/*.c))
OBJS += $(patsubst %.c,%.o,$(wildcard mtrr/*.c))
OBJS += $(patsubst %.c,%.o,$(wildcard genapic/*.c))
OBJS += $(patsubst %.c,%.o,$(wildcard cpu/*.c))
OBJS += $(patsubst %.c,%.o,$(wildcard hvm/*.c))
OBJS += $(patsubst %.c,%.o,$(wildcard hvm/vmx/*.c))
OBJS += $(patsubst %.S,%.o,$(wildcard hvm/vmx/$(TARGET_SUBARCH)/*.S))
OBJS += $(patsubst %.c,%.o,$(wildcard hvm/svm/*.c))
OBJS += $(patsubst %.S,%.o,$(wildcard hvm/svm/$(TARGET_SUBARCH)/*.S))

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
OBJS := $(subst $(TARGET_SUBARCH)/xen.lds.o,,$(OBJS))

ifneq ($(crash_debug),y)
OBJS := $(patsubst gdbstub%.o,,$(OBJS))
endif

default: $(TARGET)

$(TARGET): $(TARGET)-syms boot/mkelf32
	./boot/mkelf32 $(TARGET)-syms $(TARGET) 0x100000 \
	`nm $(TARGET)-syms | sort | tail -n 1 | sed -e 's/^\([^ ]*\).*/0x\1/'`

$(CURDIR)/arch.o: $(OBJS)
	$(LD) $(LDFLAGS) -r -o $@ $(OBJS)

$(TARGET)-syms: boot/$(TARGET_SUBARCH).o $(ALL_OBJS) xen.lds
	$(LD) $(LDFLAGS) -T xen.lds -N \
	    boot/$(TARGET_SUBARCH).o $(ALL_OBJS) -o $@
	$(NM) -n $@ | $(BASEDIR)/tools/symbols >$(BASEDIR)/xen-syms.S
	$(MAKE) $(BASEDIR)/xen-syms.o
	$(LD) $(LDFLAGS) -T xen.lds -N \
	    boot/$(TARGET_SUBARCH).o $(ALL_OBJS) $(BASEDIR)/xen-syms.o -o $@
	$(NM) -n $@ | $(BASEDIR)/tools/symbols >$(BASEDIR)/xen-syms.S
	$(MAKE) $(BASEDIR)/xen-syms.o
	$(LD) $(LDFLAGS) -T xen.lds -N \
	    boot/$(TARGET_SUBARCH).o $(ALL_OBJS) $(BASEDIR)/xen-syms.o -o $@
	rm -f $(BASEDIR)/xen-syms.S $(BASEDIR)/xen-syms.o

asm-offsets.s: $(TARGET_SUBARCH)/asm-offsets.c $(HDRS)
	$(CC) $(CFLAGS) -S -o $@ $<

xen.lds: $(TARGET_SUBARCH)/xen.lds.S $(HDRS)
	$(CC) $(CFLAGS) -P -E -Ui386 -D__ASSEMBLY__ -o $@ $<

boot/mkelf32: boot/mkelf32.c
	$(HOSTCC) $(HOSTCFLAGS) -o $@ $<

shadow_guest32.o: shadow.c

clean:
	rm -f *.o *.s *~ core boot/*.o boot/*~ boot/core boot/mkelf32
	rm -f x86_32/*.o x86_32/*~ x86_32/core
	rm -f x86_64/*.o x86_64/*~ x86_64/core
	rm -f mtrr/*.o mtrr/*~ mtrr/core
	rm -f acpi/*.o acpi/*~ acpi/core
	rm -f genapic/*.o genapic/*~ genapic/core
	rm -f cpu/*.o cpu/*~ cpu/core
	rm -f hvm/*.o hvm/*~ hvm/core
	rm -f hvm/vmx/*.o hvm/vmx/*~ hvm/vmx/core
	rm -f hvm/vmx/x86_32/*.o hvm/vmx/x86_32/*~ hvm/vmx/x86_32/core
	rm -f hvm/vmx/x86_64/*.o hvm/vmx/x86_64/*~ hvm/vmx/x86_64/core
	rm -f hvm/svm/*.o hvm/svm/*~ hvm/svm/core
	rm -f hvm/svm/x86_32/*.o hvm/svm/x86_32/*~ hvm/svm/x86_32/core
	rm -f hvm/svm/x86_64/*.o hvm/svm/x86_64/*~ hvm/svm/x86_64/core
	rm -f xen.lds

.PHONY: default clean
