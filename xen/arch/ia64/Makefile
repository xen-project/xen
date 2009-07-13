subdir-y += xen
subdir-y += vmx
subdir-y += linux
subdir-y += linux-xen

ALL_OBJS := linux-xen/head.o $(ALL_OBJS)

$(TARGET)-syms: $(ALL_OBJS) xen.lds.s
	$(MAKE) -f $(BASEDIR)/Rules.mk $(BASEDIR)/common/symbols-dummy.o
	$(LD) $(LDFLAGS) -T xen.lds.s -N -Map $(@D)/.$(@F).0.map $(ALL_OBJS) \
		$(BASEDIR)/common/symbols-dummy.o -o $(@D)/.$(@F).0 
	$(NM) -n $(@D)/.$(@F).0 | $(BASEDIR)/tools/symbols >$(@D)/.$(@F).0.S 
	$(MAKE) -f $(BASEDIR)/Rules.mk $(@D)/.$(@F).0.o 
	$(LD) $(LDFLAGS) -T xen.lds.s -N -Map $(@D)/.$(@F).1.map $(ALL_OBJS) \
		$(@D)/.$(@F).0.o -o $(@D)/.$(@F).1 
	$(NM) -n $(@D)/.$(@F).1 | $(BASEDIR)/tools/symbols >$(@D)/.$(@F).1.S 
	$(MAKE) -f $(BASEDIR)/Rules.mk $(@D)/.$(@F).1.o 
	$(LD) $(LDFLAGS) -T xen.lds.s -N -Map $@.map $(ALL_OBJS) \
		$(@D)/.$(@F).1.o -o $@
	rm -f $(@D)/.$(@F).[0-9]* 

$(TARGET): $(TARGET)-syms
	$(NM) -n $< | grep -v ' [aUw] ' > $(@D)/System.map 
	$(OBJCOPY) -R .note -R .comment -S $< $@

# Headers do not depend on auto-generated header, but object files do.
$(ALL_OBJS): $(BASEDIR)/include/asm-ia64/asm-xsi-offsets.h

asm-offsets.s: asm-offsets.c \
    $(BASEDIR)/include/asm-ia64/.offsets.h.stamp 
	$(CC) $(CFLAGS) -DGENERATE_ASM_OFFSETS -DIA64_TASK_SIZE=0 -S -o $@ $<

asm-xsi-offsets.s: asm-xsi-offsets.c
	$(CC) $(CFLAGS) -S -o $@ $<

$(BASEDIR)/include/asm-ia64/asm-xsi-offsets.h: asm-xsi-offsets.s
	@(set -e; \
	  echo "/*"; \
	  echo " * DO NOT MODIFY."; \
	  echo " *"; \
	  echo " * This file was auto-generated from $<"; \
	  echo " *"; \
	  echo " */"; \
	  echo ""; \
	  echo "#ifndef __ASM_XSI_OFFSETS_H__"; \
	  echo "#define __ASM_XSI_OFFSETS_H__"; \
	  echo ""; \
	  sed -ne "/^->/{s:^->\([^ ]*\) [\$$#]*\([^ ]*\) \(.*\):#define \1 \2 /* \3 */:; s:->::; p;}"; \
	  echo ""; \
	  echo "#endif") <$< >$@

$(BASEDIR)/include/asm-ia64/.offsets.h.stamp:
# Need such symbol link to make linux headers available
	[ -e $(BASEDIR)/include/linux ] \
	 || ln -sf $(BASEDIR)/include/xen $(BASEDIR)/include/linux
	[ -e $(BASEDIR)/include/asm-ia64/xen ] \
	 || ln -sf $(BASEDIR)/include/asm-ia64/linux $(BASEDIR)/include/asm-ia64/xen
	touch $@

# I'm sure a Makefile wizard would know a better way to do this
xen.lds.s: xen/xen.lds.S
	$(CC) -E $(CPPFLAGS) -P -DXEN $(AFLAGS) \
		-o xen.lds.s xen/xen.lds.S

.PHONY: clean
clean::
	rm -f *.o *~ core  xen.lds.s $(BASEDIR)/include/asm-ia64/.offsets.h.stamp asm-offsets.s map.out
	rm -f asm-xsi-offsets.s $(BASEDIR)/include/asm-ia64/asm-xsi-offsets.h
	rm -f $(BASEDIR)/System.map
	rm -f $(BASEDIR)/include/linux
	rm -f $(BASEDIR)/include/asm-ia64/xen
