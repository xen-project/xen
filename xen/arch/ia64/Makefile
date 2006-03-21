include $(BASEDIR)/Rules.mk

subdir-y += xen
subdir-y += vmx
subdir-y += linux
subdir-y += linux-xen

include $(BASEDIR)/Post.mk

$(TARGET)-syms: linux-xen/head.o $(ALL_OBJS) xen.lds.s
	$(LD) $(LDFLAGS) -T xen.lds.s -N \
		-Map map.out linux-xen/head.o $(ALL_OBJS) -o $@
	$(NM) -n $@ | $(BASEDIR)/tools/symbols > $(BASEDIR)/xen-syms.S
	$(MAKE) $(BASEDIR)/xen-syms.o
	$(LD) $(LDFLAGS) -T xen.lds.s -N \
		-Map map.out linux-xen/head.o $(ALL_OBJS) $(BASEDIR)/xen-syms.o -o $@
	$(NM) -n $@ | $(BASEDIR)/tools/symbols >$(BASEDIR)/xen-syms.S
	$(MAKE) $(BASEDIR)/xen-syms.o
	$(LD) $(LDFLAGS) -T xen.lds.s -N \
		-Map map.out linux-xen/head.o $(ALL_OBJS) $(BASEDIR)/xen-syms.o -o $@
	rm -f $(BASEDIR)/xen-syms.S $(BASEDIR)/xen-syms.o

$(TARGET): $(TARGET)-syms
	$(OBJCOPY) -R .note -R .comment -S $(TARGET)-syms $@
	$(NM) -n $(TARGET)-syms | grep -v '\( [aUw] \)\|\(__crc_\)\|\( \$[adt]\)'\
		 > $(BASEDIR)/System.map


asm-offsets.s: asm-offsets.c $(BASEDIR)/include/asm-ia64/.offsets.h.stamp $(BASEDIR)/include/asm-ia64/asm-xsi-offsets.h
	$(CC) $(CFLAGS) -S -o $@ $<

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
	 || ln -s $(BASEDIR)/include/xen $(BASEDIR)/include/linux
	[ -e $(BASEDIR)/include/asm-ia64/xen ] \
	 || ln -s $(BASEDIR)/include/asm-ia64/linux $(BASEDIR)/include/asm-ia64/xen
# Link to HVM files in Xen for ia64/vti
	[ -e $(BASEDIR)/include/asm-ia64/hvm ] \
	 || mkdir $(BASEDIR)/include/asm-ia64/hvm
	[ -e $(BASEDIR)/include/asm-ia64/hvm/support.h ] \
	 || ln -s ../../../include/asm-x86/hvm/support.h $(BASEDIR)/include/asm-ia64/hvm/support.h
	[ -e $(BASEDIR)/include/asm-ia64/hvm/io.h ] \
	 || ln -s ../../../include/asm-x86/hvm/io.h $(BASEDIR)/include/asm-ia64/hvm/io.h
	[ -e $(BASEDIR)/include/asm-ia64/hvm/vpic.h ] \
	 || ln -s ../../../include/asm-x86/hvm/vpic.h $(BASEDIR)/include/asm-ia64/hvm/vpic.h
	[ -e $(BASEDIR)/include/asm-ia64/hvm/vioapic.h ] \
	 || ln -s ../../../include/asm-x86/hvm/vioapic.h $(BASEDIR)/include/asm-ia64/hvm/vioapic.h
	[ -e $(BASEDIR)/arch/ia64/vmx/hvm_vioapic.c ] \
	 || ln -s ../../../arch/x86/hvm/vioapic.c $(BASEDIR)/arch/ia64/vmx/hvm_vioapic.c
# Solve circular reference on asm-offsets.h
	[ -f $(BASEDIR)/include/asm-ia64/asm-offsets.h ] \
	 || echo "#define IA64_TASK_SIZE 0" > $(BASEDIR)/include/asm-ia64/asm-offsets.h
#Bad hack. Force asm-offsets.h out-of-date
	 sleep 1
	 touch $@

# I'm sure a Makefile wizard would know a better way to do this
xen.lds.s: xen/xen.lds.S
	$(CC) -E $(CPPFLAGS) -P -DXEN -D__ASSEMBLY__ \
		-o xen.lds.s xen/xen.lds.S

clean:: FORCE
	rm -f *.o *~ core  xen.lds.s $(BASEDIR)/include/asm-ia64/.offsets.h.stamp asm-offsets.s map.out
	rm -f asm-xsi-offsets.s $(BASEDIR)/include/asm-ia64/asm-xsi-offsets.h
	rm -f $(BASEDIR)/System.map
	rm -f vmx/hvm_*.c
	rm -rf $(BASEDIR)/include/asm-ia64/hvm
