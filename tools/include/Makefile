XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

.PHONY: all
all: xen-foreign xen/.dir

.PHONY: xen-foreign
xen-foreign:
	$(MAKE) -C xen-foreign

xen/.dir:
	@rm -rf xen
	mkdir -p xen/libelf
	ln -sf $(XEN_ROOT)/xen/include/public/COPYING xen
	ln -sf $(wildcard $(XEN_ROOT)/xen/include/public/*.h) xen
	ln -sf $(addprefix $(XEN_ROOT)/xen/include/public/,arch-x86 arch-arm hvm io xsm) xen
	ln -sf ../xen-sys/$(XEN_OS) xen/sys
	ln -sf $(addprefix $(XEN_ROOT)/xen/include/xen/,libelf.h elfstructs.h) xen/libelf/
	ln -s ../xen-foreign xen/foreign
	touch $@

.PHONY: install
install: all
	$(INSTALL_DIR) $(DESTDIR)$(includedir)/xen/arch-x86
	$(INSTALL_DIR) $(DESTDIR)$(includedir)/xen/arch-x86/hvm
	$(INSTALL_DIR) $(DESTDIR)$(includedir)/xen/arch-arm
	$(INSTALL_DIR) $(DESTDIR)$(includedir)/xen/arch-arm/hvm
	$(INSTALL_DIR) $(DESTDIR)$(includedir)/xen/foreign
	$(INSTALL_DIR) $(DESTDIR)$(includedir)/xen/hvm
	$(INSTALL_DIR) $(DESTDIR)$(includedir)/xen/io
	$(INSTALL_DIR) $(DESTDIR)$(includedir)/xen/sys
	$(INSTALL_DIR) $(DESTDIR)$(includedir)/xen/xsm
	$(INSTALL_DATA) xen/COPYING $(DESTDIR)$(includedir)/xen
	$(INSTALL_DATA) xen/*.h $(DESTDIR)$(includedir)/xen
	$(INSTALL_DATA) xen/arch-x86/*.h $(DESTDIR)$(includedir)/xen/arch-x86
	$(INSTALL_DATA) xen/arch-x86/hvm/*.h $(DESTDIR)$(includedir)/xen/arch-x86/hvm

# 	xen/arch-arm doesn't contains headers for now. Uncommented the line
# 	as soon as a new header is added
#	$(INSTALL_DATA) xen/arch-arm/*.h $(DESTDIR)$(includedir)/xen/arch-arm
	$(INSTALL_DATA) xen/arch-arm/hvm/*.h $(DESTDIR)$(includedir)/xen/arch-arm/hvm
	$(INSTALL_DATA) xen/foreign/*.h $(DESTDIR)$(includedir)/xen/foreign
	$(INSTALL_DATA) xen/hvm/*.h $(DESTDIR)$(includedir)/xen/hvm
	$(INSTALL_DATA) xen/io/*.h $(DESTDIR)$(includedir)/xen/io
	$(INSTALL_DATA) xen/sys/*.h $(DESTDIR)$(includedir)/xen/sys
	$(INSTALL_DATA) xen/xsm/*.h $(DESTDIR)$(includedir)/xen/xsm

.PHONY: clean
clean:
	rm -rf xen
	$(MAKE) -C xen-foreign clean


.PHONY: distclean
distclean: clean
