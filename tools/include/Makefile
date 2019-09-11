XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

# Relative to $(XEN_ROOT)/xen/xsm/flask
FLASK_H_DEPEND := policy/initial_sids

.PHONY: all all-y build
all build: all-y xen-foreign xen/.dir xen-xsm/.dir
all-y:

.PHONY: xen-foreign
xen-foreign:
	$(MAKE) -C xen-foreign

XEN_PUBLIC_INCLUDES = $(wildcard $(XEN_ROOT)/xen/include/public/*.h)
XEN_LIB_X86_INCLUDES = $(filter-out %autogen.h, $(XEN_ROOT)/xen/include/xen/lib/x86/Makefile $(wildcard $(XEN_ROOT)/xen/include/xen/lib/x86/*.h))

xen/.dir: $(XEN_PUBLIC_INCLUDES) $(XEN_LIB_X86_INCLUDES)
	@rm -rf xen
	mkdir -p xen/libelf
	ln -sf $(XEN_ROOT)/xen/include/public/COPYING xen
	ln -sf $(XEN_PUBLIC_INCLUDES) xen
	ln -sf $(addprefix $(XEN_ROOT)/xen/include/public/,arch-x86 arch-arm hvm io xsm) xen
	ln -sf ../xen-sys/$(XEN_OS) xen/sys
	ln -sf $(addprefix $(XEN_ROOT)/xen/include/xen/,libelf.h elfstructs.h) xen/libelf/
	ln -s ../xen-foreign xen/foreign
	ln -sf $(XEN_ROOT)/xen/include/acpi acpi
ifeq ($(CONFIG_X86),y)
	ln -sf $(XEN_ROOT)/xen/include/asm-x86 xen/asm
	mkdir -p xen/lib/x86
	for f in $(patsubst $(XEN_ROOT)/xen/include/xen/lib/x86/%,%,$(XEN_LIB_X86_INCLUDES)); do \
		ln -sf $(XEN_ROOT)/xen/include/xen/lib/x86/$$f xen/lib/x86/$$f; \
	done
endif
	touch $@

all-$(CONFIG_X86): xen/.dir
	$(MAKE) -C xen/lib/x86 all XEN_ROOT=$(XEN_ROOT) PYTHON=$(PYTHON)

# Not xen/xsm as that clashes with link to
# $(XEN_ROOT)/xen/include/public/xsm above.
xen-xsm/.dir: $(XEN_ROOT)/xen/xsm/flask/policy/mkflask.sh \
	      $(patsubst %,$(XEN_ROOT)/xen/xsm/flask/%,$(FLASK_H_DEPEND))
	mkdir -p xen-xsm/flask
	cd $(XEN_ROOT)/xen/xsm/flask/ && \
		$(SHELL) policy/mkflask.sh $(AWK) $(CURDIR)/xen-xsm/flask $(FLASK_H_DEPEND)
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

.PHONY: uninstall
uninstall:
	echo "[FIXME] uninstall headers"
	rm -rf $(DESTDIR)$(includedir)/xen

.PHONY: clean
clean:
	rm -rf xen xen-xsm acpi
	$(MAKE) -C xen-foreign clean

.PHONY: dist
dist: install

.PHONY: distclean
distclean: clean
