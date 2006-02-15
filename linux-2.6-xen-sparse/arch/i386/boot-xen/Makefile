
OBJCOPYFLAGS := -g --strip-unneeded

vmlinuz: vmlinux-stripped FORCE
	$(call if_changed,gzip)

vmlinux-stripped: vmlinux FORCE
	$(call if_changed,objcopy)

INSTALL_ROOT := $(patsubst %/boot,%,$(INSTALL_PATH))

XINSTALL_NAME ?= $(KERNELRELEASE)
install:
	mkdir -p $(INSTALL_ROOT)/boot
	ln -f -s vmlinuz-$(XINSTALL_NAME)$(INSTALL_SUFFIX) $(INSTALL_ROOT)/boot/vmlinuz-$(VERSION).$(PATCHLEVEL).$(SUBLEVEL)$(XENGUEST)$(INSTALL_SUFFIX)
	rm -f $(INSTALL_ROOT)/boot/vmlinuz-$(XINSTALL_NAME)$(INSTALL_SUFFIX)
	install -m0644 vmlinuz $(INSTALL_ROOT)/boot/vmlinuz-$(XINSTALL_NAME)$(INSTALL_SUFFIX)
	install -m0644 vmlinux $(INSTALL_ROOT)/boot/vmlinux-syms-$(XINSTALL_NAME)$(INSTALL_SUFFIX)
	install -m0664 .config $(INSTALL_ROOT)/boot/config-$(XINSTALL_NAME)$(INSTALL_SUFFIX)
	install -m0664 System.map $(INSTALL_ROOT)/boot/System.map-$(XINSTALL_NAME)$(INSTALL_SUFFIX)
	ln -f -s vmlinuz-$(XINSTALL_NAME)$(INSTALL_SUFFIX) $(INSTALL_ROOT)/boot/vmlinuz-$(VERSION).$(PATCHLEVEL)$(XENGUEST)$(INSTALL_SUFFIX)
