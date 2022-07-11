XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

# Xen configuration dir and configs to go there.

XEN_READMES = README

XEN_CONFIGS += xlexample.hvm
XEN_CONFIGS += xlexample.pvlinux
XEN_CONFIGS += xlexample.pvhlinux
XEN_CONFIGS += xl.conf
XEN_CONFIGS += cpupool

.PHONY: all
all:

.PHONY: install
install: all install-readmes install-configs

.PHONY: uninstall
uninstall: uninstall-readmes uninstall-configs

.PHONY: install-readmes
install-readmes:
	$(INSTALL_DIR) $(DESTDIR)$(XEN_CONFIG_DIR)
	$(INSTALL_DATA) $(XEN_READMES) $(DESTDIR)$(XEN_CONFIG_DIR)

.PHONY: uninstall-readmes
uninstall-readmes:
	rm -f $(addprefix $(DESTDIR)$(XEN_CONFIG_DIR)/, $(XEN_READMES))

.PHONY: install-configs
install-configs: $(XEN_CONFIGS)
	$(INSTALL_DIR) $(DESTDIR)$(XEN_CONFIG_DIR)
	$(INSTALL_DIR) $(DESTDIR)$(XEN_CONFIG_DIR)/auto
	$(INSTALL_DATA) $(XEN_CONFIGS) $(DESTDIR)$(XEN_CONFIG_DIR)

.PHONY: uninstall-configs
uninstall-configs:
	rm -f $(addprefix $(DESTDIR)$(XEN_CONFIG_DIR)/, $(XEN_CONFIGS))

.PHONY: clean
clean:

.PHONY: distclean
distclean: clean
