XEN_ROOT = $(CURDIR)/../../../..
include $(XEN_ROOT)/tools/Rules.mk

XEN_SYSTEMD_MODULES = xen.conf

XEN_SYSTEMD_MOUNT =  proc-xen.mount
XEN_SYSTEMD_MOUNT += var-lib-xenstored.mount

XEN_SYSTEMD_SERVICE  = xenstored.service
XEN_SYSTEMD_SERVICE += xenconsoled.service
XEN_SYSTEMD_SERVICE += xen-qemu-dom0-disk-backend.service
XEN_SYSTEMD_SERVICE += xendomains.service
XEN_SYSTEMD_SERVICE += xen-watchdog.service
XEN_SYSTEMD_SERVICE += xen-init-dom0.service
XEN_SYSTEMD_SERVICE += xendriverdomain.service

ALL_XEN_SYSTEMD =	$(XEN_SYSTEMD_MODULES)  \
			$(XEN_SYSTEMD_MOUNT)	\
			$(XEN_SYSTEMD_SERVICE)

.PHONY: all
all:	$(ALL_XEN_SYSTEMD)

.PHONY: clean
clean:
	rm -f $(XEN_SYSTEMD_MODULES)

.PHONY: distclean
distclean: clean

.PHONY: install
install: $(ALL_XEN_SYSTEMD)
	[ -d $(DESTDIR)$(XEN_SYSTEMD_DIR) ] || \
		$(INSTALL_DIR) $(DESTDIR)$(XEN_SYSTEMD_DIR)
	[ -d $(DESTDIR)$(XEN_SYSTEMD_MODULES_LOAD) ] || \
		$(INSTALL_DIR) $(DESTDIR)$(XEN_SYSTEMD_MODULES_LOAD)
	$(INSTALL_DATA) *.service $(DESTDIR)$(XEN_SYSTEMD_DIR)
	$(INSTALL_DATA) *.mount $(DESTDIR)$(XEN_SYSTEMD_DIR)
	$(INSTALL_DATA) *.conf $(DESTDIR)$(XEN_SYSTEMD_MODULES_LOAD)

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(XEN_SYSTEMD_MODULES_LOAD)/*.conf
	rm -f $(DESTDIR)$(XEN_SYSTEMD_DIR)/*.mount
	rm -f $(DESTDIR)$(XEN_SYSTEMD_DIR)/*.service

$(XEN_SYSTEMD_MODULES):
	rm -f $@.tmp
	for mod in $(LINUX_BACKEND_MODULES) ; do \
		echo $$mod ; \
		done > $@.tmp
	$(call move-if-changed,$@.tmp,$@)
