XEN_ROOT = $(CURDIR)/../../../..
include $(XEN_ROOT)/tools/Rules.mk

XEN_SYSTEMD_MODULES = xen.conf

XEN_SYSTEMD_MOUNT =  proc-xen.mount
XEN_SYSTEMD_MOUNT += var-lib-xenstored.mount

XEN_SYSTEMD_SOCKET  = xenstored.socket
XEN_SYSTEMD_SOCKET += xenstored_ro.socket

XEN_SYSTEMD_SERVICE  = xenstored.service
XEN_SYSTEMD_SERVICE += xenconsoled.service
XEN_SYSTEMD_SERVICE += xen-qemu-dom0-disk-backend.service
XEN_SYSTEMD_SERVICE += xendomains.service
XEN_SYSTEMD_SERVICE += xen-watchdog.service

ALL_XEN_SYSTEMD =	$(XEN_SYSTEMD_MODULES)  \
			$(XEN_SYSTEMD_MOUNT)	\
			$(XEN_SYSTEMD_SOCKET)	\
			$(XEN_SYSTEMD_SERVICE)

.PHONY: all
all:	$(ALL_XEN_SYSTEMD)

.PHONY: clean
clean:

.PHONY: install
install: $(ALL_XEN_SYSTEMD)
	[ -d $(DESTDIR)$(XEN_SYSTEMD_DIR) ] || \
		$(INSTALL_DIR) $(DESTDIR)$(XEN_SYSTEMD_DIR)
	[ -d $(DESTDIR)$(XEN_SYSTEMD_MODULES_LOAD) ] || \
		$(INSTALL_DIR) $(DESTDIR)$(XEN_SYSTEMD_MODULES_LOAD)
	$(INSTALL_DATA) *.socket $(DESTDIR)$(XEN_SYSTEMD_DIR)
	$(INSTALL_DATA) *.service $(DESTDIR)$(XEN_SYSTEMD_DIR)
	$(INSTALL_DATA) *.mount $(DESTDIR)$(XEN_SYSTEMD_DIR)
	$(INSTALL_DATA) *.conf $(DESTDIR)$(XEN_SYSTEMD_MODULES_LOAD)

$(XEN_SYSTEMD_MODULES): $(XEN_ROOT)/config/$(XEN_OS).modules
	@set -e ;							\
	IFS=''								;\
	cat  $(XEN_ROOT)/config/$(XEN_OS).modules	| (		\
		while read l ; do					\
			if echo $${l} | egrep -q "^#" ; then		\
				continue				;\
			fi						;\
			if echo "$${l}" | egrep -q "\|" ; then		\
				m1=$${l%%|*}				;\
				m2=$${l#*|} 				;\
				# Systemd modules-load.d lacks support	;\
				# for module replacement options, we	;\
				# need to add that support upstream but ;\
				# its best instead to ensure this file	;\
				# is no longer needed. Some folks	;\
				# however have reported issues with	;\
				# some modules automatically loading	;\
				# so we just load all necessary xen	;\
				# modules and for replacements we load	;\
				# the latest module			;\
				echo "$$m1" ;\
				echo "$$m2" ;\
			else						\
				echo "$$l"				;\
			fi						;\
		done							\
	) > $@
