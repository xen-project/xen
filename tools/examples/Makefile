INSTALL		= install
INSTALL_DIR	= $(INSTALL) -d -m0755
INSTALL_PROG	= $(INSTALL) -m0755
INSTALL_DATA	= $(INSTALL) -m0644

# Init scripts.
XEND_INITD = init.d/xend
XENDOMAINS_INITD = init.d/xendomains

# Xen configuration dir and configs to go there.
XEN_CONFIG_DIR = /etc/xen
XEN_CONFIGS = xend-config.sxp
XEN_CONFIGS += xmexample1 
XEN_CONFIGS += xmexample2
XEN_CONFIGS += xmexample.vmx
XEN_CONFIGS += mem-map.sxp
XEN_CONFIGS += bochsrc

# Xen script dir and scripts to go there.
XEN_SCRIPT_DIR = /etc/xen/scripts
XEN_SCRIPTS = network vif-bridge
XEN_SCRIPTS += network-route vif-route
XEN_SCRIPTS += block-file
XEN_SCRIPTS += block-enbd

all: 
build:

install: all install-initd install-configs install-scripts

install-initd:
	[ -d $(DESTDIR)/etc/init.d ] || $(INSTALL_DIR) $(DESTDIR)/etc/init.d
	$(INSTALL_PROG) $(XEND_INITD) $(DESTDIR)/etc/init.d
	$(INSTALL_PROG) $(XENDOMAINS_INITD) $(DESTDIR)/etc/init.d

install-configs:
	[ -d $(DESTDIR)$(XEN_CONFIG_DIR) ] || \
		$(INSTALL_DIR) $(DESTDIR)$(XEN_CONFIG_DIR)
	[ -d $(DESTDIR)$(XEN_CONFIG_DIR)/auto ] || \
		$(INSTALL_DIR) $(DESTDIR)$(XEN_CONFIG_DIR)/auto
	for i in $(XEN_CONFIGS); \
	    do [ -a $(DESTDIR)$(XEN_CONFIG_DIR)/$$i ] || \
	    $(INSTALL_DATA) $$i $(DESTDIR)$(XEN_CONFIG_DIR); \
	done

install-scripts:
	[ -d $(DESTDIR)$(XEN_SCRIPT_DIR) ] || \
		$(INSTALL_DIR) $(DESTDIR)$(XEN_SCRIPT_DIR)
	for i in $(XEN_SCRIPTS); \
	    do [ -a $(DESTDIR)$(XEN_SCRIPT_DIR)/$$i ] || \
	    $(INSTALL_PROG) $$i $(DESTDIR)$(XEN_SCRIPT_DIR); \
	done

clean:
