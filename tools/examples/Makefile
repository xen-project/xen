
# Init scripts.
XEND_INITD = init.d/xend
XENDOMAINS_INITD = init.d/xendomains

# Xen configuration dir and configs to go there.
XEN_CONFIG_DIR = /etc/xen
XEN_CONFIGS = xend-config.sxp
XEN_CONFIGS += xmexample1 
XEN_CONFIGS += xmexample2

# Xen script dir and scripts to go there.
XEN_SCRIPT_DIR = /etc/xen/scripts
XEN_SCRIPTS = network
XEN_SCRIPTS += vif-bridge
XEN_SCRIPTS += block-file
XEN_SCRIPTS += block-enbd

all: 

install: all install-initd install-configs install-scripts

install-initd:
	install -d $(prefix)/etc/init.d
	install -m0755 $(XEND_INITD) $(prefix)/etc/init.d
	install -m0755 $(XENDOMAINS_INITD) $(prefix)/etc/init.d

install-configs:
	install -d $(prefix)$(XEN_CONFIG_DIR)
	install -d $(prefix)$(XEN_CONFIG_DIR)/auto
	for i in $(XEN_CONFIGS); \
	    do [ -a $(prefix)/$(XEN_CONFIG_DIR)/$$i ] || \
	    install -m0644 $$i $(prefix)$(XEN_CONFIG_DIR); \
	done

install-scripts:
	install -d $(prefix)$(XEN_SCRIPT_DIR)
	for i in $(XEN_SCRIPTS); \
	    do [ -a $(prefix)/$()/$$i ] || \
	    install -m0755 $$i $(prefix)$(XEN_SCRIPT_DIR); \
	done

clean:
