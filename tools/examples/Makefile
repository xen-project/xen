
INSTALL  = $(wildcard *.py)

INITD    = init.d/xend

XEN_CONFIG_DIR  = /etc/xen
XEN_CONFIGS = xmdefaults xmnetbsd xend-config.sxp

XEN_SCRIPT_DIR = /etc/xen
XEN_SCRIPTS = vifctl network vif-bridge

all: 

install: all install-initd install-configs install-scripts

install-initd:
	mkdir -p $(prefix)/etc/init.d
	install -m0755 $(INITD) $(prefix)/etc/init.d

install-configs:
	mkdir -p $(prefix)$(XEN_CONFIG_DIR)
	mkdir -p $(prefix)$(XEN_CONFIG_DIR)/auto
	for i in $(XEN_CONFIGS); \
	    do [ -a $(prefix)/$(XEN_CONFIG_DIR)/$$i ] || \
	    install -m0644 $$i $(prefix)$(XEN_CONFIG_DIR); \
	done

install-scripts:
	mkdir -p $(prefix)$(XEN_SCRIPT_DIR)
	for i in $(XEN_SCRIPTS); \
	    do [ -a $(prefix)/$()/$$i ] || \
	    install -m0755 $$i $(prefix)$(XEN_SCRIPT_DIR); \
	done

clean:
