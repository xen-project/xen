
INSTALL  = $(wildcard *.py)

ETC	 = xmdefaults
ETCDIR   = /etc/xen

INITD    = init.d/xend

XEND     = vifctl
XEND_DIR = $(ETCDIR)/xend

all: 

install: all install-initd install-etc install-xend

install-initd:
	mkdir -p $(prefix)/etc/init.d
	install -m0755 $(INITD) $(prefix)/etc/init.d

install-etc:
	mkdir -p $(prefix)$(ETCDIR)
	mkdir -p $(prefix)$(ETCDIR)/auto
	for i in $(ETC); \
	    do [ -a $(prefix)/$(ETCDIR)/$$i ] || \
	    install -m0644 $$i $(prefix)$(ETCDIR); \
	done

install-xend:
	mkdir -p $(prefix)$(XEND_DIR)
	for i in $(XEND); \
	    do [ -a $(prefix)/$(XEND_DIR)/$$i ] || \
	    install -m0755 $$i $(prefix)$(XEND_DIR); \
	done

clean:
