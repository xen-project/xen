
INSTALL  = $(wildcard *.py)
ETC	 = defaults democd netbsd xmdefaults
ETCDIR   = /etc/xen
INITD    = init.d/xendomains init.d/xend

all: 

install: all
	mkdir -p $(prefix)/usr/bin
	mkdir -p $(prefix)$(ETCDIR)
	mkdir -p $(prefix)$(ETCDIR)/auto
	mkdir -p $(prefix)/etc/init.d
	install -m0755 $(INSTALL) $(prefix)/usr/bin
	for i in $(ETC); \
	    do [ -a $(prefix)/$(ETCDIR)/$$i ] || \
	    install -m0644 $$i $(prefix)$(ETCDIR); \
	done
	install -m0755 $(INITD) $(prefix)/etc/init.d

clean:
