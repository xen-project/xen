
INSTALL  = $(wildcard *.py)
ETC	 = defaults democd netbsd
INITD    = init.d/xendomains init.d/xend

all: 

install: all
	mkdir -p $(prefix)/usr/bin
	mkdir -p $(prefix)/etc/xc
	mkdir -p $(prefix)/etc/xc/auto
	mkdir -p $(prefix)/etc/init.d
	install -m0755 $(INSTALL) $(prefix)/usr/bin
	for i in $(ETC); \
	    do [ -a $(prefix)/etc/xc/$$i ] || \
	    install -m0644 $$i $(prefix)/etc/xc; \
	done
	install -m0755 $(INITD) $(prefix)/etc/init.d

clean:
