
export LINUX_RELEASE ?=2.6

all: compile

compile: vnetd vnet-module

gc.tar.gz:
	wget http://www.hpl.hp.com/personal/Hans_Boehm/gc/gc_source/$@

gc: gc.tar.gz
	tar xfz gc.tar.gz
	ln -sf gc?.? gc

gc-install: gc
	(cd gc && ./configure --prefix=`pwd`/install && make && make install)

gc-clean:
	-$(MAKE) -C gc clean

gc-pristine:
	-rm -rf gc?.? gc

.PHONY: vnetd vnet-module install dist clean

vnetd: gc-install
	$(MAKE) -C vnetd

vnet-module:
	$(MAKE) -C vnet-module

install: compile
	$(MAKE) -C vnetd install
	$(MAKE) -C vnet-module install
	$(MAKE) -C examples install

dist: $(TARGET)
	$(MAKE) prefix=`pwd`/../../install dist=yes install

clean:
	-$(MAKE) -C vnetd clean
	-$(MAKE) -C vnet-module clean
