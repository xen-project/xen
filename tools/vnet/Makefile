
export LINUX_SERIES ?=2.6

# Root path to install in.
# Set to '/' to install relative to filesystem root.
export prefix?=$(shell cd ../../dist/install && pwd)

.PHONY: all compile
.PHONY: gc-install gc-clean gc-prstine
.PHONY: vnetd vnet-module install dist clean pristine

all: compile

compile: vnetd vnet-module
#compile: vnet-module

gc.tar.gz:
	wget http://www.hpl.hp.com/personal/Hans_Boehm/gc/gc_source/$@

gc: gc.tar.gz
	tar xfz gc.tar.gz
	ln -sf gc?.? gc

gc-install: gc 
	(cd gc && make test && ./configure --prefix=`pwd`/install)
	make -C gc
	make -C gc install

gc-clean:
	-$(MAKE) -C gc clean

gc-pristine:
	-rm -rf gc?.? gc

vnetd: gc-install
	$(MAKE) -C vnetd

vnet-module:
	$(MAKE) -C vnet-module

install: compile
	$(MAKE) -C vnetd install
	$(MAKE) -C vnet-module install
	$(MAKE) -C examples install

clean:
	-$(MAKE) -C vnetd clean
	-$(MAKE) -C vnet-module clean
	-rm -rf gc?.? gc
	
pristine: clean gc-pristine
