
all:	
	$(MAKE) -C libxutil
	$(MAKE) -C libxc
	$(MAKE) -C misc
	$(MAKE) -C examples
	$(MAKE) -C xentrace
	$(MAKE) -C python

install: all
	$(MAKE) -C libxutil install
	$(MAKE) -C libxc install
	$(MAKE) -C misc install
	$(MAKE) -C examples install
	$(MAKE) -C xentrace install
	$(MAKE) -C python install

dist: $(TARGET)
	$(MAKE) prefix=`pwd`/../../install dist=yes install


clean:
	$(MAKE) -C libxutil clean
	$(MAKE) -C libxc clean
	$(MAKE) -C misc clean
	$(MAKE) -C examples clean
	$(MAKE) -C xentrace clean
	$(MAKE) -C python clean

