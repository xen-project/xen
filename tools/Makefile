
all:	
	$(MAKE) -C xc
	$(MAKE) -C xu
	$(MAKE) -C misc
	$(MAKE) -C examples
	$(MAKE) -C xentrace
	$(MAKE) -C xen

install: all
	$(MAKE) -C xc install
	$(MAKE) -C xu install
	$(MAKE) -C misc install
	$(MAKE) -C examples install
	$(MAKE) -C xentrace install
	$(MAKE) -C xen install

dist: $(TARGET)
	$(MAKE) prefix=`pwd`/../../install dist=yes install


clean:
	$(MAKE) -C xc clean
	$(MAKE) -C xu clean
	$(MAKE) -C misc clean
	$(MAKE) -C examples clean
	$(MAKE) -C xentrace clean
	$(MAKE) -C xen clean

