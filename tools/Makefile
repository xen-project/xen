
all:	
	$(MAKE) -C xc
	$(MAKE) -C misc
	$(MAKE) -C examples
	$(MAKE) -C xentrace
	$(MAKE) -C xenctl
	$(MAKE) -C xend
	$(MAKE) -C xenmgr

install: all
	$(MAKE) -C xc install
	$(MAKE) -C misc install
	$(MAKE) -C examples install
	$(MAKE) -C xentrace install
	$(MAKE) -C xenctl install
	$(MAKE) -C xend install
	$(MAKE) -C xenmgr install

dist: $(TARGET)
	$(MAKE) prefix=`pwd`/../../install dist=yes install


clean:
	$(MAKE) -C xc clean
	$(MAKE) -C misc clean
	$(MAKE) -C examples clean
	$(MAKE) -C xentrace clean
	$(MAKE) -C xenctl clean
	$(MAKE) -C xend clean
	$(MAKE) -C xenmgr clean

