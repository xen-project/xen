
all:	
	$(MAKE) -C check
	$(MAKE) -C libxutil
	$(MAKE) -C libxc
	$(MAKE) -C misc
	$(MAKE) -C examples
	$(MAKE) -C xentrace
	$(MAKE) -C python
	$(MAKE) -C xfrd
	$(MAKE) -C xcs
	$(MAKE) -C ioemu

install: 
ifneq ($(dist),yes)
	$(MAKE) -C check install
endif
	$(MAKE) -C libxutil install
	$(MAKE) -C libxc install
	$(MAKE) -C misc install
	$(MAKE) -C examples install
	$(MAKE) -C xentrace install
	$(MAKE) -C python install
	$(MAKE) -C xfrd install
	$(MAKE) -C sv install
	$(MAKE) -C xcs install
	$(MAKE) -C ioemu install

dist: $(TARGET)
	$(MAKE) prefix=`pwd`/../../install dist=yes install


clean:
	$(MAKE) -C libxutil clean
	$(MAKE) -C libxc clean
	$(MAKE) -C misc clean
	$(MAKE) -C examples clean
	$(MAKE) -C xentrace clean
	$(MAKE) -C python clean
	$(MAKE) -C xfrd clean
	$(MAKE) -C xcs clean
	$(MAKE) -C ioemu clean
