
all:	
	$(MAKE) -C balloon
	$(MAKE) -C xc
	$(MAKE) -C misc
	$(MAKE) -C examples
	$(MAKE) -C xentrace
	$(MAKE) -C xenctl
	$(MAKE) -C xend

install: all
	$(MAKE) -C balloon install
	$(MAKE) -C xc install
	$(MAKE) -C misc install
	$(MAKE) -C examples install
	$(MAKE) -C xentrace install
	$(MAKE) -C xenctl install
	$(MAKE) -C xend install

clean:
	$(MAKE) -C balloon clean
	$(MAKE) -C xc clean
	$(MAKE) -C misc clean
	$(MAKE) -C examples clean
	$(MAKE) -C nsplitd clean
	$(MAKE) -C xentrace clean
	$(MAKE) -C xenctl clean
	$(MAKE) -C xend clean

