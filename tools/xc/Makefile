
all:
	$(MAKE) -C lib
	$(MAKE) -C py

install: all
	$(MAKE) -C lib install
	$(MAKE) -C py  install

dist: all
	$(MAKE) -C lib dist
	$(MAKE) -C py  dist

clean:
	$(MAKE) -C lib clean
	$(MAKE) -C py  clean
