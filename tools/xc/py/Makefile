
all: ../lib/libxc.a
	python setup.py build

install:
	mkdir -p ../../../../install/lib/python
	for i in `find . -name 'Xc.so'` ; do                           \
		cp $$i ../../../../install/lib/python/`basename $$i` ; \
	done

clean:
	rm -rf build
