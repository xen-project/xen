
all: ../lib/libxc.so ../lib/xc.h
	python setup.py build

install: all
	python setup.py install

dist: all
	mkdir -p ../../../../install/lib/python
	for i in `find . -name 'Xc.so'` ; do                           \
		cp $$i ../../../../install/lib/python/`basename $$i` ; \
	done

clean:
	rm -rf build *.pyc *.pyo *.o *.a *~
