
all: ../lib/libxc.so ../lib/xc.h
	python setup.py build

install: all
	python setup.py install

dist: all
	mkdir -p ../../../../install/lib/python
	for i in `find . -name 'Xc.so'` ; do                           \
		install --mode=755 $$i ../../../../install/lib/python/`basename $$i` ; \
	done
	python -c 'import py_compile, sys; py_compile.compile("XenoUtil.py")'
	install --mode=444 XenoUtil.py ../../../../install/lib/python
	install --mode=644 XenoUtil.pyc ../../../../install/lib/python
clean:
	rm -rf build *.pyc *.pyo *.o *.a *~
