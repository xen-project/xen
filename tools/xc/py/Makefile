
all:
	python setup.py build

install: all
	if [ "$(prefix)" = "" ]; then python setup.py install; \
	else python setup.py install --root "$(prefix)"; fi

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
