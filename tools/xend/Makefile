
all:
	python setup.py build

install: all
	if [ "$(prefix)" = "" ]; then python setup.py install; \
	else python setup.py install --home="$(prefix)"; fi
	mkdir -p $(prefix)/usr/sbin
	install -m0755 xend $(prefix)/usr/sbin

clean:
	rm -rf build *.pyc *.pyo *.a *.so *.o *~ *.rpm 
