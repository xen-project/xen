
all:
	python setup.py build

install: all
	if [ "$(prefix)" = "" ]; then python setup.py install; \
	else python setup.py install --root "$(prefix)"; fi
	install --mode=755 xend.py $(prefix)/usr/sbin
	ln -sf xend.py $(prefix)/usr/sbin/xend

dist: all
	mkdir -p ../../../../install/lib/python
	for i in `find . -name 'xend_utils.so'` ; do           \
		install --mode=755 $$i ../../../../install/lib/python/`basename $$i` ; \
	done
	python -c 'import py_compile, sys; py_compile.compile("XenoUtil.py")'
	install --mode=755 xend.py ../../../../install/sbin
	ln -sf xend.py ../../../../install/sbin/xend

clean:
	rm -rf build *.pyc *.pyo *.a *.so *.o *~ *.rpm 

$(BIN): $(OBJS)
	$(CC) -o $@ $^ -L../xc/lib -lxc

%.o: %.c $(HDRS) Makefile
	$(CC) $(CFLAGS) -c -o $@ $<
