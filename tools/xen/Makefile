
all:
	python setup.py build

install: all
	if [ "$(prefix)" = "" ]; then                   \
	    python setup.py install;                    \
	elif [ "$(dist)" = "yes" ]; then                \
	    python setup.py install --home="$(prefix)"; \
	else                                            \
	    python setup.py install --root="$(prefix)"; \
	fi
	mkdir -p $(prefix)/usr/sbin
	install -m0755 xend $(prefix)/usr/sbin
	install -m0755 xm $(prefix)/usr/sbin

clean:
	rm -rf build *.pyc *.pyo *.o *.a *~
