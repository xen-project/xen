
all:
	python setup.py build

install: all
	if [ "$(DESTDIR)" = "" ]; then                   \
	    python setup.py install;                     \
	else                                             \
	    python setup.py install --root="$(DESTDIR)"; \
	fi

clean:
	rm -rf build *.pyc *.pyo *.o *.a *~
