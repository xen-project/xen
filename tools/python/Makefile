
all:
	python setup.py build

install: all
	python setup.py install --home="$(DESTDIR)/usr"

clean:
	rm -rf build *.pyc *.pyo *.o *.a *~
