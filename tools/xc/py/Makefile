
all:
	python setup.py build

install: all
	if [ "$(prefix)" = "" ]; then python setup.py install; \
	else python setup.py install --home="$(prefix)"; fi

clean:
	rm -rf build *.pyc *.pyo *.o *.a *~
