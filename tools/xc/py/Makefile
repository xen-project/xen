
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

clean:
	rm -rf build *.pyc *.pyo *.o *.a *~
