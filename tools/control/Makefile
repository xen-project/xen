default: domctl xenctl

install: install-domctl install-xenctl

clean: clean-domctl clean-xenctl



domctl: FORCE
	ant -buildfile build-dom.xml dist

install-domctl: domctl
	cp domctl.jar domctl ../../../install/bin
	chmod 755 ../../../install/bin/domctl

clean-domctl:
	ant -buildfile build-dom.xml clean
	rm -f domctl.jar



xenctl: FORCE
	(cd web/tmpl; make)
	ant -buildfile build-xen.xml dist

install-xenctl: xenctl
	-ant -buildfile build-xen.xml remove
	ant -buildfile build-xen.xml install

clean-xenctl:
	(cd web/tmpl; make clean)
	ant -buildfile build-xen.xml clean
	rm -f xenctl.jar

FORCE:
