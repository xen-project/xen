default: cmdline

install: install-cmdline

clean: clean-cmdline



cmdline: FORCE
	ant -buildfile build-cmdline.xml dist

install-cmdline: domctl
	cp xenctl-cmdline.jar xenctl ../../../install/bin
	chmod 755 ../../../install/bin/xenctl

clean-cmdline:
	ant -buildfile build-cmdline.xml clean
	rm -f xenctl-cmdline.jar



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
