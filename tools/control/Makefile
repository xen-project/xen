#default: cmdline web
default: cmdline

#install: install-cmdline install-web
install: install-cmdline

clean: clean-cmdline clean-web



cmdline: FORCE
	ant -buildfile build-cmdline.xml dist

install-cmdline: cmdline
	mkdir -p ../../../install/bin
	cp -a xenctl-cmdline.jar xenctl ../../../install/bin
	chmod 755 ../../../install/bin/xenctl

clean-cmdline:
	ant -buildfile build-cmdline.xml clean
	rm -f xenctl-cmdline.jar



web: FORCE
	ant -buildfile build-web.xml dist

install-web: xenctl
	ant -buildfile build-web.xml remove || true
	ant -buildfile build-web.xml install

clean-web:
	ant -buildfile build-web.xml clean
	rm -f xenctl-web.jar

FORCE:
