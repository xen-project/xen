default:
	ant dist

install: default
	cp domctl.jar domctl ../../../install/bin
	chmod 755 ../../../install/bin/domctl
clean:
	ant clean
	rm -f domctl.jar
