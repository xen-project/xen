default:
	ant dist

install: default
	cp -a vdmanager vdmanager.jar ../../../install/bin
	chmod 755 ../../../install/bin/vdmanager
clean:
	ant clean
	rm -f vdmanager.jar
