
all: build

# Check this machine is OK for building on.
build:
	./chk build

# Check this machine is OK for installing on.
# DO NOT use this check from 'make install' in the parent
# directory, as that target can be used to make an installable
# copy rather than actually installing.
install:
	./chk install

clean:
	./chk clean