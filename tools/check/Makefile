
.PHONY: all
all: build

# Check this machine is OK for building on.
.PHONY: build
build:
	./chk build

# Check this machine is OK for installing on.
# DO NOT use this check from 'make install' in the parent
# directory, as that target can be used to make an installable
# copy rather than actually installing.
.PHONY: install
install:
	./chk install

.PHONY: clean
clean:
	./chk clean
