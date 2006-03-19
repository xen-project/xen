
subdirs-all := $(subdirs-y) $(subdirs-n)

default: $(subdirs-y)

.PHONY: FORCE
FORCE:

%/: FORCE
	$(MAKE) -C $*

clean: $(addprefix _clean_, $(subdirs-all))
_clean_%/: FORCE
	$(MAKE) -C $* clean

