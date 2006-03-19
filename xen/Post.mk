
subdirs-all := $(subdirs-y) $(subdirs-n)

obj-y += $(patsubst %,%/built_in.o,$(subdirs-y))

default: built_in.o
built_in.o: $(obj-y)
	$(LD) $(LDFLAGS) -r -o $@ $^

.PHONY: FORCE
FORCE:

%/built_in.o: FORCE
	$(MAKE) -C $*

clean: $(addprefix _clean_, $(subdirs-all))
	rm -f *.o *~ core
_clean_%/: FORCE
	$(MAKE) -C $* clean
