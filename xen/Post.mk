# Ensure each subdirectory has exactly one trailing slash.
subdir-n := $(patsubst %,%/,$(patsubst %/,%,$(subdir-n)))
subdir-y := $(patsubst %,%/,$(patsubst %/,%,$(subdir-y)))

# Add explicitly declared subdirectories to the object list.
obj-y += $(patsubst %,%/built_in.o,$(subdir-y))

# Add implicitly declared subdirectories (in the object list) to the
# subdirectory list, and rewrite the object-list entry.
subdir-y += $(filter %/,$(obj-y))
obj-y    := $(patsubst %/,%/built-in.o,$(obj-y))

subdir-all := $(subdir-y) $(subdir-n)

built_in.o: $(obj-y)
	$(LD) $(LDFLAGS) -r -o $@ $^

.PHONY: FORCE
FORCE:

%/built_in.o: FORCE
	$(MAKE) -C $*

clean:: $(addprefix _clean_, $(subdir-all)) FORCE
	rm -f *.o *~ core
_clean_%/: FORCE
	$(MAKE) -C $* clean
