# Order is important!
SUBDIRS=gui memory iodev

all: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@

.PHONY: all $(SUBDIRS)

clean:
	@for subdir in $(SUBDIRS); do 				\
		$(MAKE) -C $$subdir $(MAKEDEFS) $@ || exit -1; 	\
	done

install:
	@for subdir in $(SUBDIRS); do 				\
		$(MAKE) -C $$subdir $(MAKEDEFS) $@ || exit -1; 	\
	done
