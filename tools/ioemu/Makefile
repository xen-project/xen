# Order is important!
SUBDIRS=gui memory iodev

.PHONY: all clean install

all:
	@for subdir in $(SUBDIRS); do 				\
		$(MAKE) -C $$subdir $(MAKEDEFS) $@ || exit -1; 	\
	done

clean:
	@for subdir in $(SUBDIRS); do 				\
		$(MAKE) -C $$subdir $(MAKEDEFS) $@ || exit -1; 	\
	done

install:
	@for subdir in $(SUBDIRS); do 				\
		$(MAKE) -C $$subdir $(MAKEDEFS) $@ || exit -1; 	\
	done
