
export BASEDIR := $(shell pwd)

include Rules.mk

default: $(TARGET)
	gzip -f -9 < $(TARGET) > $(TARGET).gz
#	objdump -D -S image >image.s

install: $(TARGET)
	gzip -f -9 < $(TARGET) > $(TARGET).gz
	cp $(TARGET).gz ../../install/images/image

clean: delete-links
	$(MAKE) -C tools clean
	$(MAKE) -C common clean
	$(MAKE) -C net clean
	$(MAKE) -C drivers clean
	$(MAKE) -C arch/$(ARCH) clean
	rm -f *.o $(TARGET)* *~ core

$(TARGET): make-links
	$(MAKE) -C tools
	$(MAKE) -C common
	$(MAKE) -C net
	$(MAKE) -C drivers
	$(MAKE) -C arch/$(ARCH)

make-links:
	ln -sf xeno include/linux
	ln -sf asm-$(ARCH) include/asm

delete-links:
	rm -f include/linux include/asm

SUBDIRS         =arch common drivers net 
TAGS: 
	etags `find include/asm-$(ARCH) -name '*.h'`
	find include -type d \( -name "asm-*" -o -name config \) -prune -o -name '*.h' -print | xargs etags -a
	find $(SUBDIRS) -name '*.[ch]' | xargs etags -a

MAP:
	nm image | grep -v '\(compiled\)\|\(\.o$$\)\|\( [aUw] \)\|\(\.\.ng$$\)\|\(LASH[RL]DI\)' | sort > System.map
