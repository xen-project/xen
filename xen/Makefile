
export BASEDIR := $(shell pwd)

GENERATED_FILES := include/xeno/compile.h

include Rules.mk

default: $(TARGET)
	gzip -f -9 < $(TARGET) > $(TARGET).gz

debug:	
	objdump -D -S image >image.s

install: $(TARGET)
	gzip -f -9 < $(TARGET) > $(TARGET).gz
	cp $(TARGET).gz ../../install/images/image

clean: delete-links
	$(MAKE) -C tools clean
	$(MAKE) -C common clean
	$(MAKE) -C net clean
	$(MAKE) -C drivers clean
	$(MAKE) -C arch/$(ARCH) clean
	rm -f *.o $(TARGET)* *~ core $(GENERATED_FILES)

$(TARGET): delete-unfresh-files make-links $(GENERATED_FILES)
	$(MAKE) -C tools
	$(MAKE) -C common
	$(MAKE) -C net
	$(MAKE) -C drivers
	$(MAKE) -C arch/$(ARCH)

make-links: delete-links
	ln -sf xeno include/linux
	ln -sf asm-$(ARCH) include/asm

delete-links:
	rm -f include/linux include/asm

# NB. kernel.o is blown away as the build date is stored statically within it
#     Basically it's the only file dependent on compile.h -- we blow that
#     dependency away for all other files in Rules.mk.
delete-unfresh-files:
	rm -f $(GENERATED_FILES) common/kernel.o

include/xeno/compile.h:
	@LANG=C echo \#define XEN_COMPILE_DATE \"`date`\" > $@
	@LANG=C echo \#define XEN_COMPILE_TIME \"`date +%T`\" >> $@
	@LANG=C echo \#define XEN_COMPILE_BY \"`whoami`\" >> $@
	@LANG=C echo \#define XEN_COMPILE_DOMAIN \"`([ -x /bin/dnsdomainname ] && /bin/dnsdomainname) || ([ -x /bin/domainname ] && /bin/domainname || echo [unknown])`\" >> $@
	@LANG=C echo \#define XEN_COMPILE_HOST \"`hostname`\" >> $@
	@LANG=C echo \#define XEN_COMPILER \"`$(CC) $(CFLAGS) -v 2>&1 | tail -1`\" >> $@

.PHONY: $(GENERATED_FILES) make-links delete-links default debug install clean delete-unfresh-files


SUBDIRS         =arch common drivers net 
TAGS: 
	etags `find include/asm-$(ARCH) -name '*.h'`
	find include -type d \( -name "asm-*" -o -name config \) -prune -o -name '*.h' -print | xargs etags -a
	find $(SUBDIRS) -name '*.[ch]' | xargs etags -a

MAP:
	nm image | grep -v '\(compiled\)\|\(\.o$$\)\|\( [aUw] \)\|\(\.\.ng$$\)\|\(LASH[RL]DI\)' | sort > System.map
