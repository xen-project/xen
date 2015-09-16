include $(XEN_ROOT)/Config.mk

CODE_ADDR=$(shell nm --defined $(1) | grep $(2) | awk '{print "0x"$$1}')
CODE_SZ=$(shell nm --defined -S $(1) | grep $(2) | awk '{ print "0x"$$2}')

.PHONY: default

XSPLICE := xen_hello_world.xsplice

default: xsplice

install: xsplice
	$(INSTALL_DATA) $(XSPLICE) $(DESTDIR)$(DEBUG_DIR)/$(XSPLICE)
uninstall:
	rm -f $(DESTDIR)$(DEBUG_DIR)/$(XSPLICE)

.PHONY: clean
clean::
	rm -f *.o .*.o.d *.xsplice config.h

#
# To compute these values we need the binary files: xen-syms
# and xen_hello_world_func.o to be already compiled.
#
.PHONY: config.h
config.h: OLD_CODE=$(call CODE_ADDR,$(BASEDIR)/xen-syms,xen_extra_version)
config.h: OLD_CODE_SZ=$(call CODE_SZ,$(BASEDIR)/xen-syms,xen_extra_version)
config.h: NEW_CODE_SZ=$(call CODE_SZ,$<,xen_hello_world)
config.h: xen_hello_world_func.o
	(set -e; \
	 echo "#define NEW_CODE_SZ $(NEW_CODE_SZ)"; \
	 echo "#define OLD_CODE_SZ $(OLD_CODE_SZ)"; \
	 echo "#define OLD_CODE $(OLD_CODE)") > $@

xen_hello_world.o: config.h

.PHONY: $(XSPLICE)
$(XSPLICE): xen_hello_world_func.o xen_hello_world.o
	$(LD) $(LDFLAGS) -r -o $(XSPLICE) $^

.PHONY: xsplice
xsplice: $(XSPLICE)
