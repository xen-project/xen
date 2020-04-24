include Makefile.libfdt

SECTIONS := text data $(SPECIAL_DATA_SECTIONS)

obj-y += libfdt.o
nocov-y += libfdt.o

CFLAGS-y += -I$(BASEDIR)/include/xen/libfdt/

libfdt.o: libfdt-temp.o Makefile
	$(OBJCOPY) $(foreach s,$(SECTIONS),--rename-section .$(s)=.init.$(s)) $< $@

libfdt-temp.o: $(LIBFDT_OBJS)
	$(LD) $(XEN_LDFLAGS) -r -o $@ $^
