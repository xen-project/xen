include $(src)/Makefile.libfdt

SECTIONS := text data $(SPECIAL_DATA_SECTIONS)
OBJCOPYFLAGS := $(foreach s,$(SECTIONS),--rename-section .$(s)=.init.$(s))

obj-y += libfdt.o
nocov-y += libfdt.o

CFLAGS-y += -I$(BASEDIR)/include/xen/libfdt/

$(obj)/libfdt.o: $(obj)/libfdt-temp.o FORCE
	$(call if_changed,objcopy)

$(obj)/libfdt-temp.o: $(addprefix $(obj)/,$(LIBFDT_OBJS)) FORCE
	$(call if_changed,ld)

extra-y += libfdt-temp.o $(LIBFDT_OBJS)
