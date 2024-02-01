include $(src)/Makefile.libfdt

SECTIONS := text data $(SPECIAL_DATA_SECTIONS)

# For CONFIG_OVERLAY_DTB, libfdt functionalities will be needed during runtime.
ifneq ($(CONFIG_OVERLAY_DTB),y)
OBJCOPYFLAGS := $(foreach s,$(SECTIONS),--rename-section .$(s)=.init.$(s))
nocov-y += libfdt.o
endif

obj-y += libfdt.o

CFLAGS-y += -I$(srctree)/include/xen/libfdt/

$(obj)/libfdt.o: $(obj)/libfdt-temp.o FORCE
	$(call if_changed,objcopy)

$(obj)/libfdt-temp.o: $(addprefix $(obj)/,$(LIBFDT_OBJS)) FORCE
	$(call if_changed,ld)

targets += libfdt-temp.o $(LIBFDT_OBJS)
