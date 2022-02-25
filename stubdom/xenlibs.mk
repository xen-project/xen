include $(XEN_ROOT)/tools/Rules.mk

include Makefile.common

LIBNAME := $(notdir $(CURDIR))
FILENAME_$(LIBNAME) ?= xen$(LIBNAME)
LIB_FILE_NAME = $(FILENAME_$(LIBNAME))

lib$(LIB_FILE_NAME).a: $(OBJS-y)
	$(AR) rc $@ $^

clean::
	rm -f $(OBJS-y) lib$(LIB_FILE_NAME).a
