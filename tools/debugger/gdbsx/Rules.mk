include $(XEN_ROOT)/tools/Rules.mk

CFLAGS   += -Wmissing-prototypes
# (gcc 4.3x and later)   -Wconversion -Wno-sign-conversion

CFLAGS-$(clang) += -Wno-ignored-attributes
