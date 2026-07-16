# Put this ahead of the sorted list below, as it takes long to build and hence
# we'd like parallel make to schedule its building early.
obj-y += x86_emulate.o

ifneq ($(CONFIG_HVM),y)
$(obj)/x86_emulate.o: CFLAGS-y += -Wno-unused-label
endif
ifeq ($(CONFIG_CONDITION_COVERAGE)$(CONFIG_CC_IS_GCC),yy)
$(obj)/x86_emulate.o: CFLAGS-y += -Wno-error=coverage-too-many-conditions
endif

obj-y += 0f01.o
obj-y += 0fae.o
obj-y += 0fc7.o
obj-y += blk.o
obj-y += decode.o
obj-$(CONFIG_HVM) += fpu.o
obj-y += util.o
obj-y += util-xen.o
