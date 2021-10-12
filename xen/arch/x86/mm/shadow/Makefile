ifeq ($(CONFIG_SHADOW_PAGING),y)
obj-y += common.o set.o
obj-$(CONFIG_HVM) += hvm.o guest_2.o guest_3.o guest_4.o
obj-$(CONFIG_PV) += pv.o guest_4.o
else
obj-y += none.o
endif
