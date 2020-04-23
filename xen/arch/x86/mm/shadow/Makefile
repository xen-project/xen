ifeq ($(CONFIG_SHADOW_PAGING),y)
obj-y += common.o guest_2.o guest_3.o guest_4.o
obj-$(CONFIG_HVM) += hvm.o
obj-$(CONFIG_PV) += pv.o
else
obj-y += none.o
endif

guest_%.o: multi.c Makefile
	$(CC) $(c_flags) -DGUEST_PAGING_LEVELS=$* -c $< -o $@

guest_%.i: multi.c Makefile
	$(CPP) $(filter-out -Wa$(comma)%,$(c_flags)) -DGUEST_PAGING_LEVELS=$* -c $< -o $@

guest_%.s: multi.c Makefile
	$(CC) $(filter-out -Wa$(comma)%,$(c_flags)) -DGUEST_PAGING_LEVELS=$* -S $< -o $@
