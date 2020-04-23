obj-y += shadow/
obj-$(CONFIG_HVM) += hap/

obj-$(CONFIG_HVM) += altp2m.o
obj-$(CONFIG_HVM) += guest_walk_2.o guest_walk_3.o guest_walk_4.o
obj-$(CONFIG_SHADOW_PAGING) += guest_walk_2.o guest_walk_3.o guest_walk_4.o
obj-$(CONFIG_MEM_ACCESS) += mem_access.o
obj-y += mem_paging.o
obj-$(CONFIG_MEM_SHARING) += mem_sharing.o
obj-y += p2m.o p2m-pt.o
obj-$(CONFIG_HVM) += p2m-ept.o p2m-pod.o
obj-y += paging.o

guest_walk_%.o: guest_walk.c Makefile
	$(CC) $(c_flags) -DGUEST_PAGING_LEVELS=$* -c $< -o $@

guest_walk_%.i: guest_walk.c Makefile
	$(CPP) $(filter-out -Wa$(comma)%,$(c_flags)) -DGUEST_PAGING_LEVELS=$* -c $< -o $@

guest_walk_%.s: guest_walk.c Makefile
	$(CC) $(filter-out -Wa$(comma)%,$(c_flags)) -DGUEST_PAGING_LEVELS=$* -S $< -o $@
