subdir-y += shadow
subdir-y += hap

obj-y += paging.o
obj-y += p2m.o p2m-pt.o p2m-ept.o p2m-pod.o
obj-y += guest_walk_2.o
obj-y += guest_walk_3.o
obj-$(x86_64) += guest_walk_4.o
obj-$(x86_64) += mem_paging.o
obj-$(x86_64) += mem_sharing.o

guest_walk_%.o: guest_walk.c Makefile
	$(CC) $(CFLAGS) -DGUEST_PAGING_LEVELS=$* -c $< -o $@
