obj-y += hap.o
obj-y += guest_walk_2level.o
obj-y += guest_walk_3level.o
obj-$(x86_64) += guest_walk_4level.o
obj-y += nested_hap.o
obj-y += nested_ept.o

guest_walk_%level.o: guest_walk.c Makefile
	$(CC) $(CFLAGS) -DGUEST_PAGING_LEVELS=$* -c $< -o $@
