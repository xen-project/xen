obj-y += hap.o
obj-y += guest_walk_2level.o
obj-y += guest_walk_3level.o
obj-y += guest_walk_4level.o
obj-y += nested_hap.o
obj-y += nested_ept.o

guest_walk_%level.o: guest_walk.c Makefile
	$(CC) $(c_flags) -DGUEST_PAGING_LEVELS=$* -c $< -o $@

guest_walk_%level.i: guest_walk.c Makefile
	$(CPP) $(filter-out -Wa$(comma)%,$(c_flags)) -DGUEST_PAGING_LEVELS=$* -c $< -o $@

guest_walk_%level.s: guest_walk.c Makefile
	$(CC) $(filter-out -Wa$(comma)%,$(c_flags)) -DGUEST_PAGING_LEVELS=$* -S $< -o $@
