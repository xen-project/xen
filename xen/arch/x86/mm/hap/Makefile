obj-y += hap.o
obj-y += guest_walk_2level.o
obj-y += guest_walk_3level.o
obj-y += guest_walk_4level.o

guest_levels  = $(subst level,,$(filter %level,$(subst ., ,$(subst _, ,$(1)))))
guest_walk_defns = -DGUEST_PAGING_LEVELS=$(call guest_levels,$(1))

guest_walk_%level.o: guest_walk.c $(HDRS) Makefile
	$(CC) $(CFLAGS) $(call guest_walk_defns,$(@F)) -c $< -o $@
