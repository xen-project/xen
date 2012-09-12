obj-$(x86_64) += common.o guest_2.o guest_3.o guest_4.o

guest_%.o: multi.c Makefile
	$(CC) $(CFLAGS) -DGUEST_PAGING_LEVELS=$* -c $< -o $@
