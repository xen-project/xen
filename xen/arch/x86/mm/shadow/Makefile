ifeq ($(CONFIG_SHADOW_PAGING),y)
obj-y += common.o guest_2.o guest_3.o guest_4.o
else
obj-y += none.o
endif

guest_%.o: multi.c Makefile
	$(CC) $(CFLAGS) -DGUEST_PAGING_LEVELS=$* -c $< -o $@
