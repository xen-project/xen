subdir-y += dig
subdir-y += hp
subdir-y += sn

obj-y += bitop.o
obj-y += clear_page.o
obj-y += clear_user.o
obj-y += copy_page_mck.o
obj-y += efi_stub.o
obj-y += extable.o
obj-y += flush.o
obj-y += hpsim.o
obj-y += linuxextable.o
obj-y += machvec.o
obj-y += memcpy_mck.o
obj-y += memset.o
obj-y += numa.o
obj-y += pal.o
obj-y += strlen.o

obj-y += __divsi3.o
obj-y += __udivsi3.o
obj-y += __modsi3.o
obj-y += __umodsi3.o
obj-y += __divdi3.o
obj-y += __udivdi3.o
obj-y += __moddi3.o
obj-y += __umoddi3.o
obj-y += carta_random.o
obj-y += io.o

## variants of divide/modulo
## see files in xen/arch/ia64/linux/lib (linux/arch/ia64/lib)
__divdi3.o: idiv64.S
	$(CC) $(AFLAGS) $(AFLAGS_KERNEL) -c -o $@ $<

__udivdi3.o: idiv64.S
	$(CC) $(AFLAGS) $(AFLAGS_KERNEL) -c -DUNSIGNED -c -o $@ $<

__moddi3.o: idiv64.S
	$(CC) $(AFLAGS) $(AFLAGS_KERNEL) -c -DMODULO -c -o $@ $<

__umoddi3.o: idiv64.S
	$(CC) $(AFLAGS) $(AFLAGS_KERNEL) -c -DMODULO -DUNSIGNED -c -o $@ $<

__divsi3.o: idiv32.S
	$(CC) $(AFLAGS) $(AFLAGS_KERNEL) -c -o $@ $<

__udivsi3.o: idiv32.S
	$(CC) $(AFLAGS) $(AFLAGS_KERNEL) -c -DUNSIGNED -c -o $@ $<

__modsi3.o: idiv32.S
	$(CC) $(AFLAGS) $(AFLAGS_KERNEL) -c -DMODULO -c -o $@ $<

__umodsi3.o: idiv32.S
	$(CC) $(AFLAGS) $(AFLAGS_KERNEL) -c -DMODULO -DUNSIGNED -c -o $@ $<

