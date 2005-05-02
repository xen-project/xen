#
# Makefile for ia64-specific library routines..
#

include $(BASEDIR)/Rules.mk

OBJS := __divsi3.o __udivsi3.o __modsi3.o __umodsi3.o			\
	__divdi3.o __udivdi3.o __moddi3.o __umoddi3.o			\
	bitop.o checksum.o clear_page.o csum_partial_copy.o copy_page.o	\
	clear_user.o strncpy_from_user.o strlen_user.o strnlen_user.o	\
	flush.o ip_fast_csum.o do_csum.o copy_user.o			\
	memset.o strlen.o memcpy.o

default: $(OBJS)
	$(LD) -r -o ia64lib.o $(OBJS)

AFLAGS += -I$(BASEDIR)/include -D__ASSEMBLY__

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

clean:
	rm -f *.o *~
