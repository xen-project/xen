
.S.o:
	$(CC) $(AFLAGS) -c $< -o $*.o

L_TARGET = lib.a

obj-y = checksum.o old-checksum.o delay.o \
	usercopy.o getuser.o \
	memcpy.o strstr.o xen_proc.o

obj-$(CONFIG_X86_USE_3DNOW) += mmx.o
obj-$(CONFIG_HAVE_DEC_LOCK) += dec_and_lock.o
obj-$(CONFIG_DEBUG_IOVIRT)  += iodebug.o

include $(TOPDIR)/Rules.make
