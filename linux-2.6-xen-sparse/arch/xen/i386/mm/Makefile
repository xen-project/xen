#
# Makefile for the linux i386-specific parts of the memory manager.
#

XENARCH	:= $(subst ",,$(CONFIG_XENARCH))

CFLAGS	+= -Iarch/$(XENARCH)/mm

obj-y	:= init.o pgtable.o fault.o ioremap.o hypervisor.o
c-obj-y	:= extable.o mmap.o pageattr.o

c-obj-$(CONFIG_DISCONTIGMEM)	+= discontig.o
c-obj-$(CONFIG_HUGETLB_PAGE) += hugetlbpage.o
obj-$(CONFIG_HIGHMEM) += highmem.o
c-obj-$(CONFIG_BOOT_IOREMAP) += boot_ioremap.o

c-link	:=

$(patsubst %.o,$(obj)/%.c,$(c-obj-y) $(c-link)):
	@ln -fsn $(srctree)/arch/i386/mm/$(notdir $@) $@

obj-y	+= $(c-obj-y)

clean-files += $(patsubst %.o,%.c,$(c-obj-y) $(c-obj-) $(c-link))
