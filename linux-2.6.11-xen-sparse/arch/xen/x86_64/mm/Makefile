#
# Makefile for the linux x86_64-specific parts of the memory manager.
#

XENARCH	:= $(subst ",,$(CONFIG_XENARCH))

CFLAGS	+= -Iarch/$(XENARCH)/mm

obj-y	:= init.o fault.o ioremap.o pageattr.o hypervisor.o
c-obj-y	:= extable.o

#obj-y	 := init.o fault.o ioremap.o extable.o pageattr.o
#c-obj-$(CONFIG_HUGETLB_PAGE) += hugetlbpage.o
c-obj-$(CONFIG_DISCONTIGMEM) += numa.o
c-obj-$(CONFIG_K8_NUMA) += k8topology.o

hugetlbpage-y = ../../../i386/mm/hugetlbpage.o

c-link	:=

$(patsubst %.o,$(obj)/%.c,$(c-obj-y) $(c-link)):
	@ln -fsn $(srctree)/arch/x86_64/mm/$(notdir $@) $@

obj-y	+= $(c-obj-y)

clean-files += $(patsubst %.o,%.c,$(c-obj-y) $(c-obj-) $(c-link))
