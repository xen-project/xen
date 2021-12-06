XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

SRCS-y       += xc_altp2m.c
SRCS-y       += xc_cpupool.c
SRCS-y       += xc_domain.c
SRCS-y       += xc_evtchn.c
SRCS-y       += xc_gnttab.c
SRCS-y       += xc_misc.c
SRCS-y       += xc_flask.c
SRCS-y       += xc_physdev.c
SRCS-y       += xc_private.c
SRCS-y       += xc_csched.c
SRCS-y       += xc_csched2.c
SRCS-y       += xc_arinc653.c
SRCS-y       += xc_rt.c
SRCS-y       += xc_tbuf.c
SRCS-y       += xc_pm.c
SRCS-y       += xc_cpu_hotplug.c
SRCS-y       += xc_vm_event.c
SRCS-y       += xc_vmtrace.c
SRCS-y       += xc_monitor.c
SRCS-y       += xc_mem_paging.c
SRCS-y       += xc_mem_access.c
SRCS-y       += xc_memshr.c
SRCS-y       += xc_hcall_buf.c
SRCS-y       += xc_foreign_memory.c
SRCS-y       += xc_kexec.c
SRCS-y       += xc_resource.c
SRCS-$(CONFIG_X86) += xc_psr.c
SRCS-$(CONFIG_X86) += xc_pagetab.c
SRCS-$(CONFIG_Linux) += xc_linux.c
SRCS-$(CONFIG_FreeBSD) += xc_freebsd.c
SRCS-$(CONFIG_SunOS) += xc_solaris.c
SRCS-$(CONFIG_NetBSD) += xc_netbsd.c
SRCS-$(CONFIG_NetBSDRump) += xc_netbsd.c
SRCS-$(CONFIG_MiniOS) += xc_minios.c
SRCS-y       += xc_evtchn_compat.c
SRCS-y       += xc_gnttab_compat.c
SRCS-y       += xc_devicemodel_compat.c

CFLAGS   += -D__XEN_TOOLS__
CFLAGS	+= $(PTHREAD_CFLAGS)
CFLAGS += -include $(XEN_ROOT)/tools/config.h

# Needed for posix_fadvise64() in xc_linux.c
CFLAGS-$(CONFIG_Linux) += -D_GNU_SOURCE

LIBHEADER := xenctrl.h xenctrl_compat.h
PKG_CONFIG := xencontrol.pc
PKG_CONFIG_NAME := Xencontrol

NO_HEADERS_CHK := y

include $(XEN_ROOT)/tools/libs/libs.mk

-include $(DEPS_INCLUDE)

clean: cleanlocal

.PHONY: cleanlocal
cleanlocal:
	rm -f libxenctrl.map
