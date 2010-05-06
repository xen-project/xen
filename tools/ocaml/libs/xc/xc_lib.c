/*
 * Copyright (C) 2006-2007 XenSource Ltd.
 * Copyright (C) 2008      Citrix Ltd.
 * Author Vincent Hanquez <vincent.hanquez@eu.citrix.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdarg.h>

#include "xc.h"

#define PAGE_SHIFT		12
#define PAGE_SIZE               (1UL << PAGE_SHIFT)
#define PAGE_MASK               (~(PAGE_SIZE-1))

#define MIN(a, b) 		(((a) < (b)) ? (a) : (b))

#define DECLARE_DOMCTL(_cmd, _domain)	\
	struct xen_domctl domctl = {    \
		.cmd = _cmd,		\
		.domain = _domain,	\
		.interface_version = XEN_DOMCTL_INTERFACE_VERSION, \
	}

#define DECLARE_SYSCTL(_cmd)		\
	struct xen_sysctl sysctl = {	\
		.cmd = _cmd,		\
		.interface_version = XEN_SYSCTL_INTERFACE_VERSION, \
	}

#define DECLARE_HYPERCALL2(_cmd, _arg0, _arg1)	\
	privcmd_hypercall_t hypercall = {	\
		.op = _cmd,			\
		.arg[0] = (unsigned long) _arg0,\
		.arg[1] = (unsigned long) _arg1,\
	}
#define DECLARE_HYPERCALL0(_cmd)	DECLARE_HYPERCALL2(_cmd, 0, 0);
#define DECLARE_HYPERCALL1(_cmd, _arg0)	DECLARE_HYPERCALL2(_cmd, _arg0, 0);

/*---- Errors handlings ----*/
#ifndef WITHOUT_GOOD_ERROR
#define ERROR_STRLEN 256

static char __error_str[ERROR_STRLEN];

char * xc_error_get(void)
{
	return __error_str;
}

static void xc_error_set(const char *fmt, ...)
{
	va_list ap;
	char __errordup[ERROR_STRLEN];

	va_start(ap, fmt);
	vsnprintf(__errordup, ERROR_STRLEN, fmt, ap);
	va_end(ap);
	memcpy(__error_str, __errordup, ERROR_STRLEN);
}

static void xc_error_dom_set(unsigned int domid, const char *fmt, ...)
{
	va_list ap;
	char __errordup[ERROR_STRLEN];
	int i;

	i = snprintf(__errordup, ERROR_STRLEN, "domain %u - ", domid);
	va_start(ap, fmt);
	i += vsnprintf(__errordup + i, ERROR_STRLEN - i, fmt, ap);
	va_end(ap);
	snprintf(__errordup + i, ERROR_STRLEN - i,
	         " failed: %s", xc_error_get());
	memcpy(__error_str, __errordup, ERROR_STRLEN);
}

void xc_error_clear(void)
{
	memset(__error_str, '\0', ERROR_STRLEN);
}
#else
char * xc_error_get(void)
{
	return "";
}
#define xc_error_set(fmt, ...) do {} while (0)
#define xc_error_dom_set(id, fmt, ...) do {} while (0)
#define xc_error_clear() do {} while (0)
#endif

#define xc_error_hypercall(_h, _r) \
	xc_error_set("hypercall %lld fail: %d: %s (ret %d)", _h.op, errno, errno ? strerror(errno) : strerror(-_r), _r)

int xc_using_injection(void)
{
	return 0;
}

/*---- Trivia ----*/
int xc_interface_open(void)
{
	int fd, ret;

	fd = open("/proc/xen/privcmd", O_RDWR);
	if (fd == -1) {
		xc_error_set("open /proc/xen/privcmd failed: %s",
		             strerror(errno));
		return -1;
	}

	ret = fcntl(fd, F_GETFD);
	if (ret < 0) {
		xc_error_set("cannot get handle flags: %s",
		             strerror(errno));
		goto out;
	}

	ret = fcntl(fd, F_SETFD, ret | FD_CLOEXEC);
	if (ret < 0) {
		xc_error_set("cannot set handle flags: %s",
		             strerror(errno));
		goto out;
	}

	return fd;
out:
	close(fd);
	return -1;
}

int xc_interface_close(int handle)
{
	int ret;

	ret = close(handle);
	if (ret != 0)
		xc_error_set("close xc failed: %s", strerror(errno));
	return ret;
}

/*---- Low private operations ----*/
static int do_xen_hypercall(int handle, privcmd_hypercall_t *hypercall)
{
	return ioctl(handle, IOCTL_PRIVCMD_HYPERCALL, (unsigned long) hypercall);
}

static int do_domctl(int handle, struct xen_domctl *domctl)
{
	int ret;
	DECLARE_HYPERCALL1(__HYPERVISOR_domctl, domctl);

	if (mlock(domctl, sizeof(*domctl)) != 0) {
		xc_error_set("mlock failed: %s", strerror(errno));
		return -1;
	}

	ret = do_xen_hypercall(handle, &hypercall);
	if (ret < 0)
		xc_error_hypercall(hypercall, ret);

	munlock(domctl, sizeof(*domctl));
	return ret;
}

static int do_sysctl(int handle, struct xen_sysctl *sysctl)
{
	int ret;
	DECLARE_HYPERCALL1(__HYPERVISOR_sysctl, sysctl);

	if (mlock(sysctl, sizeof(*sysctl)) != 0) {
		xc_error_set("mlock failed: %s", strerror(errno));
		return -1;
	}

	ret = do_xen_hypercall(handle, &hypercall);
	if (ret < 0)
		xc_error_hypercall(hypercall, ret);

	munlock(sysctl, sizeof(*sysctl));
	return ret;
}

static int do_evtchnctl(int handle, int cmd, void *arg, size_t arg_size)
{
	DECLARE_HYPERCALL2(__HYPERVISOR_event_channel_op, cmd, arg);
	int ret;

	if (mlock(arg, arg_size) != 0) {
		xc_error_set("mlock failed: %s", strerror(errno));
		return -1;
	}

	ret = do_xen_hypercall(handle, &hypercall);
	if (ret < 0)
		xc_error_hypercall(hypercall, ret);
	munlock(arg, arg_size);
	return ret;
}

static int do_memctl_reservation(int handle, int cmd,
                                 struct xen_memory_reservation *reservation)
{
	int ret;
	DECLARE_HYPERCALL2(__HYPERVISOR_memory_op, cmd, reservation);
	xen_pfn_t *extent_start;

	if (cmd != XENMEM_increase_reservation &&
	    cmd != XENMEM_decrease_reservation &&
	    cmd != XENMEM_populate_physmap) {
		xc_error_set("do_memctl_reservation: unknown cmd %d", cmd);
		return -EINVAL;
	}

	if (mlock(reservation, sizeof(*reservation)) == -1) {
		xc_error_set("mlock failed: %s", strerror(errno));
		return -ENOMEM;
	}
	get_xen_guest_handle(extent_start, reservation->extent_start);
	if (extent_start && mlock(extent_start, reservation->nr_extents
	                                      * sizeof(xen_pfn_t)) == -1) {
		xc_error_set("mlock failed: %s", strerror(errno));
		munlock(reservation, sizeof(*reservation));
		return -3;
	}

	ret = do_xen_hypercall(handle, &hypercall);
	if (ret)
		xc_error_hypercall(hypercall, ret);
	munlock(extent_start, reservation->nr_extents * sizeof(xen_pfn_t));
	get_xen_guest_handle(extent_start, reservation->extent_start);
	munlock(reservation, sizeof(*reservation));
	return ret;
}

static int do_ioctl(int handle, int cmd, void *arg)
{
	return ioctl(handle, cmd, arg);
}

static void * do_mmap(void *start, size_t length, int prot, int flags,
                      int fd, off_t offset)
{
	return mmap(start, length, prot, flags, fd, offset);
}

int xc_get_hvm_param(int handle, unsigned int domid,
                     int param, unsigned long *value)
{
	struct xen_hvm_param arg = {
		.domid = domid,
		.index = param,
	};
	DECLARE_HYPERCALL2(__HYPERVISOR_hvm_op, HVMOP_get_param,
	                   (unsigned long) &arg);
	int ret;

	if (mlock(&arg, sizeof(arg)) == -1) {
		xc_error_set("mlock failed: %s", strerror(errno));
		return -1;
	}

	ret = do_xen_hypercall(handle, &hypercall);
	if (ret)
		xc_error_hypercall(hypercall, ret);
	*value = arg.value;
	munlock(&arg, sizeof(arg));
	return ret;
}

static int xc_set_hvm_param(int handle, unsigned int domid,
                            int param, unsigned long value)
{
	struct xen_hvm_param arg = {
		.domid = domid,
		.index = param,
		.value = value,
	};
	DECLARE_HYPERCALL2(__HYPERVISOR_hvm_op, HVMOP_set_param, (unsigned long) &arg);
	int ret;

	if (mlock(&arg, sizeof(arg)) == -1) {
		xc_error_set("mlock failed: %s", strerror(errno));
		return -1;
	}

	ret = do_xen_hypercall(handle, &hypercall);
	if (ret)
		xc_error_hypercall(hypercall, ret);
	munlock(&arg, sizeof(arg));
	return ret;
}


/*---- XC API ----*/
int xc_domain_create(int handle, unsigned int ssidref,
                     xen_domain_handle_t dhandle,
                     unsigned int flags, unsigned int *pdomid)
{
	int ret;
	DECLARE_DOMCTL(XEN_DOMCTL_createdomain, *pdomid);
	domctl.u.createdomain.ssidref = ssidref;
	domctl.u.createdomain.flags = flags;
	memcpy(domctl.u.createdomain.handle, dhandle, sizeof(xen_domain_handle_t));

	ret = do_domctl(handle, &domctl);
	if (ret != 0) {
		xc_error_set("creating domain failed: %s", xc_error_get());
		return ret;
	}
	*pdomid = domctl.domain;
	return 0;
}

int xc_domain_pause(int handle, unsigned int domid)
{
	int ret;
	DECLARE_DOMCTL(XEN_DOMCTL_pausedomain, domid);

	ret = do_domctl(handle, &domctl);
	if (ret != 0)
		xc_error_dom_set(domid, "pause");
	return ret;
}

int xc_domain_unpause(int handle, unsigned int domid)
{
	int ret;
	DECLARE_DOMCTL(XEN_DOMCTL_unpausedomain, domid);

	ret = do_domctl(handle, &domctl);
	if (ret != 0)
		xc_error_dom_set(domid, "unpause");
	return ret;
}

/* return 1 if hvm domain got pv driver, 0 if not. -1 is error occurs */
int xc_hvm_check_pvdriver(int handle, unsigned int domid)
{
	int ret;
	unsigned long irq = 0;
	xc_domaininfo_t info;

	ret = xc_domain_getinfolist(handle, domid, 1, &info);
	if (ret != 1) {
		xc_error_set("domain getinfo failed: %s", strerror(errno));
		xc_error_dom_set(domid, "hvm_check_pvdriver");
		return -1;
	}

	if (!(info.flags & XEN_DOMINF_hvm_guest)) {
		xc_error_set("domain is not hvm");
		xc_error_dom_set(domid, "hvm_check_pvdriver");
		return -1;
	}
	xc_get_hvm_param(handle, domid, HVM_PARAM_CALLBACK_IRQ, &irq);
	return irq;
}

static int modify_returncode_register(int handle, unsigned int domid)
{
	int ret;
	xc_domaininfo_t info;
	xen_capabilities_info_t caps;
	vcpu_guest_context_any_t context;

	ret = xc_domain_getinfolist(handle, domid, 1, &info);
	if (ret != 1) {
		xc_error_set("domain getinfo failed: %s", strerror(errno));
		return -1;
	}

	/* HVM guests without PV drivers do not have a return code to modify */
	if (info.flags & XEN_DOMINF_hvm_guest) {
		unsigned long irq = 0;
		xc_get_hvm_param(handle, domid, HVM_PARAM_CALLBACK_IRQ, &irq);
		if (!irq)
			return 0;
	}

	ret = xc_version(handle, XENVER_capabilities, &caps);
	if (ret) {
		xc_error_set("could not get Xen capabilities");
		return ret;
	}

	ret = xc_vcpu_getcontext(handle, domid, 0, &context);
	if (ret) {
		xc_error_set("could not get vcpu 0 context");
		return ret;
	}

	if (!(info.flags & XEN_DOMINF_hvm_guest))
		context.c.user_regs.eax = 1;
	else if (strstr(caps, "x86_64"))
		context.x64.user_regs.eax = 1;
	else
		context.x32.user_regs.eax = 1;

	ret = xc_vcpu_setcontext(handle, domid, 0, &context);
	if (ret) {
		xc_error_set("could not set vcpu 0 context");
		return ret;
	}
	return 0;
}

int xc_domain_resume_fast(int handle, unsigned int domid)
{
	int ret;
	DECLARE_DOMCTL(XEN_DOMCTL_resumedomain, domid);

	ret = modify_returncode_register(handle, domid);
	if (ret != 0) {
		xc_error_dom_set(domid, "resume_fast");
		return ret;
	}

	ret = do_domctl(handle, &domctl);
	if (ret != 0)
		xc_error_dom_set(domid, "resume_fast");
	return ret;
}

int xc_domain_destroy(int handle, unsigned int domid)
{
	int ret;
	DECLARE_DOMCTL(XEN_DOMCTL_destroydomain, domid);

	do {
		ret = do_domctl(handle, &domctl);
	} while (ret && (errno == EAGAIN));
	if (ret != 0)
		xc_error_dom_set(domid, "destroy");
	return ret;
}

int xc_domain_shutdown(int handle, int domid, int reason)
{
	sched_remote_shutdown_t arg = {
		.domain_id = domid,
		.reason = reason,
	};
	DECLARE_HYPERCALL2(__HYPERVISOR_sched_op, SCHEDOP_remote_shutdown, &arg);
	int ret;

	if (mlock(&arg, sizeof(arg)) != 0) {
		xc_error_set("mlock failed: %s", strerror(errno));
		xc_error_dom_set(domid, "shutdown %d", reason);
		return -1;
	}

	ret = do_xen_hypercall(handle, &hypercall);
	if (ret < 0) {
		xc_error_hypercall(hypercall, ret);
		xc_error_dom_set(domid, "shutdown %d", reason);
	}
	munlock(&arg, sizeof(arg));
	return ret;
}

int xc_vcpu_setaffinity(int handle, unsigned int domid, int vcpu,
                        uint64_t cpumap)
{
	int ret;
	DECLARE_DOMCTL(XEN_DOMCTL_setvcpuaffinity, domid);
	domctl.u.vcpuaffinity.vcpu = vcpu;
	domctl.u.vcpuaffinity.cpumap.nr_cpus = sizeof(cpumap) * 8;

	set_xen_guest_handle(domctl.u.vcpuaffinity.cpumap.bitmap, (uint8_t *) &cpumap);

	if (mlock(&cpumap, sizeof(cpumap)) != 0) {
		xc_error_set("mlock failed: %s", strerror(errno));
		xc_error_dom_set(domid, "vcpu %d set affinity", vcpu);
		return -1;
	}

	ret = do_domctl(handle, &domctl);
	if (ret < 0)
		xc_error_dom_set(domid, "vcpu %d set affinity", vcpu);
	munlock(&cpumap, sizeof(cpumap));
	return ret;
}

int xc_vcpu_getaffinity(int handle, unsigned int domid, int vcpu,
                        uint64_t *cpumap)
{
	int ret;
	DECLARE_DOMCTL(XEN_DOMCTL_getvcpuaffinity, domid);
	domctl.u.vcpuaffinity.vcpu = vcpu;
	domctl.u.vcpuaffinity.cpumap.nr_cpus = sizeof(*cpumap) * 8;

	set_xen_guest_handle(domctl.u.vcpuaffinity.cpumap.bitmap, cpumap);

	if (mlock(cpumap, sizeof(*cpumap)) != 0) {
		xc_error_set("mlock failed: %s", strerror(errno));
		xc_error_dom_set(domid, "vcpu %d get affinity", vcpu);
		return -1;
	}

	ret = do_domctl(handle, &domctl);
	if (ret < 0)
		xc_error_dom_set(domid, "vcpu %d get affinity", vcpu);
	munlock(cpumap, sizeof(*cpumap));
	return ret;
}

int xc_vcpu_context_get(int handle, unsigned int domid, unsigned short vcpu,
                        struct vcpu_guest_context *ctxt)
{
	int ret;
	DECLARE_DOMCTL(XEN_DOMCTL_getvcpucontext, domid);
	domctl.u.vcpucontext.vcpu = vcpu;

	set_xen_guest_handle(domctl.u.vcpucontext.ctxt, ctxt);

	if (mlock(ctxt, sizeof(struct vcpu_guest_context)) != 0) {
		xc_error_set("mlock failed: %s", strerror(errno));
		xc_error_dom_set(domid, "vcpu %d get context", vcpu);
		return -1;
	}

	ret = do_domctl(handle, &domctl);
	if (ret < 0)
		xc_error_dom_set(domid, "vcpu %d get context", vcpu);
	munlock(ctxt, sizeof(struct vcpu_guest_context));

	return ret;
}

int xc_domain_getinfolist(int handle, unsigned int first_domain,
                          unsigned int max_domains, xc_domaininfo_t *info)
{
	int ret;
	DECLARE_SYSCTL(XEN_SYSCTL_getdomaininfolist);
	sysctl.u.getdomaininfolist.first_domain = first_domain;
	sysctl.u.getdomaininfolist.max_domains = max_domains;
	set_xen_guest_handle(sysctl.u.getdomaininfolist.buffer, info);

	if (mlock(info, max_domains * sizeof(xc_domaininfo_t)) != 0) {
		xc_error_set("getinfolist(%d, %u, %u, %x (%d)) failed: mlock failed: %s",
			     handle, first_domain, max_domains, info, sizeof(xc_domaininfo_t),
		             strerror(errno));
		return -1;
	}

	ret = do_sysctl(handle, &sysctl);
	if (ret < 0)
		xc_error_set("getinfolist(%d, %u, %u, %x (%d)) failed: %s", 
			     handle, first_domain, max_domains, info, sizeof(xc_domaininfo_t),
			     xc_error_get());
	else
		ret = sysctl.u.getdomaininfolist.num_domains;

	munlock(info, max_domains * sizeof(xc_domaininfo_t));
	return ret;
}

int xc_domain_getinfo(int handle, unsigned int domid, xc_domaininfo_t *info)
{
	int ret;
	ret = xc_domain_getinfolist(handle, domid, 1, info);
	if (ret != 1) {
		xc_error_set("getinfo failed: domain %d: %s", domid, xc_error_get());
		return -1;
	}

	/* If the requested domain didn't exist but there exists one with a 
	   higher domain ID, this will be returned. We consider this an error since
	   we only wanted info about a specific domain. */
	if (info->domain != domid) {
		xc_error_set("getinfo failed: domain %d nolonger exists", domid);
		return -1;
	}

	return 0;
}

int xc_domain_setmaxmem(int handle, unsigned int domid, unsigned int max_memkb)
{
	DECLARE_DOMCTL(XEN_DOMCTL_max_mem, domid);
	domctl.u.max_mem.max_memkb = max_memkb;
	int ret;

	ret = do_domctl(handle, &domctl);
	if (ret < 0)
		xc_error_dom_set(domid, "set max memory to %u", max_memkb);
	return ret;
}

int xc_domain_set_memmap_limit(int handle, unsigned int domid,
                               unsigned long map_limitkb)
{
	int ret;
	struct xen_foreign_memory_map fmap = {
		.domid = domid,
		.map = { .nr_entries = 1 }
	};
	struct e820entry e820 = {
		.addr = 0,
		.size = (uint64_t)map_limitkb << 10,
		.type = E820_RAM
	};
	DECLARE_HYPERCALL2(__HYPERVISOR_memory_op, XENMEM_set_memory_map, &fmap);

	set_xen_guest_handle(fmap.map.buffer, &e820);

	if (mlock(&fmap, sizeof(fmap)) != 0) {
		xc_error_set("set_memmap_limit failed: mlock failed: %s",
		             strerror(errno));
		return -1;
	}

	if (mlock(&e820, sizeof(e820)) != 0) {
		xc_error_set("set_memmap_limit failed: mlock failed: %s",
		             strerror(errno));
		munlock(&fmap, sizeof(fmap));
		return -1;
	}

	ret = do_xen_hypercall(handle, &hypercall);
	if (ret)
		xc_error_hypercall(hypercall, ret);

	munlock(&e820, sizeof(e820));
	munlock(&fmap, sizeof(fmap));
	return ret;
}

int xc_domain_set_time_offset(int handle, unsigned int domid, int time_offset)
{
	DECLARE_DOMCTL(XEN_DOMCTL_settimeoffset, domid);
	domctl.u.settimeoffset.time_offset_seconds = time_offset;
	int ret;

	ret = do_domctl(handle, &domctl);
	if (ret < 0)
		xc_error_dom_set(domid, "set time offset %d", time_offset);
	return ret;
}

int xc_domain_memory_increase_reservation(int handle, unsigned int domid,
                                          unsigned long nr_extents,
                                          unsigned int extent_order,
                                          unsigned int address_bits,
                                          xen_pfn_t *extent_start)
{
	int ret;
	struct xen_memory_reservation reservation = {
		.nr_extents   = nr_extents,
		.extent_order = extent_order,
		.COMPAT_FIELD_ADDRESS_BITS = address_bits,
		.domid        = domid
	};

	set_xen_guest_handle(reservation.extent_start, extent_start);

	ret = do_memctl_reservation(handle, XENMEM_increase_reservation,
	                            &reservation);
	if (ret != nr_extents) {
		xc_error_dom_set(domid, "increase reservation to %lu",
		                 nr_extents);
		return (ret >= 0) ? -1 : ret;
	}
	return 0;
}

int xc_domain_memory_decrease_reservation(int handle, unsigned int domid,
                                          unsigned long nr_extents,
                                          unsigned int extent_order,
                                          unsigned int address_bits,
                                          xen_pfn_t *extent_start)
{
	int ret;
	struct xen_memory_reservation reservation = {
		.nr_extents   = nr_extents,
		.extent_order = extent_order,
		.COMPAT_FIELD_ADDRESS_BITS = 0,
		.domid        = domid
	};

	set_xen_guest_handle(reservation.extent_start, extent_start);
	if (!extent_start) {
		xc_error_set("decrease reservation: extent start is NULL");
		return -EINVAL;
	}

	ret = do_memctl_reservation(handle, XENMEM_decrease_reservation,
	                            &reservation);
	if (ret < nr_extents) {
		xc_error_dom_set(domid, "decrease reservation to %lu",
		                 nr_extents);
		return (ret >= 0) ? -1 : ret;
	}
	return 0;
}

int xc_domain_memory_populate_physmap(int handle, unsigned int domid,
                                      unsigned long nr_extents,
                                      unsigned int extent_order,
                                      unsigned int address_bits,
                                      xen_pfn_t *extent_start)
{
	int ret;
	struct xen_memory_reservation reservation = {
		.nr_extents   = nr_extents,
		.extent_order = extent_order,
		.COMPAT_FIELD_ADDRESS_BITS = address_bits,
		.domid        = domid
	};

	set_xen_guest_handle(reservation.extent_start, extent_start);
	ret = do_memctl_reservation(handle, XENMEM_populate_physmap,
	                            &reservation);
	if (ret < nr_extents) {
		xc_error_dom_set(domid, "populate physmap");
		return (ret >= 0) ? -1 : ret;
	}
	return 0;
}

int xc_domain_setvmxassist(int handle, unsigned int domid, int use_vmxassist)
{
	int ret = 0;
#ifdef XEN_DOMCTL_setvmxassist
	DECLARE_DOMCTL(XEN_DOMCTL_setvmxassist, domid);
	domctl.u.setvmxassist.use_vmxassist = use_vmxassist;

	ret = do_domctl(handle, &domctl);
	if (ret)
		xc_error_dom_set(domid, "setting vmxassist to %d",
				 use_vmxassist);
#endif
	return ret;
}

int xc_domain_max_vcpus(int handle, unsigned int domid, unsigned int max)
{
	int ret;
	DECLARE_DOMCTL(XEN_DOMCTL_max_vcpus, domid);
	domctl.u.max_vcpus.max = max;

	ret = do_domctl(handle, &domctl);
	if (ret)
		xc_error_dom_set(domid, "setting max vcpus to %d", max);
	return ret;
}

int xc_domain_sethandle(int handle, unsigned int domid,
                        xen_domain_handle_t dhandle)
{
	int ret;
	DECLARE_DOMCTL(XEN_DOMCTL_setdomainhandle, domid);
	memcpy(domctl.u.setdomainhandle.handle, dhandle, sizeof(xen_domain_handle_t));

	ret = do_domctl(handle, &domctl);
	if (ret)
		xc_error_dom_set(domid, "set handle");
	return ret;
}

int xc_vcpu_getinfo(int handle, unsigned int domid, unsigned int vcpu,
                    xc_vcpuinfo_t *info)
{
	int ret;
	DECLARE_DOMCTL(XEN_DOMCTL_getvcpuinfo, domid);
	domctl.u.getvcpuinfo.vcpu = vcpu;

	ret = do_domctl(handle, &domctl);
	if (ret < 0) {
		xc_error_dom_set(domid, "vcpu %u getinfo", vcpu);
		return ret;
	}
	memcpy(info, &domctl.u.getvcpuinfo, sizeof(*info));
	return ret;
}

int xc_domain_ioport_permission(int handle, unsigned int domid,
                                unsigned int first_port, unsigned int nr_ports,
                                unsigned int allow_access)
{
	DECLARE_DOMCTL(XEN_DOMCTL_ioport_permission, domid);
	domctl.u.ioport_permission.first_port = first_port;
	domctl.u.ioport_permission.nr_ports = nr_ports;
	domctl.u.ioport_permission.allow_access = allow_access;

	return do_domctl(handle, &domctl);
}

int xc_vcpu_getcontext(int handle, unsigned int domid,
                       unsigned int vcpu, vcpu_guest_context_any_t *ctxt)
{
	int ret;
	DECLARE_DOMCTL(XEN_DOMCTL_getvcpucontext, domid);
	domctl.u.vcpucontext.vcpu = vcpu;
	set_xen_guest_handle(domctl.u.vcpucontext.ctxt, ctxt);

	if (mlock(ctxt, sizeof(*ctxt)) != 0) {
		xc_error_set("mlock failed: %s", strerror(errno));
		return -1;
	}

	ret = do_domctl(handle, &domctl);
	if (ret)
		xc_error_dom_set(domid, "vcpu %u getcontext", vcpu);
	munlock(ctxt, sizeof(*ctxt));
	return ret;
}

int xc_vcpu_setcontext(int handle, unsigned int domid,
                       unsigned int vcpu, vcpu_guest_context_any_t *ctxt)
{
	int ret;
	DECLARE_DOMCTL(XEN_DOMCTL_setvcpucontext, domid);
	domctl.u.vcpucontext.vcpu = vcpu;
	set_xen_guest_handle(domctl.u.vcpucontext.ctxt, ctxt);

	if (mlock(ctxt, sizeof(*ctxt)) != 0) {
		xc_error_set("mlock failed: %s", strerror(errno));
		return -1;
	}

	ret = do_domctl(handle, &domctl);
	if (ret)
		xc_error_dom_set(domid, "vcpu %u setcontext", vcpu);

	munlock(ctxt, sizeof(*ctxt));
	return ret;
}

int xc_domain_irq_permission(int handle, unsigned int domid,
                             unsigned char pirq, unsigned char allow_access)
{
	DECLARE_DOMCTL(XEN_DOMCTL_irq_permission, domid);
	domctl.u.irq_permission.pirq = pirq;
	domctl.u.irq_permission.allow_access = allow_access;
	int ret;

	ret = do_domctl(handle, &domctl);
	if (ret)
		xc_error_dom_set(domid, "irq permission %u to %u",
		                 pirq, allow_access);
	return ret;
}

int xc_domain_iomem_permission(int handle, unsigned int domid,
                               unsigned long first_mfn, unsigned long nr_mfns,
                               unsigned char allow_access)
{
	DECLARE_DOMCTL(XEN_DOMCTL_iomem_permission, domid);
	domctl.u.iomem_permission.first_mfn = first_mfn;
	domctl.u.iomem_permission.nr_mfns = nr_mfns;
	domctl.u.iomem_permission.allow_access = allow_access;
	int ret;

	ret = do_domctl(handle, &domctl);
	if (ret)
		xc_error_dom_set(domid, "iomem permission [%lu, %lu] to %u",
		                 first_mfn, first_mfn + nr_mfns, allow_access);
	return ret;
}

long long xc_domain_get_cpu_usage(int handle, unsigned int domid,
                                  unsigned int vcpu)
{
	DECLARE_DOMCTL(XEN_DOMCTL_getvcpuinfo, domid);
	domctl.u.getvcpuinfo.vcpu = vcpu;

	if (do_domctl(handle, &domctl) < 0) {
		xc_error_dom_set(domid, "get cpu %d usage", vcpu);
		return -1;
	}
	return domctl.u.getvcpuinfo.cpu_time;
}

void *xc_map_foreign_range(int handle, unsigned int domid,
                           int size, int prot, unsigned long mfn)
{
	privcmd_mmap_entry_t entry = {
		.mfn = mfn,
		.npages = (size + PAGE_SIZE - 1) >> PAGE_SHIFT,
	};
	privcmd_mmap_t ioctlx = {
		.num = 1,
		.dom = domid,
		.entry = &entry,
	};
	void *addr;

	addr = do_mmap(NULL, size, prot, MAP_SHARED, handle, 0);
	if (addr == MAP_FAILED) {
		xc_error_set("mmap failed: %s", strerror(errno));
		xc_error_dom_set(domid, "map foreign range [%lx,%lx] prot %u",
		                 mfn, mfn + size, prot);
		return NULL;
	}
	entry.va = (unsigned long) addr;
	if (do_ioctl(handle, IOCTL_PRIVCMD_MMAP, &ioctlx) < 0) {
		xc_error_set("ioctl failed: %s", strerror(errno));
		xc_error_dom_set(domid, "map foreign range [%lx,%lx] prot %u",
		                 mfn, mfn + size, prot);
		munmap(addr, size);
		return NULL;
	}
	return addr;
}

int xc_map_foreign_ranges(int handle, unsigned int domid,
                          privcmd_mmap_entry_t *entries, int nr)
{
	privcmd_mmap_t ioctlx = {
		.num = nr,
		.dom = domid,
		.entry = entries,
	};
	int ret;

	ret = do_ioctl(handle, IOCTL_PRIVCMD_MMAP, &ioctlx);
	if (ret < 0) {
		xc_error_set("ioctl failed: %s", strerror(errno));
		xc_error_dom_set(domid, "map foreign ranges");
		return -1;
	}
	return ret;
}

int xc_readconsolering(int handle, char **pbuffer,
                       unsigned int *pnr_chars, int clear)
{
	int ret;
	DECLARE_SYSCTL(XEN_SYSCTL_readconsole);
	char *buffer = *pbuffer;
	unsigned int nr_chars = *pnr_chars;

	set_xen_guest_handle(sysctl.u.readconsole.buffer, buffer);
	sysctl.u.readconsole.count = nr_chars;
	sysctl.u.readconsole.clear = clear;

	if (mlock(buffer, nr_chars) != 0) {
		xc_error_set("read console ring: mlock failed: %s",
		             strerror(errno));
		return -1;
	}

	ret = do_sysctl(handle, &sysctl);
	if (ret != 0)
		xc_error_set("read console ring failed: %s", xc_error_get());
	else
		*pnr_chars = sysctl.u.readconsole.count;

	munlock(buffer, nr_chars);
	return ret;
}

int xc_send_debug_keys(int handle, char *keys)
{
	int ret;
	DECLARE_SYSCTL(XEN_SYSCTL_debug_keys);

	set_xen_guest_handle(sysctl.u.debug_keys.keys, keys);
	sysctl.u.debug_keys.nr_keys = strlen(keys);

	if (mlock(keys, sysctl.u.debug_keys.nr_keys) != 0) {
		xc_error_set("send debug keys: mlock failed: %s",
		             strerror(errno));
		return -1;
	}

	ret = do_sysctl(handle, &sysctl);
	if (ret != 0)
		xc_error_set("send debug keys: %s", xc_error_get());

	munlock(keys, sysctl.u.debug_keys.nr_keys);
	return ret;
}

int xc_physinfo(int handle, xc_physinfo_t *put_info)
{
	DECLARE_SYSCTL(XEN_SYSCTL_physinfo);
	int ret;

	ret = do_sysctl(handle, &sysctl);
	if (ret) {
		xc_error_set("physinfo failed: %s", xc_error_get());
		return ret;
	}
	memcpy(put_info, &sysctl.u.physinfo, sizeof(*put_info));
	return 0;
}

int xc_pcpu_info(int handle, int max_cpus, uint64_t *info, int *nr_cpus)
{
	DECLARE_SYSCTL(XEN_SYSCTL_getcpuinfo);
	int ret;

	sysctl.u.getcpuinfo.max_cpus = max_cpus;
	set_xen_guest_handle(sysctl.u.getcpuinfo.info, info);

	if (mlock(info, sizeof(*info) * max_cpus) != 0) {
		xc_error_set("mlock failed: %s", strerror(errno));
		return -1;
	}

	ret = do_sysctl(handle, &sysctl);
	if (ret)
		xc_error_set("pcpu info failed: %s", xc_error_get());
	else if (ret == 0 && nr_cpus)
		*nr_cpus = sysctl.u.getcpuinfo.nr_cpus;
	munlock(info, sizeof(*info) * max_cpus);
	return ret;
}

int xc_sched_id(int handle, int *sched_id)
{
	DECLARE_SYSCTL(XEN_SYSCTL_sched_id);
	int ret;

	ret = do_sysctl(handle, &sysctl);
	if (ret) {
		xc_error_set("sched id failed: %s", xc_error_get());
		return ret;
	}
	*sched_id = sysctl.u.sched_id.sched_id;
	return 0;
}

int xc_version(int handle, int cmd, void *arg)
{
	int argsize;
	int ret;
	DECLARE_HYPERCALL2(__HYPERVISOR_xen_version, cmd, arg);

	switch (cmd) {
	case XENVER_extraversion:
		argsize = sizeof(xen_extraversion_t); break;
	case XENVER_compile_info:
		argsize = sizeof(xen_compile_info_t); break;
	case XENVER_capabilities:
		argsize = sizeof(xen_capabilities_info_t); break;
	case XENVER_changeset:
		argsize = sizeof(xen_changeset_info_t); break;
	case XENVER_platform_parameters:
		argsize = sizeof(xen_platform_parameters_t); break;
	case XENVER_version:
		argsize = 0; break;
	default:
		xc_error_set("version: unknown command");
		return -1;
	}
	if (argsize && mlock(arg, argsize) == -1) {
		xc_error_set("version: mlock failed: %s", strerror(errno));
		return -ENOMEM;
	}

	ret = do_xen_hypercall(handle, &hypercall);
	if (ret)
		xc_error_hypercall(hypercall, ret);

	if (argsize)
		munlock(arg, argsize);
	return ret;
}

int xc_evtchn_alloc_unbound(int handle, unsigned int domid,
                            unsigned int remote_domid)
{
	struct evtchn_alloc_unbound arg = {
		.dom = domid,
		.remote_dom = remote_domid,
	};
	int ret;

	ret = do_evtchnctl(handle, EVTCHNOP_alloc_unbound, &arg, sizeof(arg));
	if (ret) {
		xc_error_dom_set(domid, "alloc unbound evtchn to %d",
		                 remote_domid);
		return ret;
	}
	return arg.port;
}

int xc_evtchn_reset(int handle, unsigned int domid)
{
	struct evtchn_reset arg = {
		.dom = domid,
	};
	int ret;

	ret = do_evtchnctl(handle, EVTCHNOP_reset, &arg, sizeof(arg));
	if (ret)
		xc_error_dom_set(domid, "reset evtchn of %d", domid);
	return ret;
}

int xc_sched_credit_domain_set(int handle, unsigned int domid,
                               struct xen_domctl_sched_credit *sdom)
{
	int ret;
	DECLARE_DOMCTL(XEN_DOMCTL_scheduler_op, domid);
	domctl.u.scheduler_op.sched_id = XEN_SCHEDULER_CREDIT;
	domctl.u.scheduler_op.cmd = XEN_DOMCTL_SCHEDOP_putinfo;
	domctl.u.scheduler_op.u.credit = *sdom;

	ret = do_domctl(handle, &domctl);
	if (ret < 0)
		xc_error_dom_set(domid, "credit scheduler domain set");
	return ret;
}

int xc_sched_credit_domain_get(int handle, unsigned int domid,
                               struct xen_domctl_sched_credit *sdom)
{
	int ret;
	DECLARE_DOMCTL(XEN_DOMCTL_scheduler_op, domid);

	domctl.u.scheduler_op.sched_id = XEN_SCHEDULER_CREDIT;
	domctl.u.scheduler_op.cmd = XEN_DOMCTL_SCHEDOP_getinfo;

	ret = do_domctl(handle, &domctl);
	if (ret < 0)
		xc_error_dom_set(domid, "credit scheduler domain get");
	else
		*sdom = domctl.u.scheduler_op.u.credit;
	return ret;
}

int xc_shadow_allocation_get(int handle, unsigned int domid, uint32_t *mb)
{
	int ret;
	DECLARE_DOMCTL(XEN_DOMCTL_shadow_op, domid);

	domctl.u.shadow_op.op = XEN_DOMCTL_SHADOW_OP_GET_ALLOCATION;

	ret = do_domctl(handle, &domctl);
	if (ret < 0)
		xc_error_dom_set(domid, "shadow allocation get");
	else
		*mb = domctl.u.shadow_op.mb;
	return ret;
}

int xc_shadow_allocation_set(int handle, unsigned int domid, uint32_t mb)
{
	int ret;
	DECLARE_DOMCTL(XEN_DOMCTL_shadow_op, domid);

	domctl.u.shadow_op.op = XEN_DOMCTL_SHADOW_OP_SET_ALLOCATION;
	domctl.u.shadow_op.mb = mb;

	ret = do_domctl(handle, &domctl);
	if (ret < 0)
		xc_error_dom_set(domid, "shadow allocation set");
	return ret;
}

int xc_domain_get_pfn_list(int handle, unsigned int domid,
                           xen_pfn_t *pfn_array, unsigned long max_pfns)
{
	int ret;
	DECLARE_DOMCTL(XEN_DOMCTL_getmemlist, domid);

	domctl.u.getmemlist.max_pfns = max_pfns;
	set_xen_guest_handle(domctl.u.getmemlist.buffer, pfn_array);

	if (mlock(pfn_array, max_pfns * sizeof(xen_pfn_t)) != 0) {
		xc_error_set("mlock failed: %s", strerror(errno));
		return -1;
	}

	ret = do_domctl(handle, &domctl);
	if (ret < 0)
		xc_error_dom_set(domid, "get pfn list");

	munlock(pfn_array, max_pfns * sizeof(xen_pfn_t));
	return (ret < 0) ? ret : domctl.u.getmemlist.num_pfns;
}

#define MARSHALL_BDF(d,b,s,f) \
	(((b) & 0xff) << 16 | ((s) & 0x1f) << 11 | ((f) & 0x7) << 8)

int xc_domain_assign_device(int handle, unsigned int domid,
                            int domain, int bus, int slot, int func)
{
	int ret = -EBADF;
#ifdef XEN_DOMCTL_assign_device
	DECLARE_DOMCTL(XEN_DOMCTL_assign_device, domid);

	domctl.u.assign_device.machine_bdf = MARSHALL_BDF(domain, bus, slot, func);
	ret = do_domctl(handle, &domctl);
	if (ret < 0)
		xc_error_dom_set(domid, "assign device");
#endif
	return ret;
}

int xc_domain_deassign_device(int handle, unsigned int domid,
                              int domain, int bus, int slot, int func)
{
	int ret = -EBADF;
#ifdef XEN_DOMCTL_deassign_device
	DECLARE_DOMCTL(XEN_DOMCTL_deassign_device, domid);

	domctl.u.assign_device.machine_bdf = MARSHALL_BDF(domain, bus, slot, func);
	ret = do_domctl(handle, &domctl);
	if (ret < 0)
		xc_error_dom_set(domid, "deassign device");
#endif
	return ret;
}

int xc_domain_test_assign_device(int handle, unsigned int domid,
                                 int domain, int bus, int slot, int func)
{
	int ret = -EBADF;
#ifdef XEN_DOMCTL_test_assign_device
	DECLARE_DOMCTL(XEN_DOMCTL_test_assign_device, domid);
	domctl.u.assign_device.machine_bdf = MARSHALL_BDF(domain, bus, slot, func);

	ret = do_domctl(handle, &domctl);
	if (ret < 0)
		xc_error_dom_set(domid, "test assign device");
#endif
	return ret;
}

int xc_domain_watchdog(int handle, int id, uint32_t timeout)
{
	int ret = -EBADF;
#ifdef SCHEDOP_watchdog
	sched_watchdog_t arg = {
		.id = (uint32_t) id,
		.timeout = timeout,
	};
	DECLARE_HYPERCALL2(__HYPERVISOR_sched_op, SCHEDOP_watchdog, &arg);

	if (mlock(&arg, sizeof(arg)) != 0) {
		xc_error_set("mlock failed: %s", strerror(errno));
		return -1;
	}

	ret = do_xen_hypercall(handle, &hypercall);
	if (ret < 0) {
		xc_error_hypercall(hypercall, ret);
	}
	munlock(&arg, sizeof(arg));
#endif
	return ret;
}

int xc_domain_set_machine_address_size(int xc, uint32_t domid, unsigned int width)
{
	DECLARE_DOMCTL(XEN_DOMCTL_set_machine_address_size, domid);
	int rc;

	domctl.u.address_size.size = width;
	rc = do_domctl(xc, &domctl);
	if (rc != 0)
		xc_error_dom_set(domid, "set machine address size");

	return rc;
}

int xc_domain_get_machine_address_size(int xc, uint32_t domid)
{
	DECLARE_DOMCTL(XEN_DOMCTL_get_machine_address_size, domid);
	int rc;

	rc = do_domctl(xc, &domctl);
	if (rc != 0)
		xc_error_dom_set(domid, "get machine address size");
	return rc == 0 ? domctl.u.address_size.size : rc;
}

#include "xc_cpuid.h"
int xc_domain_cpuid_set(int xc, unsigned int domid, int hvm,
                        uint32_t input, uint32_t oinput,
                        char *config[4], char *config_out[4])
{
	int ret = -EBADF;
#ifdef XEN_DOMCTL_set_cpuid
	DECLARE_DOMCTL(XEN_DOMCTL_set_cpuid, domid);
	uint32_t regs[4], polregs[4];
	int i, j;

	xc_cpuid(input, oinput, regs);
	memcpy(polregs, regs, sizeof(regs));
	do_cpuid_policy(xc, domid, hvm, input, polregs);

	for (i = 0; i < 4; i++) {
		if (!config[i]) {
			regs[i] = polregs[i];
			continue;
		}
		
		for (j = 0; j < 32; j++) {
			unsigned char val, polval;

			val = !!((regs[i] & (1U << (31 - j))));
			polval = !!((regs[i] & (1U << (31 - j))));

			switch (config[i][j]) {
			case '1': val = 1; break; /* force to true */
			case '0': val = 0; break; /* force to false */
			case 'x': val = polval; break;
			case 'k': case 's': break;
			default:
				xc_error_dom_set(domid, "domain cpuid set: invalid config");
				ret = -EINVAL;
				goto out;
			}

			if (val)
				set_bit(31 - j, regs[i]);
			else
				clear_bit(31 - j, regs[i]);

			if (config_out && config_out[i]) {
				config_out[i][j] = (config[i][j] == 's')
				                   ? '0' + val
						   : config[i][j];
			}
		}
	}

	domctl.u.cpuid.input[0] = input;
	domctl.u.cpuid.input[1] = oinput;
	domctl.u.cpuid.eax = regs[0];
	domctl.u.cpuid.ebx = regs[1];
	domctl.u.cpuid.ecx = regs[2];
	domctl.u.cpuid.edx = regs[3];
	ret = do_domctl(xc, &domctl);
	if (ret) {
		xc_error_dom_set(domid, "cpuid set");
		goto out;
	}
out:
#endif
	return ret;
}

int xc_domain_cpuid_apply(int xc, unsigned int domid, int hvm)
{
	int ret = -EBADF;
#ifdef XEN_DOMCTL_set_cpuid
	uint32_t regs[4], base_max, ext_max, eax, ecx;

	/* determinate cpuid range */
	xc_cpuid(0, 0, regs);
	base_max = MIN(regs[0], DEF_MAX_BASE);
	xc_cpuid(0x80000000, 0, regs);
	ext_max = MIN(regs[0], DEF_MAX_EXT);

	eax = ecx = 0;
	while (!(eax & 0x80000000) || (eax <= ext_max)) {
		xc_cpuid(eax, ecx, regs);

		do_cpuid_policy(xc, domid, hvm, eax, regs);
		
		if (regs[0] || regs[1] || regs[2] || regs[3]) {
			DECLARE_DOMCTL(XEN_DOMCTL_set_cpuid, domid);
			
			domctl.u.cpuid.input[0] = eax;
			domctl.u.cpuid.input[1] = (eax == 4) ? ecx : XEN_CPUID_INPUT_UNUSED;
			domctl.u.cpuid.eax = regs[0];
			domctl.u.cpuid.ebx = regs[1];
			domctl.u.cpuid.ecx = regs[2];
			domctl.u.cpuid.edx = regs[3];

			ret = do_domctl(xc, &domctl);
			if (ret) {
				xc_error_dom_set(domid, "cpuid apply");
				goto out;
			}

			/* we repeat when doing node 4 (cache descriptor leaves) increasing ecx 
			 * until the cpuid eax value masked is 0 */
			if (eax == 4) {
				ecx++;
				if ((regs[0] & 0x1f) != 0)
					continue;
				ecx = 0;
			}
		}

		eax++;
		if (!(eax & 0x80000000) && (eax > base_max))
			eax = 0x80000000;
	}
	ret = 0;
out:
#endif
	return ret;
}

/*
 * return 1 on checking success 
 *        0 on checking failure
 *        -EINVAL if the config contains unknown character
 */
int xc_cpuid_check(uint32_t input, uint32_t optsubinput,
                   char *config[4], char *config_out[4])
{
	int ret = -EBADF;
#ifdef XEN_DOMCTL_set_cpuid
	uint32_t regs[4];
	int i, j;

	xc_cpuid(input, optsubinput, regs);

	ret = 1;
	for (i = 0; i < 4; i++) {
		if (!config[i])
			continue;
		for (j = 0; j < 32; j++) {
			unsigned char val;

			val = !!((regs[i] & (1U << (31 - j))));

			switch (config[i][j]) {
			case '1': if (!val) { ret = 0; goto out; }; break;
			case '0': if (val) { ret = 0; goto out; }; break;
			case 'x': case 's': break;
			default:
				xc_error_set("cpuid check: invalid config");
				ret = -EINVAL;
				goto out;
			}

			if (config_out && config_out[i]) {
				config_out[i][j] = (config[i][j] == 's')
				                   ? '0' + val
						   : config[i][j];
			}
		}
	} 
out:
#endif
	return ret;
}

#ifndef HVM_PARAM_HPET_ENABLED
#define HVM_PARAM_HPET_ENABLED 11
#endif

#ifndef HVM_PARAM_ACPI_S_STATE
#define HVM_PARAM_ACPI_S_STATE 14
#endif

#ifndef HVM_PARAM_VPT_ALIGN
#define HVM_PARAM_VPT_ALIGN 16
#endif

int xc_domain_send_s3resume(int handle, unsigned int domid)
{
	return xc_set_hvm_param(handle, domid, HVM_PARAM_ACPI_S_STATE, 0);
}

int xc_domain_set_timer_mode(int handle, unsigned int domid, int mode)
{
	return xc_set_hvm_param(handle, domid,
	                        HVM_PARAM_TIMER_MODE, (unsigned long) mode);
}

int xc_domain_set_hpet(int handle, unsigned int domid, int hpet)
{
	return xc_set_hvm_param(handle, domid, HVM_PARAM_HPET_ENABLED, (unsigned long) hpet);
}

int xc_domain_set_vpt_align(int handle, unsigned int domid, int vpt_align)
{
	return xc_set_hvm_param(handle, domid, HVM_PARAM_HPET_ENABLED, (unsigned long) vpt_align);
}

int xc_domain_get_acpi_s_state(int handle, unsigned int domid)
{
	int ret;
	unsigned long value;

	ret = xc_get_hvm_param(handle, domid, HVM_PARAM_ACPI_S_STATE, &value);
	if (ret != 0)
		xc_error_dom_set(domid, "get acpi s-state");
	return value;
}
