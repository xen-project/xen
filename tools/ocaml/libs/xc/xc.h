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

#include <xen/xen.h>
#include <xen/memory.h>
#include <xen/sysctl.h>
#include <xen/domctl.h>
#include <xen/sched.h>
#include <xen/sysctl.h>
#include <xen/sys/privcmd.h>
#include <xen/version.h>
#include <xen/foreign/x86_32.h>
#include <xen/foreign/x86_64.h>
#include <xen/hvm/params.h>
#include "xc_e820.h"

typedef xen_domctl_getdomaininfo_t xc_domaininfo_t;
typedef xen_domctl_getvcpuinfo_t xc_vcpuinfo_t;
typedef xen_sysctl_physinfo_t xc_physinfo_t;

struct xc_core_header {
	unsigned int xch_magic;
	unsigned int xch_nr_vcpus;
	unsigned int xch_nr_pages;
	unsigned int xch_ctxt_offset;
	unsigned int xch_index_offset;
	unsigned int xch_pages_offset;
};

typedef union {
#if defined(__i386__) || defined(__x86_64__)
	vcpu_guest_context_x86_64_t x64;
	vcpu_guest_context_x86_32_t x32;
#endif
	vcpu_guest_context_t c;
} vcpu_guest_context_any_t;

char * xc_error_get(void);
void xc_error_clear(void);

int xc_using_injection(void);

int xc_interface_open(void);
int xc_interface_close(int handle);

int xc_domain_create(int handle, unsigned int ssidref,
                     xen_domain_handle_t dhandle,
                     unsigned int flags, unsigned int *pdomid);
int xc_domain_pause(int handle, unsigned int domid);
int xc_domain_unpause(int handle, unsigned int domid);
int xc_domain_resume_fast(int handle, unsigned int domid);
int xc_domain_destroy(int handle, unsigned int domid);
int xc_domain_shutdown(int handle, int domid, int reason);

int xc_vcpu_setaffinity(int handle, unsigned int domid, int vcpu,
                        uint64_t cpumap);
int xc_vcpu_getaffinity(int handle, unsigned int domid, int vcpu,
                        uint64_t *cpumap);

int xc_domain_getinfolist(int handle, unsigned int first_domain,
                          unsigned int max_domains, xc_domaininfo_t *info);
int xc_domain_getinfo(int handle, unsigned int first_domain,
                      xc_domaininfo_t *info);

int xc_domain_setmaxmem(int handle, unsigned int domid, unsigned int max_memkb);
int xc_domain_set_memmap_limit(int handle, unsigned int domid,
                               unsigned long map_limitkb);

int xc_domain_set_time_offset(int handle, unsigned int domid, int time_offset);

int xc_domain_memory_increase_reservation(int handle, unsigned int domid,
                                          unsigned long nr_extents,
                                          unsigned int extent_order,
                                          unsigned int address_bits,
                                          xen_pfn_t *extent_start);
int xc_domain_memory_decrease_reservation(int handle, unsigned int domid,
                                          unsigned long nr_extents,
                                          unsigned int extent_order,
                                          unsigned int address_bits,
                                          xen_pfn_t *extent_start);
int xc_domain_memory_populate_physmap(int handle, unsigned int domid,
                                      unsigned long nr_extents,
                                      unsigned int extent_order,
                                      unsigned int address_bits,
                                      xen_pfn_t *extent_start);
int xc_domain_setvmxassist(int handle, unsigned int domid, int use_vmxassist);
int xc_domain_max_vcpus(int handle, unsigned int domid, unsigned int max);
int xc_domain_sethandle(int handle, unsigned int domid,
                        xen_domain_handle_t dhandle);
int xc_vcpu_getinfo(int handle, unsigned int domid, unsigned int vcpu,
                    xc_vcpuinfo_t *info);
int xc_domain_ioport_permission(int handle, unsigned int domid,
                                unsigned int first_port, unsigned int nr_ports,
                                unsigned int allow_access);
int xc_vcpu_setcontext(int handle, unsigned int domid,
                       unsigned int vcpu, vcpu_guest_context_any_t *ctxt);
int xc_vcpu_getcontext(int handle, unsigned int domid,
                       unsigned int vcpu, vcpu_guest_context_any_t *ctxt);
int xc_domain_irq_permission(int handle, unsigned int domid,
                             unsigned char pirq, unsigned char allow_access);
int xc_domain_iomem_permission(int handle, unsigned int domid,
                               unsigned long first_mfn, unsigned long nr_mfns,
                               unsigned char allow_access);
long long xc_domain_get_cpu_usage(int handle, unsigned int domid,
                                  unsigned int vcpu);
void *xc_map_foreign_range(int handle, unsigned int domid,
                           int size, int prot, unsigned long mfn);
int xc_map_foreign_ranges(int handle, unsigned int domid,
                          privcmd_mmap_entry_t *entries, int nr);
int xc_readconsolering(int handle, char **pbuffer,
                       unsigned int *pnr_chars, int clear);
int xc_send_debug_keys(int handle, char *keys);
int xc_physinfo(int handle, xc_physinfo_t *put_info);
int xc_pcpu_info(
	int handle, int max_cpus, xen_sysctl_cpuinfo_t *info, int *nr_cpus);
int xc_sched_id(int handle, int *sched_id);
int xc_version(int handle, int cmd, void *arg);
int xc_evtchn_alloc_unbound(int handle, unsigned int domid,
                            unsigned int remote_domid);
int xc_evtchn_reset(int handle, unsigned int domid);

int xc_sched_credit_domain_set(int handle, unsigned int domid,
                               struct xen_domctl_sched_credit *sdom);
int xc_sched_credit_domain_get(int handle, unsigned int domid,
                               struct xen_domctl_sched_credit *sdom);
int xc_shadow_allocation_get(int handle, unsigned int domid,
			     uint32_t *mb);
int xc_shadow_allocation_set(int handle, unsigned int domid,
			     uint32_t mb);
int xc_domain_get_pfn_list(int handle, unsigned int domid,
                           xen_pfn_t *pfn_array, unsigned long max_pfns);
int xc_hvm_check_pvdriver(int handle, unsigned int domid);

int xc_domain_assign_device(int handle, unsigned int domid,
                            int domain, int bus, int slot, int func);
int xc_domain_deassign_device(int handle, unsigned int domid,
                              int domain, int bus, int slot, int func);
int xc_domain_test_assign_device(int handle, unsigned int domid,
                                 int domain, int bus, int slot, int func);
int xc_domain_watchdog(int handle, int id, uint32_t timeout);
int xc_domain_set_machine_address_size(int xc, uint32_t domid, unsigned int width);
int xc_domain_get_machine_address_size(int xc, uint32_t domid);

int xc_domain_cpuid_set(int xc, unsigned int domid, int hvm,
                        uint32_t input, uint32_t oinput,
                        char *config[4], char *config_out[4]);
int xc_domain_cpuid_apply(int xc, unsigned int domid, int hvm);
int xc_cpuid_check(uint32_t input, uint32_t optsubinput,
                   char *config[4], char *config_out[4]);

int xc_domain_send_s3resume(int handle, unsigned int domid);
int xc_domain_set_vpt_align(int handle, unsigned int domid, int vpt_align);
int xc_domain_set_hpet(int handle, unsigned int domid, int hpet);
int xc_domain_set_timer_mode(int handle, unsigned int domid, int mode);
int xc_domain_get_acpi_s_state(int handle, unsigned int domid);

#if XEN_SYSCTL_INTERFACE_VERSION >= 6
#define SAFEDIV(a, b)					(((b) > 0) ? (a) / (b) : (a))
#define COMPAT_FIELD_physinfo_get_nr_cpus(p)		(p).nr_cpus
#define COMPAT_FIELD_physinfo_get_sockets_per_node(p)	\
	SAFEDIV((p).nr_cpus, ((p).threads_per_core * (p).cores_per_socket * (p).nr_nodes))
#else
#define COMPAT_FIELD_physinfo_get_nr_cpus(p)		\
	((p).threads_per_core * (p).sockets_per_node *	\
	 (p).cores_per_socket * (p).threads_per_core)
#define COMPAT_FIELD_physinfo_get_sockets_per_node(p)	(p).sockets_per_node
#endif

#if __XEN_LATEST_INTERFACE_VERSION__ >= 0x00030209
#define COMPAT_FIELD_ADDRESS_BITS		mem_flags
#else
#define COMPAT_FIELD_ADDRESS_BITS		address_bits
#endif
