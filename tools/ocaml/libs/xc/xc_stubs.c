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

#define _XOPEN_SOURCE 600
#include <stdlib.h>

#define CAML_NAME_SPACE
#include <caml/alloc.h>
#include <caml/memory.h>
#include <caml/signals.h>
#include <caml/fail.h>
#include <caml/callback.h>

#include <sys/mman.h>
#include <stdint.h>
#include <string.h>

#include "xc.h"

#include "mmap_stubs.h"

#define PAGE_SHIFT		12
#define PAGE_SIZE               (1UL << PAGE_SHIFT)
#define PAGE_MASK               (~(PAGE_SIZE-1))

#define _H(__h) (Int_val(__h))
#define _D(__d) ((uint32_t)Int_val(__d))

#define Val_none (Val_int(0))

#define string_of_option_array(array, index) \
	((Field(array, index) == Val_none) ? NULL : String_val(Field(Field(array, index), 0)))

/* maybe here we should check the range of the input instead of blindly
 * casting it to uint32 */
#define cpuid_input_of_val(i1, i2, input) \
	i1 = (uint32_t) Int64_val(Field(input, 0)); \
	i2 = ((Field(input, 1) == Val_none) ? 0xffffffff : (uint32_t) Int64_val(Field(Field(input, 1), 0)));

/**
 * Convert the given number of pages to an amount in MiB, rounded up.
 */
void failwith_xc(void)
{
	caml_raise_with_string(*caml_named_value("xc.error"), xc_error_get());
}

CAMLprim value stub_sizeof_core_header(value unit)
{
	CAMLparam1(unit);
	CAMLreturn(Val_int(sizeof(struct xc_core_header)));
}

CAMLprim value stub_sizeof_vcpu_guest_context(value unit)
{
	CAMLparam1(unit);
	CAMLreturn(Val_int(sizeof(struct vcpu_guest_context)));
}

CAMLprim value stub_sizeof_xen_pfn(value unit)
{
	CAMLparam1(unit);
	CAMLreturn(Val_int(sizeof(xen_pfn_t)));
}

#define XC_CORE_MAGIC     0xF00FEBED
#define XC_CORE_MAGIC_HVM 0xF00FEBEE

CAMLprim value stub_marshall_core_header(value header)
{
	CAMLparam1(header);
	CAMLlocal1(s);
	struct xc_core_header c_header;

	c_header.xch_magic = (Field(header, 0))
		? XC_CORE_MAGIC
		: XC_CORE_MAGIC_HVM;
	c_header.xch_nr_vcpus = Int_val(Field(header, 1));
	c_header.xch_nr_pages = Nativeint_val(Field(header, 2));
	c_header.xch_ctxt_offset = Int64_val(Field(header, 3));
	c_header.xch_index_offset = Int64_val(Field(header, 4));
	c_header.xch_pages_offset = Int64_val(Field(header, 5));

	s = caml_alloc_string(sizeof(c_header));
	memcpy(String_val(s), (char *) &c_header, sizeof(c_header));
	CAMLreturn(s);
}

CAMLprim value stub_xc_interface_open(void)
{
        int handle;
        handle = xc_interface_open();
        if (handle == -1)
		failwith_xc();
        return Val_int(handle);
}


CAMLprim value stub_xc_interface_open_fake(void)
{
	return Val_int(-1);
}

CAMLprim value stub_xc_using_injection(void)
{
	if (xc_using_injection ()){
		return Val_int(1);
	} else {
		return Val_int(0);
	}
}

CAMLprim value stub_xc_interface_close(value xc_handle)
{
	CAMLparam1(xc_handle);

	int handle = _H(xc_handle);
	// caml_enter_blocking_section();
	xc_interface_close(handle);
	// caml_leave_blocking_section();

	CAMLreturn(Val_unit);
}

static int domain_create_flag_table[] = {
	XEN_DOMCTL_CDF_hvm_guest,
	XEN_DOMCTL_CDF_hap,
};

CAMLprim value stub_xc_domain_create(value xc_handle, value ssidref,
                                     value flags, value handle)
{
	CAMLparam4(xc_handle, ssidref, flags, handle);

	uint32_t domid = 0;
	xen_domain_handle_t h = { 0 };
	int result;
	int i;
	int c_xc_handle = _H(xc_handle);
	uint32_t c_ssidref = Int32_val(ssidref);
	unsigned int c_flags = 0;
	value l;

        if (Wosize_val(handle) != 16)
		caml_invalid_argument("Handle not a 16-integer array");

	for (i = 0; i < sizeof(h); i++) {
		h[i] = Int_val(Field(handle, i)) & 0xff;
	}

	for (l = flags; l != Val_none; l = Field(l, 1)) {
		int v = Int_val(Field(l, 0));
		c_flags |= domain_create_flag_table[v];
	}

	// caml_enter_blocking_section();
	result = xc_domain_create(c_xc_handle, c_ssidref, h, c_flags, &domid);
	// caml_leave_blocking_section();

	if (result < 0)
		failwith_xc();

	CAMLreturn(Val_int(domid));
}

CAMLprim value stub_xc_domain_setvmxassist(value xc_handle, value domid,
					    value use_vmxassist)
{
	CAMLparam3(xc_handle, domid, use_vmxassist);
	int r;

	r = xc_domain_setvmxassist(_H(xc_handle), _D(domid),
				   Bool_val(use_vmxassist));
	if (r)
		failwith_xc();

	CAMLreturn(Val_unit);
}

CAMLprim value stub_xc_domain_max_vcpus(value xc_handle, value domid,
                                        value max_vcpus)
{
	CAMLparam3(xc_handle, domid, max_vcpus);
	int r;

	r = xc_domain_max_vcpus(_H(xc_handle), _D(domid), Int_val(max_vcpus));
	if (r)
		failwith_xc();

	CAMLreturn(Val_unit);
}


value stub_xc_domain_sethandle(value xc_handle, value domid, value handle)
{
	CAMLparam3(xc_handle, domid, handle);
	xen_domain_handle_t h = { 0 };
	int i;

        if (Wosize_val(handle) != 16)
		caml_invalid_argument("Handle not a 16-integer array");

	for (i = 0; i < sizeof(h); i++) {
		h[i] = Int_val(Field(handle, i)) & 0xff;
	}

	i = xc_domain_sethandle(_H(xc_handle), _D(domid), h);
	if (i)
		failwith_xc();

	CAMLreturn(Val_unit);
}

static value dom_op(value xc_handle, value domid, int (*fn)(int, uint32_t))
{
	CAMLparam2(xc_handle, domid);

	int c_xc_handle = _H(xc_handle);
	uint32_t c_domid = _D(domid);

	// caml_enter_blocking_section();
	int result = fn(c_xc_handle, c_domid);
	// caml_leave_blocking_section();
        if (result)
		failwith_xc();
	CAMLreturn(Val_unit);
}

CAMLprim value stub_xc_domain_pause(value xc_handle, value domid)
{
	return dom_op(xc_handle, domid, xc_domain_pause);
}


CAMLprim value stub_xc_domain_unpause(value xc_handle, value domid)
{
	return dom_op(xc_handle, domid, xc_domain_unpause);
}

CAMLprim value stub_xc_domain_destroy(value xc_handle, value domid)
{
	return dom_op(xc_handle, domid, xc_domain_destroy);
}

CAMLprim value stub_xc_domain_resume_fast(value xc_handle, value domid)
{
	return dom_op(xc_handle, domid, xc_domain_resume_fast);
}

CAMLprim value stub_xc_domain_shutdown(value handle, value domid, value reason)
{
	CAMLparam3(handle, domid, reason);
	int ret;

	ret = xc_domain_shutdown(_H(handle), _D(domid), Int_val(reason));
	if (ret < 0)
		failwith_xc();

	CAMLreturn(Val_unit);
}

static value alloc_domaininfo(xc_domaininfo_t * info)
{
	CAMLparam0();
	CAMLlocal2(result, tmp);
	int i;

	result = caml_alloc_tuple(16);

	Store_field(result,  0, Val_int(info->domain));
	Store_field(result,  1, Val_bool(info->flags & XEN_DOMINF_dying));
	Store_field(result,  2, Val_bool(info->flags & XEN_DOMINF_shutdown));
	Store_field(result,  3, Val_bool(info->flags & XEN_DOMINF_paused));
	Store_field(result,  4, Val_bool(info->flags & XEN_DOMINF_blocked));
	Store_field(result,  5, Val_bool(info->flags & XEN_DOMINF_running));
	Store_field(result,  6, Val_bool(info->flags & XEN_DOMINF_hvm_guest));
	Store_field(result,  7, Val_int((info->flags >> XEN_DOMINF_shutdownshift)
	                                 & XEN_DOMINF_shutdownmask));
	Store_field(result,  8, caml_copy_nativeint(info->tot_pages));
	Store_field(result,  9, caml_copy_nativeint(info->max_pages));
	Store_field(result, 10, caml_copy_int64(info->shared_info_frame));
	Store_field(result, 11, caml_copy_int64(info->cpu_time));
	Store_field(result, 12, Val_int(info->nr_online_vcpus));
	Store_field(result, 13, Val_int(info->max_vcpu_id));
	Store_field(result, 14, caml_copy_int32(info->ssidref));

        tmp = caml_alloc_small(16, 0);
	for (i = 0; i < 16; i++) {
		Field(tmp, i) = Val_int(info->handle[i]);
	}

	Store_field(result, 15, tmp);

	CAMLreturn(result);
}

CAMLprim value stub_xc_domain_getinfolist(value xc_handle, value first_domain, value nb)
{
	CAMLparam3(xc_handle, first_domain, nb);
	CAMLlocal2(result, temp);
	xc_domaininfo_t * info;
	int i, ret, toalloc, c_xc_handle, retval;
	unsigned int c_max_domains;
	uint32_t c_first_domain;

	/* get the minimum number of allocate byte we need and bump it up to page boundary */
	toalloc = (sizeof(xc_domaininfo_t) * Int_val(nb)) | 0xfff;
	ret = posix_memalign((void **) ((void *) &info), 4096, toalloc);
	if (ret)
		caml_raise_out_of_memory();

	result = temp = Val_emptylist;

	c_xc_handle = _H(xc_handle);
	c_first_domain = _D(first_domain);
	c_max_domains = Int_val(nb);
	// caml_enter_blocking_section();
	retval = xc_domain_getinfolist(c_xc_handle, c_first_domain,
				       c_max_domains, info);
	// caml_leave_blocking_section();

	if (retval < 0) {
		free(info);
		failwith_xc();
	}
	for (i = 0; i < retval; i++) {
		result = caml_alloc_small(2, Tag_cons);
		Field(result, 0) = Val_int(0);
		Field(result, 1) = temp;
		temp = result;

		Store_field(result, 0, alloc_domaininfo(info + i));
	}

	free(info);
	CAMLreturn(result);
}

CAMLprim value stub_xc_domain_getinfo(value xc_handle, value domid)
{
	CAMLparam2(xc_handle, domid);
	CAMLlocal1(result);
	xc_domaininfo_t info;
	int ret;

	ret = xc_domain_getinfo(_H(xc_handle), _D(domid), &info);
	if (ret != 0)
		failwith_xc();

	result = alloc_domaininfo(&info);
	CAMLreturn(result);
}

CAMLprim value stub_xc_vcpu_getinfo(value xc_handle, value domid, value vcpu)
{
	CAMLparam3(xc_handle, domid, vcpu);
	CAMLlocal1(result);
	xc_vcpuinfo_t info;
	int retval;

	int c_xc_handle = _H(xc_handle);
	uint32_t c_domid = _D(domid);
	uint32_t c_vcpu = Int_val(vcpu);
	// caml_enter_blocking_section();
	retval = xc_vcpu_getinfo(c_xc_handle, c_domid,
	                         c_vcpu, &info);
	// caml_leave_blocking_section();
	if (retval < 0)
		failwith_xc();

	result = caml_alloc_tuple(5);
	Store_field(result, 0, Val_bool(info.online));
	Store_field(result, 1, Val_bool(info.blocked));
	Store_field(result, 2, Val_bool(info.running));
	Store_field(result, 3, caml_copy_int64(info.cpu_time));
	Store_field(result, 4, caml_copy_int32(info.cpu));

	CAMLreturn(result);
}

CAMLprim value stub_xc_vcpu_context_get(value xc_handle, value domid,
                                        value cpu)
{
	CAMLparam3(xc_handle, domid, cpu);
	CAMLlocal1(context);
	int ret;
	vcpu_guest_context_any_t ctxt;

	ret = xc_vcpu_getcontext(_H(xc_handle), _D(domid), Int_val(cpu), &ctxt);

	context = caml_alloc_string(sizeof(ctxt));
	memcpy(String_val(context), (char *) &ctxt.c, sizeof(ctxt.c));

	CAMLreturn(context);
}

CAMLprim value stub_xc_vcpu_setaffinity(value xc_handle, value domid,
                                        value vcpu, value cpumap)
{
	CAMLparam4(xc_handle, domid, vcpu, cpumap);
	uint64_t c_cpumap;
	int retval;

	c_cpumap = Int64_val(cpumap);
	retval = xc_vcpu_setaffinity(_H(xc_handle), _D(domid),
	                             Int_val(vcpu), c_cpumap);
	if (retval < 0)
		failwith_xc();
	CAMLreturn(Val_unit);
}

CAMLprim value stub_xc_vcpu_getaffinity(value xc_handle, value domid,
                                        value vcpu)
{
	CAMLparam3(xc_handle, domid, vcpu);
	CAMLlocal1(ret);
	uint64_t cpumap;
	int retval;

	retval = xc_vcpu_getaffinity(_H(xc_handle), _D(domid),
	                             Int_val(vcpu), &cpumap);
	if (retval < 0)
		failwith_xc();
	ret = caml_copy_int64(cpumap);
	CAMLreturn(ret);
}

CAMLprim value stub_xc_sched_id(value xc_handle)
{
	CAMLparam1(xc_handle);
	int sched_id;

	if (xc_sched_id(_H(xc_handle), &sched_id))
		failwith_xc();
	CAMLreturn(Val_int(sched_id));
}

CAMLprim value stub_xc_evtchn_alloc_unbound(value xc_handle,
                                            value local_domid,
                                            value remote_domid)
{
	CAMLparam3(xc_handle, local_domid, remote_domid);

	int c_xc_handle = _H(xc_handle);
	uint32_t c_local_domid = _D(local_domid);
	uint32_t c_remote_domid = _D(remote_domid);

	// caml_enter_blocking_section();
	int result = xc_evtchn_alloc_unbound(c_xc_handle, c_local_domid,
	                                     c_remote_domid);
	// caml_leave_blocking_section();

	if (result < 0)
		failwith_xc();
	CAMLreturn(Val_int(result));
}

CAMLprim value stub_xc_evtchn_reset(value handle, value domid)
{
	CAMLparam2(handle, domid);
	int r;

	r = xc_evtchn_reset(_H(handle), _D(domid));
	if (r < 0)
		failwith_xc();
	CAMLreturn(Val_unit);
}


#define RING_SIZE 32768
static char ring[RING_SIZE];

CAMLprim value stub_xc_readconsolering(value xc_handle)
{
	unsigned int size = RING_SIZE;
	char *ring_ptr = ring;

	CAMLparam1(xc_handle);
	int c_xc_handle = _H(xc_handle);

	// caml_enter_blocking_section();
	int retval = xc_readconsolering(c_xc_handle, &ring_ptr, &size, 0);
	// caml_leave_blocking_section();

	if (retval)
		failwith_xc();
	ring[size] = '\0';
	CAMLreturn(caml_copy_string(ring));
}

CAMLprim value stub_xc_send_debug_keys(value xc_handle, value keys)
{
	CAMLparam2(xc_handle, keys);
	int r;

	r = xc_send_debug_keys(_H(xc_handle), String_val(keys));
	if (r)
		failwith_xc();
	CAMLreturn(Val_unit);
}

CAMLprim value stub_xc_physinfo(value xc_handle)
{
	CAMLparam1(xc_handle);
	CAMLlocal3(physinfo, cap_list, tmp);
	xc_physinfo_t c_physinfo;
	int r;

	// caml_enter_blocking_section();
	r = xc_physinfo(_H(xc_handle), &c_physinfo);
	// caml_leave_blocking_section();

	if (r)
		failwith_xc();

	tmp = cap_list = Val_emptylist;
	for (r = 0; r < 2; r++) {
		if ((c_physinfo.capabilities >> r) & 1) {
			tmp = caml_alloc_small(2, Tag_cons);
			Field(tmp, 0) = Val_int(r);
			Field(tmp, 1) = cap_list;
			cap_list = tmp;
		}
	}

	physinfo = caml_alloc_tuple(9);
	Store_field(physinfo, 0, Val_int(c_physinfo.threads_per_core));
	Store_field(physinfo, 1, Val_int(c_physinfo.cores_per_socket));
	Store_field(physinfo, 2, Val_int(c_physinfo.nr_cpus));
	Store_field(physinfo, 3, Val_int(c_physinfo.max_node_id));
	Store_field(physinfo, 4, Val_int(c_physinfo.cpu_khz));
	Store_field(physinfo, 5, caml_copy_nativeint(c_physinfo.total_pages));
	Store_field(physinfo, 6, caml_copy_nativeint(c_physinfo.free_pages));
	Store_field(physinfo, 7, caml_copy_nativeint(c_physinfo.scrub_pages));
	Store_field(physinfo, 8, cap_list);

	CAMLreturn(physinfo);
}

CAMLprim value stub_xc_pcpu_info(value xc_handle, value nr_cpus)
{
	CAMLparam2(xc_handle, nr_cpus);
	CAMLlocal2(pcpus, v);
	xen_sysctl_cpuinfo_t *info;
	int r, size;

	if (Int_val(nr_cpus) < 1)
		caml_invalid_argument("nr_cpus");
	
	info = calloc(Int_val(nr_cpus) + 1, sizeof(*info));
	if (!info)
		caml_raise_out_of_memory();

	// caml_enter_blocking_section();
	r = xc_pcpu_info(_H(xc_handle), Int_val(nr_cpus), info, &size);
	// caml_leave_blocking_section();

	if (r) {
		free(info);
		failwith_xc();
	}

	if (size > 0) {
		int i;
		pcpus = caml_alloc(size, 0);
		for (i = 0; i < size; i++) {
			v = caml_copy_int64(info[i].idletime);
			caml_modify(&Field(pcpus, i), v);
		}
	} else
		pcpus = Atom(0);
	free(info);
	CAMLreturn(pcpus);
}

CAMLprim value stub_xc_domain_setmaxmem(value xc_handle, value domid,
                                        value max_memkb)
{
	CAMLparam3(xc_handle, domid, max_memkb);

	int c_xc_handle = _H(xc_handle);
	uint32_t c_domid = _D(domid);
	unsigned int c_max_memkb = Int64_val(max_memkb);
	// caml_enter_blocking_section();
	int retval = xc_domain_setmaxmem(c_xc_handle, c_domid,
	                                 c_max_memkb);
	// caml_leave_blocking_section();
	if (retval)
		failwith_xc();
	CAMLreturn(Val_unit);
}

CAMLprim value stub_xc_domain_set_memmap_limit(value xc_handle, value domid,
                                               value map_limitkb)
{
	CAMLparam3(xc_handle, domid, map_limitkb);
	unsigned long v;
	int retval;

	v = Int64_val(map_limitkb);
	retval = xc_domain_set_memmap_limit(_H(xc_handle), _D(domid), v);
	if (retval)
		failwith_xc();

	CAMLreturn(Val_unit);
}

CAMLprim value stub_xc_domain_memory_increase_reservation(value xc_handle,
                                                          value domid,
                                                          value mem_kb)
{
	CAMLparam3(xc_handle, domid, mem_kb);

	unsigned long nr_extents = ((unsigned long)(Int64_val(mem_kb))) >> (PAGE_SHIFT - 10);

	int c_xc_handle = _H(xc_handle);
	uint32_t c_domid = _D(domid);
	// caml_enter_blocking_section();
	int retval = xc_domain_memory_increase_reservation(c_xc_handle, c_domid,
	                                                   nr_extents, 0, 0, NULL);
	// caml_leave_blocking_section();

	if (retval)
		failwith_xc();
	CAMLreturn(Val_unit);
}

CAMLprim value stub_xc_domain_set_machine_address_size(value xc_handle,
						       value domid,
						       value width)
{
	CAMLparam3(xc_handle, domid, width);
	int c_xc_handle = _H(xc_handle);
	uint32_t c_domid = _D(domid);
	int c_width = Int_val(width);

	int retval = xc_domain_set_machine_address_size(c_xc_handle, c_domid, c_width);
	if (retval)
		failwith_xc();
	CAMLreturn(Val_unit);
}

CAMLprim value stub_xc_domain_get_machine_address_size(value xc_handle,
                                                       value domid)
{
	CAMLparam2(xc_handle, domid);
	int retval;

	retval = xc_domain_get_machine_address_size(_H(xc_handle), _D(domid));
	if (retval < 0)
		failwith_xc();
	CAMLreturn(Val_int(retval));
}

CAMLprim value stub_xc_domain_cpuid_set(value xc_handle, value domid,
                                        value is_hvm, value input,
                                        value config)
{
	CAMLparam5(xc_handle, domid, is_hvm, input, config);
	CAMLlocal2(array, tmp);
	int r;
	char *c_config[4], *out_config[4];
	uint32_t c_input, c_oinput;

	c_config[0] = string_of_option_array(config, 0);
	c_config[1] = string_of_option_array(config, 1);
	c_config[2] = string_of_option_array(config, 2);
	c_config[3] = string_of_option_array(config, 3);

	cpuid_input_of_val(c_input, c_oinput, input);

	array = caml_alloc(4, 0);
	for (r = 0; r < 4; r++) {
		tmp = Val_none;
		if (c_config[r]) {
			tmp = caml_alloc_small(1, 0);
			Field(tmp, 0) = caml_alloc_string(32);
		}
		Store_field(array, r, tmp);
	}

	for (r = 0; r < 4; r++)
		out_config[r] = (c_config[r]) ? String_val(Field(Field(array, r), 0)) : NULL;

	r = xc_domain_cpuid_set(_H(xc_handle), _D(domid), Bool_val(is_hvm),
	                        c_input, c_oinput, c_config, out_config);
	if (r < 0)
		failwith_xc();
	CAMLreturn(array);
}

CAMLprim value stub_xc_domain_cpuid_apply(value xc_handle, value domid, value is_hvm)
{
	CAMLparam3(xc_handle, domid, is_hvm);
	int r;
	r = xc_domain_cpuid_apply(_H(xc_handle), _D(domid), Bool_val(is_hvm));
	if (r < 0)
		failwith_xc();
	CAMLreturn(Val_unit);
}

CAMLprim value stub_xc_cpuid_check(value input, value config)
{
	CAMLparam2(input, config);
	CAMLlocal3(ret, array, tmp);
	int r;
	uint32_t c_input, c_oinput;
	char *c_config[4], *out_config[4];

	c_config[0] = string_of_option_array(config, 0);
	c_config[1] = string_of_option_array(config, 1);
	c_config[2] = string_of_option_array(config, 2);
	c_config[3] = string_of_option_array(config, 3);

	cpuid_input_of_val(c_input, c_oinput, input);

	array = caml_alloc(4, 0);
	for (r = 0; r < 4; r++) {
		tmp = Val_none;
		if (c_config[r]) {
			tmp = caml_alloc_small(1, 0);
			Field(tmp, 0) = caml_alloc_string(32);
		}
		Store_field(array, r, tmp);
	}

	for (r = 0; r < 4; r++)
		out_config[r] = (c_config[r]) ? String_val(Field(Field(array, r), 0)) : NULL;

	r = xc_cpuid_check(c_input, c_oinput, c_config, out_config);
	if (r < 0)
		failwith_xc();

	ret = caml_alloc_tuple(2);
	Store_field(ret, 0, Val_bool(r));
	Store_field(ret, 1, array);

	CAMLreturn(ret);
}

CAMLprim value stub_xc_version_version(value xc_handle)
{
	CAMLparam1(xc_handle);
	CAMLlocal1(result);
	xen_extraversion_t extra;
	long packed;
	int retval;

	int c_xc_handle = _H(xc_handle);
	// caml_enter_blocking_section();
	packed = xc_version(c_xc_handle, XENVER_version, NULL);
	retval = xc_version(c_xc_handle, XENVER_extraversion, &extra);
	// caml_leave_blocking_section();

	if (retval)
		failwith_xc();

	result = caml_alloc_tuple(3);

	Store_field(result, 0, Val_int(packed >> 16));
	Store_field(result, 1, Val_int(packed & 0xffff));
	Store_field(result, 2, caml_copy_string(extra));

	CAMLreturn(result);
}


CAMLprim value stub_xc_version_compile_info(value xc_handle)
{
	CAMLparam1(xc_handle);
	CAMLlocal1(result);
	xen_compile_info_t ci;
	int retval;

	int c_xc_handle = _H(xc_handle);
	// caml_enter_blocking_section();
	retval = xc_version(c_xc_handle, XENVER_compile_info, &ci);
	// caml_leave_blocking_section();

	if (retval)
		failwith_xc();

	result = caml_alloc_tuple(4);

	Store_field(result, 0, caml_copy_string(ci.compiler));
	Store_field(result, 1, caml_copy_string(ci.compile_by));
	Store_field(result, 2, caml_copy_string(ci.compile_domain));
	Store_field(result, 3, caml_copy_string(ci.compile_date));

	CAMLreturn(result);
}


static value xc_version_single_string(value xc_handle, int code, void *info)
{
	CAMLparam1(xc_handle);
	int retval;

	int c_xc_handle = _H(xc_handle);
	// caml_enter_blocking_section();
	retval = xc_version(c_xc_handle, code, info);
	// caml_leave_blocking_section();

	if (retval)
		failwith_xc();

	CAMLreturn(caml_copy_string((char *)info));
}


CAMLprim value stub_xc_version_changeset(value xc_handle)
{
	xen_changeset_info_t ci;

	return xc_version_single_string(xc_handle, XENVER_changeset, &ci);
}


CAMLprim value stub_xc_version_capabilities(value xc_handle)
{
	xen_capabilities_info_t ci;

	return xc_version_single_string(xc_handle, XENVER_capabilities, &ci);
}


CAMLprim value stub_pages_to_kib(value pages)
{
	CAMLparam1(pages);

	CAMLreturn(caml_copy_int64(Int64_val(pages) << (PAGE_SHIFT - 10)));
}


CAMLprim value stub_map_foreign_range(value xc_handle, value dom,
                                      value size, value mfn)
{
	CAMLparam4(xc_handle, dom, size, mfn);
	CAMLlocal1(result);
	struct mmap_interface *intf;
	int c_xc_handle;
	uint32_t c_dom;
	unsigned long c_mfn;

	result = caml_alloc(sizeof(struct mmap_interface), Abstract_tag);
	intf = (struct mmap_interface *) result;

	intf->len = Int_val(size);

	c_xc_handle = _H(xc_handle);
	c_dom = _D(dom);
	c_mfn = Nativeint_val(mfn);
	// caml_enter_blocking_section();
	intf->addr = xc_map_foreign_range(c_xc_handle, c_dom,
	                                  intf->len, PROT_READ|PROT_WRITE,
	                                  c_mfn);
	// caml_leave_blocking_section();
	if (!intf->addr)
		caml_failwith("xc_map_foreign_range error");
	CAMLreturn(result);
}

CAMLprim value stub_sched_credit_domain_get(value xc_handle, value domid)
{
	CAMLparam2(xc_handle, domid);
	CAMLlocal1(sdom);
	struct xen_domctl_sched_credit c_sdom;
	int ret;

	// caml_enter_blocking_section();
	ret = xc_sched_credit_domain_get(_H(xc_handle), _D(domid), &c_sdom);
	// caml_leave_blocking_section();
	if (ret != 0)
		failwith_xc();

	sdom = caml_alloc_tuple(2);
	Store_field(sdom, 0, Val_int(c_sdom.weight));
	Store_field(sdom, 1, Val_int(c_sdom.cap));

	CAMLreturn(sdom);
}

CAMLprim value stub_sched_credit_domain_set(value xc_handle, value domid,
                                            value sdom)
{
	CAMLparam3(xc_handle, domid, sdom);
	struct xen_domctl_sched_credit c_sdom;
	int ret;

	c_sdom.weight = Int_val(Field(sdom, 0));
	c_sdom.cap = Int_val(Field(sdom, 1));
	// caml_enter_blocking_section();
	ret = xc_sched_credit_domain_set(_H(xc_handle), _D(domid), &c_sdom);
	// caml_leave_blocking_section();
	if (ret != 0)
		failwith_xc();

	CAMLreturn(Val_unit);
}

CAMLprim value stub_shadow_allocation_get(value xc_handle, value domid)
{
	CAMLparam2(xc_handle, domid);
	CAMLlocal1(mb);
	uint32_t c_mb;
	int ret;

	// caml_enter_blocking_section();
	ret = xc_shadow_allocation_get(_H(xc_handle), _D(domid), &c_mb);
	// caml_leave_blocking_section();
	if (ret != 0)
		failwith_xc();

	mb = Val_int(c_mb);
	CAMLreturn(mb);
}

CAMLprim value stub_shadow_allocation_set(value xc_handle, value domid,
					  value mb)
{
	CAMLparam3(xc_handle, domid, mb);
	uint32_t c_mb;
	int ret;

	c_mb = Int_val(mb);
	// caml_enter_blocking_section();
	ret = xc_shadow_allocation_set(_H(xc_handle), _D(domid), c_mb);
	// caml_leave_blocking_section();
	if (ret != 0)
		failwith_xc();

	CAMLreturn(Val_unit);
}

CAMLprim value stub_xc_domain_get_pfn_list(value xc_handle, value domid,
                                           value nr_pfns)
{
	CAMLparam3(xc_handle, domid, nr_pfns);
	CAMLlocal2(array, v);
	unsigned long c_nr_pfns;
	long ret, i;
	uint64_t *c_array;

	c_nr_pfns = Nativeint_val(nr_pfns);

	c_array = malloc(sizeof(uint64_t) * c_nr_pfns);
	if (!c_array)
		caml_raise_out_of_memory();

	ret = xc_domain_get_pfn_list(_H(xc_handle), _D(domid),
	                             c_array, c_nr_pfns);
	if (ret < 0) {
		free(c_array);
		failwith_xc();
	}

	array = caml_alloc(ret, 0);
	for (i = 0; i < ret; i++) {
		v = caml_copy_nativeint(c_array[i]);
		Store_field(array, i, v);
	}
	free(c_array);

	CAMLreturn(array);
}

CAMLprim value stub_xc_domain_ioport_permission(value xc_handle, value domid,
					       value start_port, value nr_ports,
					       value allow)
{
	CAMLparam5(xc_handle, domid, start_port, nr_ports, allow);
	uint32_t c_start_port, c_nr_ports;
	uint8_t c_allow;
	int ret;

	c_start_port = Int_val(start_port);
	c_nr_ports = Int_val(nr_ports);
	c_allow = Bool_val(allow);

	ret = xc_domain_ioport_permission(_H(xc_handle), _D(domid),
					 c_start_port, c_nr_ports, c_allow);
	if (ret < 0)
		failwith_xc();

	CAMLreturn(Val_unit);
}

CAMLprim value stub_xc_domain_iomem_permission(value xc_handle, value domid,
					       value start_pfn, value nr_pfns,
					       value allow)
{
	CAMLparam5(xc_handle, domid, start_pfn, nr_pfns, allow);
	unsigned long c_start_pfn, c_nr_pfns;
	uint8_t c_allow;
	int ret;

	c_start_pfn = Nativeint_val(start_pfn);
	c_nr_pfns = Nativeint_val(nr_pfns);
	c_allow = Bool_val(allow);

	ret = xc_domain_iomem_permission(_H(xc_handle), _D(domid),
					 c_start_pfn, c_nr_pfns, c_allow);
	if (ret < 0)
		failwith_xc();

	CAMLreturn(Val_unit);
}

CAMLprim value stub_xc_domain_irq_permission(value xc_handle, value domid,
					     value pirq, value allow)
{
	CAMLparam4(xc_handle, domid, pirq, allow);
	uint8_t c_pirq;
	uint8_t c_allow;
	int ret;

	c_pirq = Int_val(pirq);
	c_allow = Bool_val(allow);

	ret = xc_domain_irq_permission(_H(xc_handle), _D(domid),
				       c_pirq, c_allow);
	if (ret < 0)
		failwith_xc();

	CAMLreturn(Val_unit);
}

CAMLprim value stub_xc_hvm_check_pvdriver(value xc_handle, value domid)
{
	CAMLparam2(xc_handle, domid);
	int ret;

	ret = xc_hvm_check_pvdriver(_H(xc_handle), _D(domid));
	if (ret < 0)
		failwith_xc();
	CAMLreturn(Val_bool(ret));
}

CAMLprim value stub_xc_domain_test_assign_device(value xc_handle, value domid, value desc)
{
	CAMLparam3(xc_handle, domid, desc);
	int ret;
	int domain, bus, slot, func;

	domain = Int_val(Field(desc, 0));
	bus = Int_val(Field(desc, 1));
	slot = Int_val(Field(desc, 2));
	func = Int_val(Field(desc, 3));

	ret = xc_domain_test_assign_device(_H(xc_handle), _D(domid),
	                                   domain, bus, slot, func);
	CAMLreturn(Val_bool(ret == 0));
}

CAMLprim value stub_xc_domain_assign_device(value xc_handle, value domid, value desc)
{
	CAMLparam3(xc_handle, domid, desc);
	int ret;
	int domain, bus, slot, func;

	domain = Int_val(Field(desc, 0));
	bus = Int_val(Field(desc, 1));
	slot = Int_val(Field(desc, 2));
	func = Int_val(Field(desc, 3));

	ret = xc_domain_assign_device(_H(xc_handle), _D(domid),
	                              domain, bus, slot, func);
	if (ret < 0)
		failwith_xc();
	CAMLreturn(Val_unit);
}

CAMLprim value stub_xc_domain_deassign_device(value xc_handle, value domid, value desc)
{
	CAMLparam3(xc_handle, domid, desc);
	int ret;
	int domain, bus, slot, func;

	domain = Int_val(Field(desc, 0));
	bus = Int_val(Field(desc, 1));
	slot = Int_val(Field(desc, 2));
	func = Int_val(Field(desc, 3));

	ret = xc_domain_deassign_device(_H(xc_handle), _D(domid),
	                                domain, bus, slot, func);
	if (ret < 0)
		failwith_xc();
	CAMLreturn(Val_unit);
}

CAMLprim value stub_xc_domain_set_timer_mode(value handle, value id, value mode)
{
	CAMLparam3(handle, id, mode);
	int ret;

	ret = xc_domain_set_timer_mode(_H(handle), _D(id), Int_val(mode));
	if (ret < 0)
		failwith_xc();
	CAMLreturn(Val_unit);
}

CAMLprim value stub_xc_domain_set_hpet(value handle, value id, value mode)
{
	CAMLparam3(handle, id, mode);
	int ret;

	ret = xc_domain_set_hpet(_H(handle), _D(id), Int_val(mode));
	if (ret < 0)
		failwith_xc();
	CAMLreturn(Val_unit);
}

CAMLprim value stub_xc_domain_set_vpt_align(value handle, value id, value mode)
{
	CAMLparam3(handle, id, mode);
	int ret;

	ret = xc_domain_set_vpt_align(_H(handle), _D(id), Int_val(mode));
	if (ret < 0)
		failwith_xc();
	CAMLreturn(Val_unit);
}

CAMLprim value stub_xc_watchdog(value handle, value domid, value timeout)
{
	CAMLparam3(handle, domid, timeout);
	int ret;
	unsigned int c_timeout = Int32_val(timeout);

	ret = xc_domain_watchdog(_H(handle), _D(domid), c_timeout);
	if (ret < 0)
		failwith_xc();

	CAMLreturn(Val_int(ret));
}

CAMLprim value stub_xc_domain_send_s3resume(value handle, value domid)
{
	CAMLparam2(handle, domid);
	xc_domain_send_s3resume(_H(handle), _D(domid));
	CAMLreturn(Val_unit);
}

CAMLprim value stub_xc_domain_get_acpi_s_state(value handle, value domid)
{
	CAMLparam2(handle, domid);
	int ret;

	ret = xc_domain_get_acpi_s_state(_H(handle), _D(domid));
	if (ret < 0)
		failwith_xc();

	CAMLreturn(Val_int(ret));
}

/*
 * Local variables:
 *  indent-tabs-mode: t
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
