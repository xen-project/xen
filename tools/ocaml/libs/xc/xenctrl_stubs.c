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
#include <errno.h>

#define CAML_NAME_SPACE
#include <caml/alloc.h>
#include <caml/memory.h>
#include <caml/signals.h>
#include <caml/fail.h>
#include <caml/callback.h>

#include <sys/mman.h>
#include <stdint.h>
#include <string.h>

#define XC_WANT_COMPAT_MAP_FOREIGN_API
#include <xenctrl.h>

#include "mmap_stubs.h"

#define PAGE_SHIFT		12
#define PAGE_SIZE               (1UL << PAGE_SHIFT)
#define PAGE_MASK               (~(PAGE_SIZE-1))

#define _H(__h) ((xc_interface *)(__h))
#define _D(__d) ((uint32_t)Int_val(__d))

#define Val_none (Val_int(0))

#define string_of_option_array(array, index) \
	((Field(array, index) == Val_none) ? NULL : String_val(Field(Field(array, index), 0)))

/* maybe here we should check the range of the input instead of blindly
 * casting it to uint32 */
#define cpuid_input_of_val(i1, i2, input) \
	i1 = (uint32_t) Int64_val(Field(input, 0)); \
	i2 = ((Field(input, 1) == Val_none) ? 0xffffffff : (uint32_t) Int64_val(Field(Field(input, 1), 0)));

static void Noreturn failwith_xc(xc_interface *xch)
{
	char error_str[256];
	if (xch) {
		const xc_error *error = xc_get_last_error(xch);
		if (error->code == XC_ERROR_NONE)
			snprintf(error_str, sizeof(error_str),
				 "%d: %s", errno, strerror(errno));
		else
			snprintf(error_str, sizeof(error_str),
				 "%d: %s: %s", error->code,
				 xc_error_code_to_desc(error->code),
				 error->message);
	} else {
		snprintf(error_str, sizeof(error_str),
			 "Unable to open XC interface");
	}
	caml_raise_with_string(*caml_named_value("xc.error"), error_str);
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
	CAMLparam0();
        xc_interface *xch;

	/* Don't assert XC_OPENFLAG_NON_REENTRANT because these bindings
	 * do not prevent re-entrancy to libxc */
        xch = xc_interface_open(NULL, NULL, 0);
        if (xch == NULL)
		failwith_xc(NULL);
        CAMLreturn((value)xch);
}


CAMLprim value stub_xc_interface_close(value xch)
{
	CAMLparam1(xch);

	caml_enter_blocking_section();
	xc_interface_close(_H(xch));
	caml_leave_blocking_section();

	CAMLreturn(Val_unit);
}

static int domain_create_flag_table[] = {
	XEN_DOMCTL_CDF_hvm_guest,
	XEN_DOMCTL_CDF_hap,
};

CAMLprim value stub_xc_domain_create(value xch, value ssidref,
                                     value flags, value handle)
{
	CAMLparam4(xch, ssidref, flags, handle);

	uint32_t domid = 0;
	xen_domain_handle_t h = { 0 };
	int result;
	int i;
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

	caml_enter_blocking_section();
	result = xc_domain_create(_H(xch), c_ssidref, h, c_flags, &domid, NULL);
	caml_leave_blocking_section();

	if (result < 0)
		failwith_xc(_H(xch));

	CAMLreturn(Val_int(domid));
}

CAMLprim value stub_xc_domain_max_vcpus(value xch, value domid,
                                        value max_vcpus)
{
	CAMLparam3(xch, domid, max_vcpus);
	int r;

	r = xc_domain_max_vcpus(_H(xch), _D(domid), Int_val(max_vcpus));
	if (r)
		failwith_xc(_H(xch));

	CAMLreturn(Val_unit);
}


value stub_xc_domain_sethandle(value xch, value domid, value handle)
{
	CAMLparam3(xch, domid, handle);
	xen_domain_handle_t h = { 0 };
	int i;

        if (Wosize_val(handle) != 16)
		caml_invalid_argument("Handle not a 16-integer array");

	for (i = 0; i < sizeof(h); i++) {
		h[i] = Int_val(Field(handle, i)) & 0xff;
	}

	i = xc_domain_sethandle(_H(xch), _D(domid), h);
	if (i)
		failwith_xc(_H(xch));

	CAMLreturn(Val_unit);
}

static value dom_op(value xch, value domid, int (*fn)(xc_interface *, uint32_t))
{
	CAMLparam2(xch, domid);
	int result;

	uint32_t c_domid = _D(domid);

	caml_enter_blocking_section();
	result = fn(_H(xch), c_domid);
	caml_leave_blocking_section();
        if (result)
		failwith_xc(_H(xch));
	CAMLreturn(Val_unit);
}

CAMLprim value stub_xc_domain_pause(value xch, value domid)
{
	return dom_op(xch, domid, xc_domain_pause);
}


CAMLprim value stub_xc_domain_unpause(value xch, value domid)
{
	return dom_op(xch, domid, xc_domain_unpause);
}

CAMLprim value stub_xc_domain_destroy(value xch, value domid)
{
	return dom_op(xch, domid, xc_domain_destroy);
}

CAMLprim value stub_xc_domain_resume_fast(value xch, value domid)
{
	CAMLparam2(xch, domid);
	int result;

	uint32_t c_domid = _D(domid);

	caml_enter_blocking_section();
	result = xc_domain_resume(_H(xch), c_domid, 1);
	caml_leave_blocking_section();
        if (result)
		failwith_xc(_H(xch));
	CAMLreturn(Val_unit);
}

CAMLprim value stub_xc_domain_shutdown(value xch, value domid, value reason)
{
	CAMLparam3(xch, domid, reason);
	int ret;

	ret = xc_domain_shutdown(_H(xch), _D(domid), Int_val(reason));
	if (ret < 0)
		failwith_xc(_H(xch));

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

CAMLprim value stub_xc_domain_getinfolist(value xch, value first_domain, value nb)
{
	CAMLparam3(xch, first_domain, nb);
	CAMLlocal2(result, temp);
	xc_domaininfo_t * info;
	int i, ret, toalloc, retval;
	unsigned int c_max_domains;
	uint32_t c_first_domain;

	/* get the minimum number of allocate byte we need and bump it up to page boundary */
	toalloc = (sizeof(xc_domaininfo_t) * Int_val(nb)) | 0xfff;
	ret = posix_memalign((void **) ((void *) &info), 4096, toalloc);
	if (ret)
		caml_raise_out_of_memory();

	result = temp = Val_emptylist;

	c_first_domain = _D(first_domain);
	c_max_domains = Int_val(nb);
	caml_enter_blocking_section();
	retval = xc_domain_getinfolist(_H(xch), c_first_domain,
				       c_max_domains, info);
	caml_leave_blocking_section();

	if (retval < 0) {
		free(info);
		failwith_xc(_H(xch));
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

CAMLprim value stub_xc_domain_getinfo(value xch, value domid)
{
	CAMLparam2(xch, domid);
	CAMLlocal1(result);
	xc_domaininfo_t info;
	int ret;

	ret = xc_domain_getinfolist(_H(xch), _D(domid), 1, &info);
	if (ret != 1)
		failwith_xc(_H(xch));
	if (info.domain != _D(domid))
		failwith_xc(_H(xch));

	result = alloc_domaininfo(&info);
	CAMLreturn(result);
}

CAMLprim value stub_xc_vcpu_getinfo(value xch, value domid, value vcpu)
{
	CAMLparam3(xch, domid, vcpu);
	CAMLlocal1(result);
	xc_vcpuinfo_t info;
	int retval;

	uint32_t c_domid = _D(domid);
	uint32_t c_vcpu = Int_val(vcpu);
	caml_enter_blocking_section();
	retval = xc_vcpu_getinfo(_H(xch), c_domid,
	                         c_vcpu, &info);
	caml_leave_blocking_section();
	if (retval < 0)
		failwith_xc(_H(xch));

	result = caml_alloc_tuple(5);
	Store_field(result, 0, Val_bool(info.online));
	Store_field(result, 1, Val_bool(info.blocked));
	Store_field(result, 2, Val_bool(info.running));
	Store_field(result, 3, caml_copy_int64(info.cpu_time));
	Store_field(result, 4, caml_copy_int32(info.cpu));

	CAMLreturn(result);
}

CAMLprim value stub_xc_vcpu_context_get(value xch, value domid,
                                        value cpu)
{
	CAMLparam3(xch, domid, cpu);
	CAMLlocal1(context);
	int ret;
	vcpu_guest_context_any_t ctxt;

	ret = xc_vcpu_getcontext(_H(xch), _D(domid), Int_val(cpu), &ctxt);

	context = caml_alloc_string(sizeof(ctxt));
	memcpy(String_val(context), (char *) &ctxt.c, sizeof(ctxt.c));

	CAMLreturn(context);
}

static int get_cpumap_len(value xch, value cpumap)
{
	int ml_len = Wosize_val(cpumap);
	int xc_len = xc_get_max_cpus(_H(xch));

	if (ml_len < xc_len)
		return ml_len;
	else
		return xc_len;
}

CAMLprim value stub_xc_vcpu_setaffinity(value xch, value domid,
                                        value vcpu, value cpumap)
{
	CAMLparam4(xch, domid, vcpu, cpumap);
	int i, len = get_cpumap_len(xch, cpumap);
	xc_cpumap_t c_cpumap;
	int retval;

	c_cpumap = xc_cpumap_alloc(_H(xch));
	if (c_cpumap == NULL)
		failwith_xc(_H(xch));

	for (i=0; i<len; i++) {
		if (Bool_val(Field(cpumap, i)))
			c_cpumap[i/8] |= 1 << (i&7);
	}
	retval = xc_vcpu_setaffinity(_H(xch), _D(domid),
				     Int_val(vcpu),
				     c_cpumap, NULL,
				     XEN_VCPUAFFINITY_HARD);
	free(c_cpumap);

	if (retval < 0)
		failwith_xc(_H(xch));
	CAMLreturn(Val_unit);
}

CAMLprim value stub_xc_vcpu_getaffinity(value xch, value domid,
                                        value vcpu)
{
	CAMLparam3(xch, domid, vcpu);
	CAMLlocal1(ret);
	xc_cpumap_t c_cpumap;
	int i, len = xc_get_max_cpus(_H(xch));
	int retval;

	if (len < 1)
		failwith_xc(_H(xch));

	c_cpumap = xc_cpumap_alloc(_H(xch));
	if (c_cpumap == NULL)
		failwith_xc(_H(xch));

	retval = xc_vcpu_getaffinity(_H(xch), _D(domid),
				     Int_val(vcpu),
				     c_cpumap, NULL,
				     XEN_VCPUAFFINITY_HARD);
	if (retval < 0) {
		free(c_cpumap);
		failwith_xc(_H(xch));
	}

	ret = caml_alloc(len, 0);

	for (i=0; i<len; i++) {
		if (c_cpumap[i/8] & 1 << (i&7))
			Store_field(ret, i, Val_true);
		else
			Store_field(ret, i, Val_false);
	}

	free(c_cpumap);

	CAMLreturn(ret);
}

CAMLprim value stub_xc_sched_id(value xch)
{
	CAMLparam1(xch);
	int sched_id;

	if (xc_sched_id(_H(xch), &sched_id))
		failwith_xc(_H(xch));
	CAMLreturn(Val_int(sched_id));
}

CAMLprim value stub_xc_evtchn_alloc_unbound(value xch,
                                            value local_domid,
                                            value remote_domid)
{
	CAMLparam3(xch, local_domid, remote_domid);
	int result;

	uint32_t c_local_domid = _D(local_domid);
	uint32_t c_remote_domid = _D(remote_domid);

	caml_enter_blocking_section();
	result = xc_evtchn_alloc_unbound(_H(xch), c_local_domid,
	                                     c_remote_domid);
	caml_leave_blocking_section();

	if (result < 0)
		failwith_xc(_H(xch));
	CAMLreturn(Val_int(result));
}

CAMLprim value stub_xc_evtchn_reset(value xch, value domid)
{
	CAMLparam2(xch, domid);
	int r;

	r = xc_evtchn_reset(_H(xch), _D(domid));
	if (r < 0)
		failwith_xc(_H(xch));
	CAMLreturn(Val_unit);
}


CAMLprim value stub_xc_readconsolering(value xch)
{
	/* Safe to use outside of blocking sections because of Ocaml GC lock. */
	static unsigned int conring_size = 16384 + 1;

	unsigned int count = conring_size, size = count, index = 0;
	char *str = NULL, *ptr;
	int ret;

	CAMLparam1(xch);
	CAMLlocal1(ring);

	str = malloc(size);
	if (!str)
		caml_raise_out_of_memory();

	/* Hopefully our conring_size guess is sufficient */
	caml_enter_blocking_section();
	ret = xc_readconsolering(_H(xch), str, &count, 0, 0, &index);
	caml_leave_blocking_section();

	if (ret < 0) {
		free(str);
		failwith_xc(_H(xch));
	}

	while (count == size && ret >= 0) {
		size += count - 1;
		if (size < count)
			break;

		ptr = realloc(str, size);
		if (!ptr)
			break;

		str = ptr + count;
		count = size - count;

		caml_enter_blocking_section();
		ret = xc_readconsolering(_H(xch), str, &count, 0, 1, &index);
		caml_leave_blocking_section();

		count += str - ptr;
		str = ptr;
	}

	/*
	 * If we didn't break because of an overflow with size, and we have
	 * needed to realloc() ourself more space, update our tracking of the
	 * real console ring size.
	 */
	if (size > conring_size)
		conring_size = size;

	ring = caml_alloc_string(count);
	memcpy(String_val(ring), str, count);
	free(str);

	CAMLreturn(ring);
}

CAMLprim value stub_xc_send_debug_keys(value xch, value keys)
{
	CAMLparam2(xch, keys);
	int r;

	r = xc_send_debug_keys(_H(xch), String_val(keys));
	if (r)
		failwith_xc(_H(xch));
	CAMLreturn(Val_unit);
}

CAMLprim value stub_xc_physinfo(value xch)
{
	CAMLparam1(xch);
	CAMLlocal3(physinfo, cap_list, tmp);
	xc_physinfo_t c_physinfo;
	int r;

	caml_enter_blocking_section();
	r = xc_physinfo(_H(xch), &c_physinfo);
	caml_leave_blocking_section();

	if (r)
		failwith_xc(_H(xch));

	tmp = cap_list = Val_emptylist;
	for (r = 0; r < 2; r++) {
		if ((c_physinfo.capabilities >> r) & 1) {
			tmp = caml_alloc_small(2, Tag_cons);
			Field(tmp, 0) = Val_int(r);
			Field(tmp, 1) = cap_list;
			cap_list = tmp;
		}
	}

	physinfo = caml_alloc_tuple(10);
	Store_field(physinfo, 0, Val_int(c_physinfo.threads_per_core));
	Store_field(physinfo, 1, Val_int(c_physinfo.cores_per_socket));
	Store_field(physinfo, 2, Val_int(c_physinfo.nr_cpus));
	Store_field(physinfo, 3, Val_int(c_physinfo.max_node_id));
	Store_field(physinfo, 4, Val_int(c_physinfo.cpu_khz));
	Store_field(physinfo, 5, caml_copy_nativeint(c_physinfo.total_pages));
	Store_field(physinfo, 6, caml_copy_nativeint(c_physinfo.free_pages));
	Store_field(physinfo, 7, caml_copy_nativeint(c_physinfo.scrub_pages));
	Store_field(physinfo, 8, cap_list);
	Store_field(physinfo, 9, Val_int(c_physinfo.max_cpu_id + 1));

	CAMLreturn(physinfo);
}

CAMLprim value stub_xc_pcpu_info(value xch, value nr_cpus)
{
	CAMLparam2(xch, nr_cpus);
	CAMLlocal2(pcpus, v);
	xc_cpuinfo_t *info;
	int r, size;

	if (Int_val(nr_cpus) < 1)
		caml_invalid_argument("nr_cpus");
	
	info = calloc(Int_val(nr_cpus) + 1, sizeof(*info));
	if (!info)
		caml_raise_out_of_memory();

	caml_enter_blocking_section();
	r = xc_getcpuinfo(_H(xch), Int_val(nr_cpus), info, &size);
	caml_leave_blocking_section();

	if (r) {
		free(info);
		failwith_xc(_H(xch));
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

CAMLprim value stub_xc_domain_setmaxmem(value xch, value domid,
                                        value max_memkb)
{
	CAMLparam3(xch, domid, max_memkb);
	int retval;

	uint32_t c_domid = _D(domid);
	unsigned int c_max_memkb = Int64_val(max_memkb);
	caml_enter_blocking_section();
	retval = xc_domain_setmaxmem(_H(xch), c_domid,
	                                 c_max_memkb);
	caml_leave_blocking_section();
	if (retval)
		failwith_xc(_H(xch));
	CAMLreturn(Val_unit);
}

CAMLprim value stub_xc_domain_set_memmap_limit(value xch, value domid,
                                               value map_limitkb)
{
	CAMLparam3(xch, domid, map_limitkb);
	unsigned long v;
	int retval;

	v = Int64_val(map_limitkb);
	retval = xc_domain_set_memmap_limit(_H(xch), _D(domid), v);
	if (retval)
		failwith_xc(_H(xch));

	CAMLreturn(Val_unit);
}

CAMLprim value stub_xc_domain_memory_increase_reservation(value xch,
                                                          value domid,
                                                          value mem_kb)
{
	CAMLparam3(xch, domid, mem_kb);
	int retval;

	unsigned long nr_extents = ((unsigned long)(Int64_val(mem_kb))) >> (PAGE_SHIFT - 10);

	uint32_t c_domid = _D(domid);
	caml_enter_blocking_section();
	retval = xc_domain_increase_reservation_exact(_H(xch), c_domid,
							  nr_extents, 0, 0, NULL);
	caml_leave_blocking_section();

	if (retval)
		failwith_xc(_H(xch));
	CAMLreturn(Val_unit);
}

CAMLprim value stub_xc_domain_set_machine_address_size(value xch,
						       value domid,
						       value width)
{
	CAMLparam3(xch, domid, width);
	uint32_t c_domid = _D(domid);
	int c_width = Int_val(width);

	int retval = xc_domain_set_machine_address_size(_H(xch), c_domid, c_width);
	if (retval)
		failwith_xc(_H(xch));
	CAMLreturn(Val_unit);
}

CAMLprim value stub_xc_domain_get_machine_address_size(value xch,
                                                       value domid)
{
	CAMLparam2(xch, domid);
	int retval;

	retval = xc_domain_get_machine_address_size(_H(xch), _D(domid));
	if (retval < 0)
		failwith_xc(_H(xch));
	CAMLreturn(Val_int(retval));
}

CAMLprim value stub_xc_domain_cpuid_set(value xch, value domid,
                                        value input,
                                        value config)
{
	CAMLparam4(xch, domid, input, config);
	CAMLlocal2(array, tmp);
#if defined(__i386__) || defined(__x86_64__)
	int r;
	unsigned int c_input[2];
	char *c_config[4], *out_config[4];

	c_config[0] = string_of_option_array(config, 0);
	c_config[1] = string_of_option_array(config, 1);
	c_config[2] = string_of_option_array(config, 2);
	c_config[3] = string_of_option_array(config, 3);

	cpuid_input_of_val(c_input[0], c_input[1], input);

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

	r = xc_cpuid_set(_H(xch), _D(domid),
			 c_input, (const char **)c_config, out_config);
	if (r < 0)
		failwith_xc(_H(xch));
#else
	caml_failwith("xc_domain_cpuid_set: not implemented");
#endif
	CAMLreturn(array);
}

CAMLprim value stub_xc_domain_cpuid_apply_policy(value xch, value domid)
{
	CAMLparam2(xch, domid);
#if defined(__i386__) || defined(__x86_64__)
	int r;

	r = xc_cpuid_apply_policy(_H(xch), _D(domid), NULL, 0);
	if (r < 0)
		failwith_xc(_H(xch));
#else
	caml_failwith("xc_domain_cpuid_apply_policy: not implemented");
#endif
	CAMLreturn(Val_unit);
}

CAMLprim value stub_xc_cpuid_check(value xch, value input, value config)
{
	CAMLparam3(xch, input, config);
	CAMLlocal3(ret, array, tmp);
#if defined(__i386__) || defined(__x86_64__)
	int r;
	unsigned int c_input[2];
	char *c_config[4], *out_config[4];

	c_config[0] = string_of_option_array(config, 0);
	c_config[1] = string_of_option_array(config, 1);
	c_config[2] = string_of_option_array(config, 2);
	c_config[3] = string_of_option_array(config, 3);

	cpuid_input_of_val(c_input[0], c_input[1], input);

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

	r = xc_cpuid_check(_H(xch), c_input, (const char **)c_config, out_config);
	if (r < 0)
		failwith_xc(_H(xch));

	ret = caml_alloc_tuple(2);
	Store_field(ret, 0, Val_bool(r));
	Store_field(ret, 1, array);

#else
	caml_failwith("xc_domain_cpuid_check: not implemented");
#endif
	CAMLreturn(ret);
}

CAMLprim value stub_xc_version_version(value xch)
{
	CAMLparam1(xch);
	CAMLlocal1(result);
	xen_extraversion_t extra;
	long packed;
	int retval;

	caml_enter_blocking_section();
	packed = xc_version(_H(xch), XENVER_version, NULL);
	caml_leave_blocking_section();

	if (packed < 0)
		failwith_xc(_H(xch));

	caml_enter_blocking_section();
	retval = xc_version(_H(xch), XENVER_extraversion, &extra);
	caml_leave_blocking_section();

	if (retval)
		failwith_xc(_H(xch));

	result = caml_alloc_tuple(3);

	Store_field(result, 0, Val_int(packed >> 16));
	Store_field(result, 1, Val_int(packed & 0xffff));
	Store_field(result, 2, caml_copy_string(extra));

	CAMLreturn(result);
}


CAMLprim value stub_xc_version_compile_info(value xch)
{
	CAMLparam1(xch);
	CAMLlocal1(result);
	xen_compile_info_t ci;
	int retval;

	caml_enter_blocking_section();
	retval = xc_version(_H(xch), XENVER_compile_info, &ci);
	caml_leave_blocking_section();

	if (retval)
		failwith_xc(_H(xch));

	result = caml_alloc_tuple(4);

	Store_field(result, 0, caml_copy_string(ci.compiler));
	Store_field(result, 1, caml_copy_string(ci.compile_by));
	Store_field(result, 2, caml_copy_string(ci.compile_domain));
	Store_field(result, 3, caml_copy_string(ci.compile_date));

	CAMLreturn(result);
}


static value xc_version_single_string(value xch, int code, void *info)
{
	CAMLparam1(xch);
	int retval;

	caml_enter_blocking_section();
	retval = xc_version(_H(xch), code, info);
	caml_leave_blocking_section();

	if (retval)
		failwith_xc(_H(xch));

	CAMLreturn(caml_copy_string((char *)info));
}


CAMLprim value stub_xc_version_changeset(value xch)
{
	xen_changeset_info_t ci;

	return xc_version_single_string(xch, XENVER_changeset, &ci);
}


CAMLprim value stub_xc_version_capabilities(value xch)
{
	xen_capabilities_info_t ci;

	return xc_version_single_string(xch, XENVER_capabilities, &ci);
}


CAMLprim value stub_pages_to_kib(value pages)
{
	CAMLparam1(pages);

	CAMLreturn(caml_copy_int64(Int64_val(pages) << (PAGE_SHIFT - 10)));
}


CAMLprim value stub_map_foreign_range(value xch, value dom,
                                      value size, value mfn)
{
	CAMLparam4(xch, dom, size, mfn);
	CAMLlocal1(result);
	struct mmap_interface *intf;
	uint32_t c_dom;
	unsigned long c_mfn;

	result = caml_alloc(sizeof(struct mmap_interface), Abstract_tag);
	intf = (struct mmap_interface *) result;

	intf->len = Int_val(size);

	c_dom = _D(dom);
	c_mfn = Nativeint_val(mfn);
	caml_enter_blocking_section();
	intf->addr = xc_map_foreign_range(_H(xch), c_dom,
	                                  intf->len, PROT_READ|PROT_WRITE,
	                                  c_mfn);
	caml_leave_blocking_section();
	if (!intf->addr)
		caml_failwith("xc_map_foreign_range error");
	CAMLreturn(result);
}

CAMLprim value stub_sched_credit_domain_get(value xch, value domid)
{
	CAMLparam2(xch, domid);
	CAMLlocal1(sdom);
	struct xen_domctl_sched_credit c_sdom;
	int ret;

	caml_enter_blocking_section();
	ret = xc_sched_credit_domain_get(_H(xch), _D(domid), &c_sdom);
	caml_leave_blocking_section();
	if (ret != 0)
		failwith_xc(_H(xch));

	sdom = caml_alloc_tuple(2);
	Store_field(sdom, 0, Val_int(c_sdom.weight));
	Store_field(sdom, 1, Val_int(c_sdom.cap));

	CAMLreturn(sdom);
}

CAMLprim value stub_sched_credit_domain_set(value xch, value domid,
                                            value sdom)
{
	CAMLparam3(xch, domid, sdom);
	struct xen_domctl_sched_credit c_sdom;
	int ret;

	c_sdom.weight = Int_val(Field(sdom, 0));
	c_sdom.cap = Int_val(Field(sdom, 1));
	caml_enter_blocking_section();
	ret = xc_sched_credit_domain_set(_H(xch), _D(domid), &c_sdom);
	caml_leave_blocking_section();
	if (ret != 0)
		failwith_xc(_H(xch));

	CAMLreturn(Val_unit);
}

CAMLprim value stub_shadow_allocation_get(value xch, value domid)
{
	CAMLparam2(xch, domid);
	CAMLlocal1(mb);
	unsigned long c_mb;
	int ret;

	caml_enter_blocking_section();
	ret = xc_shadow_control(_H(xch), _D(domid),
				XEN_DOMCTL_SHADOW_OP_GET_ALLOCATION,
				NULL, 0, &c_mb, 0, NULL);
	caml_leave_blocking_section();
	if (ret != 0)
		failwith_xc(_H(xch));

	mb = Val_int(c_mb);
	CAMLreturn(mb);
}

CAMLprim value stub_shadow_allocation_set(value xch, value domid,
					  value mb)
{
	CAMLparam3(xch, domid, mb);
	unsigned long c_mb;
	int ret;

	c_mb = Int_val(mb);
	caml_enter_blocking_section();
	ret = xc_shadow_control(_H(xch), _D(domid),
				XEN_DOMCTL_SHADOW_OP_SET_ALLOCATION,
				NULL, 0, &c_mb, 0, NULL);
	caml_leave_blocking_section();
	if (ret != 0)
		failwith_xc(_H(xch));

	CAMLreturn(Val_unit);
}

CAMLprim value stub_xc_domain_get_pfn_list(value xch, value domid,
                                           value nr_pfns)
{
	CAMLparam3(xch, domid, nr_pfns);
	CAMLlocal2(array, v);
	unsigned long c_nr_pfns;
	long ret, i;
	uint64_t *c_array;

	c_nr_pfns = Nativeint_val(nr_pfns);

	c_array = malloc(sizeof(uint64_t) * c_nr_pfns);
	if (!c_array)
		caml_raise_out_of_memory();

	ret = xc_get_pfn_list(_H(xch), _D(domid),
			      c_array, c_nr_pfns);
	if (ret < 0) {
		free(c_array);
		failwith_xc(_H(xch));
	}

	array = caml_alloc(ret, 0);
	for (i = 0; i < ret; i++) {
		v = caml_copy_nativeint(c_array[i]);
		Store_field(array, i, v);
	}
	free(c_array);

	CAMLreturn(array);
}

CAMLprim value stub_xc_domain_ioport_permission(value xch, value domid,
					       value start_port, value nr_ports,
					       value allow)
{
	CAMLparam5(xch, domid, start_port, nr_ports, allow);
	uint32_t c_start_port, c_nr_ports;
	uint8_t c_allow;
	int ret;

	c_start_port = Int_val(start_port);
	c_nr_ports = Int_val(nr_ports);
	c_allow = Bool_val(allow);

	ret = xc_domain_ioport_permission(_H(xch), _D(domid),
					 c_start_port, c_nr_ports, c_allow);
	if (ret < 0)
		failwith_xc(_H(xch));

	CAMLreturn(Val_unit);
}

CAMLprim value stub_xc_domain_iomem_permission(value xch, value domid,
					       value start_pfn, value nr_pfns,
					       value allow)
{
	CAMLparam5(xch, domid, start_pfn, nr_pfns, allow);
	unsigned long c_start_pfn, c_nr_pfns;
	uint8_t c_allow;
	int ret;

	c_start_pfn = Nativeint_val(start_pfn);
	c_nr_pfns = Nativeint_val(nr_pfns);
	c_allow = Bool_val(allow);

	ret = xc_domain_iomem_permission(_H(xch), _D(domid),
					 c_start_pfn, c_nr_pfns, c_allow);
	if (ret < 0)
		failwith_xc(_H(xch));

	CAMLreturn(Val_unit);
}

CAMLprim value stub_xc_domain_irq_permission(value xch, value domid,
					     value pirq, value allow)
{
	CAMLparam4(xch, domid, pirq, allow);
	uint8_t c_pirq;
	uint8_t c_allow;
	int ret;

	c_pirq = Int_val(pirq);
	c_allow = Bool_val(allow);

	ret = xc_domain_irq_permission(_H(xch), _D(domid),
				       c_pirq, c_allow);
	if (ret < 0)
		failwith_xc(_H(xch));

	CAMLreturn(Val_unit);
}

static uint32_t encode_sbdf(int domain, int bus, int dev, int func)
{
	return  ((uint32_t)domain & 0xffff) << 16 |
		((uint32_t)bus    &   0xff) << 8  |
		((uint32_t)dev    &   0x1f) << 3  |
		((uint32_t)func   &    0x7);
}

CAMLprim value stub_xc_domain_test_assign_device(value xch, value domid, value desc)
{
	CAMLparam3(xch, domid, desc);
	int ret;
	int domain, bus, dev, func;
	uint32_t sbdf;

	domain = Int_val(Field(desc, 0));
	bus = Int_val(Field(desc, 1));
	dev = Int_val(Field(desc, 2));
	func = Int_val(Field(desc, 3));
	sbdf = encode_sbdf(domain, bus, dev, func);

	ret = xc_test_assign_device(_H(xch), _D(domid), sbdf);

	CAMLreturn(Val_bool(ret == 0));
}

static int domain_assign_device_rdm_flag_table[] = {
    XEN_DOMCTL_DEV_RDM_RELAXED,
};

CAMLprim value stub_xc_domain_assign_device(value xch, value domid, value desc,
                                            value rflag)
{
	CAMLparam4(xch, domid, desc, rflag);
	int ret;
	int domain, bus, dev, func;
	uint32_t sbdf, flag;

	domain = Int_val(Field(desc, 0));
	bus = Int_val(Field(desc, 1));
	dev = Int_val(Field(desc, 2));
	func = Int_val(Field(desc, 3));
	sbdf = encode_sbdf(domain, bus, dev, func);

	ret = Int_val(Field(rflag, 0));
	flag = domain_assign_device_rdm_flag_table[ret];

	ret = xc_assign_device(_H(xch), _D(domid), sbdf, flag);

	if (ret < 0)
		failwith_xc(_H(xch));
	CAMLreturn(Val_unit);
}

CAMLprim value stub_xc_domain_deassign_device(value xch, value domid, value desc)
{
	CAMLparam3(xch, domid, desc);
	int ret;
	int domain, bus, dev, func;
	uint32_t sbdf;

	domain = Int_val(Field(desc, 0));
	bus = Int_val(Field(desc, 1));
	dev = Int_val(Field(desc, 2));
	func = Int_val(Field(desc, 3));
	sbdf = encode_sbdf(domain, bus, dev, func);

	ret = xc_deassign_device(_H(xch), _D(domid), sbdf);

	if (ret < 0)
		failwith_xc(_H(xch));
	CAMLreturn(Val_unit);
}

CAMLprim value stub_xc_get_cpu_featureset(value xch, value idx)
{
	CAMLparam2(xch, idx);
	CAMLlocal1(bitmap_val);
#if defined(__i386__) || defined(__x86_64__)

	/* Safe, because of the global ocaml lock. */
	static uint32_t fs_len;

	if (fs_len == 0)
	{
		int ret = xc_get_cpu_featureset(_H(xch), 0, &fs_len, NULL);

		if (ret || (fs_len == 0))
			failwith_xc(_H(xch));
	}

	{
		/* To/from hypervisor to retrieve actual featureset */
		uint32_t fs[fs_len], len = fs_len;
		unsigned int i;

		int ret = xc_get_cpu_featureset(_H(xch), Int_val(idx), &len, fs);

		if (ret)
			failwith_xc(_H(xch));

		bitmap_val = caml_alloc(len, 0);

		for (i = 0; i < len; ++i)
			Store_field(bitmap_val, i, caml_copy_int64(fs[i]));
	}
#else
	caml_failwith("xc_get_cpu_featureset: not implemented");
#endif
	CAMLreturn(bitmap_val);
}

CAMLprim value stub_xc_watchdog(value xch, value domid, value timeout)
{
	CAMLparam3(xch, domid, timeout);
	int ret;
	unsigned int c_timeout = Int32_val(timeout);

	ret = xc_watchdog(_H(xch), _D(domid), c_timeout);
	if (ret < 0)
		failwith_xc(_H(xch));

	CAMLreturn(Val_int(ret));
}

/*
 * Local variables:
 *  indent-tabs-mode: t
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
