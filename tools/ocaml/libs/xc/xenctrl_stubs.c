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
#include <inttypes.h>

#define XC_WANT_COMPAT_MAP_FOREIGN_API
#include <xenctrl.h>
#include <xenguest.h>
#include <xen-tools/common-macros.h>

#include "mmap_stubs.h"

#ifndef Val_none
#define Val_none (Val_int(0))
#endif

#ifndef Tag_some
#define Tag_some 0
#endif

static inline xc_interface *xch_of_val(value v)
{
	xc_interface *xch = *(xc_interface **)Data_custom_val(v);

	return xch;
}

static void stub_xenctrl_finalize(value v)
{
	xc_interface *xch = xch_of_val(v);

	xc_interface_close(xch);
}

static struct custom_operations xenctrl_ops = {
	.identifier  = "xenctrl",
	.finalize    = stub_xenctrl_finalize,
	.compare     = custom_compare_default,     /* Can't compare     */
	.hash        = custom_hash_default,        /* Can't hash        */
	.serialize   = custom_serialize_default,   /* Can't serialize   */
	.deserialize = custom_deserialize_default, /* Can't deserialize */
	.compare_ext = custom_compare_ext_default, /* Can't compare     */
};

#define string_of_option_array(array, index) \
	((Field(array, index) == Val_none) ? NULL : String_val(Field(Field(array, index), 0)))

static void Noreturn failwith_xc(xc_interface *xch)
{
	char error_str[XC_MAX_ERROR_MSG_LEN + 6];
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

CAMLprim value stub_xc_interface_open(value unit)
{
	CAMLparam1(unit);
	CAMLlocal1(result);
	xc_interface *xch;

	result = caml_alloc_custom(&xenctrl_ops, sizeof(xch), 0, 1);

	caml_enter_blocking_section();
	xch = xc_interface_open(NULL, NULL, 0);
	caml_leave_blocking_section();

	if ( !xch )
		failwith_xc(xch);

	*(xc_interface **)Data_custom_val(result) = xch;

	CAMLreturn(result);
}

static void domain_handle_of_uuid_string(xen_domain_handle_t h,
					 const char *uuid)
{
#define X "%02"SCNx8
#define UUID_FMT (X X X X "-" X X "-" X X "-" X X "-" X X X X X X)

	if ( sscanf(uuid, UUID_FMT, &h[0], &h[1], &h[2], &h[3], &h[4],
		    &h[5], &h[6], &h[7], &h[8], &h[9], &h[10], &h[11],
		    &h[12], &h[13], &h[14], &h[15]) != 16 )
	{
		char buf[128];

		snprintf(buf, sizeof(buf),
			 "Xc.int_array_of_uuid_string: %s", uuid);

		caml_invalid_argument(buf);
	}

#undef X
}

/*
 * Various fields which are a bitmap in the C ABI are converted to lists of
 * integers in the Ocaml ABI for more idiomatic handling.
 */
static value c_bitmap_to_ocaml_list
             /* ! */
             /*
	      * All calls to this function must be in a form suitable
	      * for xenctrl_abi_check.  The parsing there is ad-hoc.
	      */
             (unsigned int bitmap)
{
	CAMLparam0();
	CAMLlocal2(list, tmp);

#if defined(__i386__) || defined(__x86_64__)
/*
 * This check file contains a mixture of stuff, because it is
 * generated from the whole of this xenctrl_stubs.c file (without
 * regard to arch ifdefs) and the whole of xenctrl.ml (which does not
 * have any arch ifdeffery).  Currently, there is only x86 and
 * arch-independent stuff, and there is no facility in the abi-check
 * script for arch conditionals.  So for now we make the checks
 * effective on x86 only; this will suffice to defend even ARM
 * because breaking changes to common code will break the build
 * on x86 and not make it to master.  This is a bit of a bodge.
 */
#include "xenctrl_abi_check.h"
#endif

	list = tmp = Val_emptylist;

	for ( unsigned int i = 0; bitmap; i++, bitmap >>= 1 )
	{
		if ( !(bitmap & 1) )
			continue;

		tmp = caml_alloc_small(2, Tag_cons);
		Field(tmp, 0) = Val_int(i);
		Field(tmp, 1) = list;
		list = tmp;
	}

	CAMLreturn(list);
}

static unsigned int ocaml_list_to_c_bitmap(value l)
             /* ! */
             /*
	      * All calls to this function must be in a form suitable
	      * for xenctrl_abi_check.  The parsing there is ad-hoc.
	      */
{
	unsigned int val = 0;

	for ( ; l != Val_none; l = Field(l, 1) )
		val |= 1u << Int_val(Field(l, 0));

	return val;
}

CAMLprim value stub_xc_domain_create(value xch_val, value wanted_domid, value config)
{
	CAMLparam3(xch_val, wanted_domid, config);
	CAMLlocal2(l, arch_domconfig);
	xc_interface *xch = xch_of_val(xch_val);

	/* Mnemonics for the named fields inside domctl_create_config */
#define VAL_SSIDREF             Field(config, 0)
#define VAL_HANDLE              Field(config, 1)
#define VAL_FLAGS               Field(config, 2)
#define VAL_IOMMU_OPTS          Field(config, 3)
#define VAL_MAX_VCPUS           Field(config, 4)
#define VAL_MAX_EVTCHN_PORT     Field(config, 5)
#define VAL_MAX_GRANT_FRAMES    Field(config, 6)
#define VAL_MAX_MAPTRACK_FRAMES Field(config, 7)
#define VAL_MAX_GRANT_VERSION   Field(config, 8)
#define VAL_VMTRACE_BUF_KB      Field(config, 9)
#define VAL_CPUPOOL_ID          Field(config, 10)
#define VAL_ARCH                Field(config, 11)

	uint32_t domid = Int_val(wanted_domid);
	uint64_t vmtrace_size = Int32_val(VAL_VMTRACE_BUF_KB);

	vmtrace_size = ROUNDUP(vmtrace_size << 10, XC_PAGE_SHIFT);
	if ( vmtrace_size != (uint32_t)vmtrace_size )
		caml_invalid_argument("vmtrace_buf_kb");

	int result;
	struct xen_domctl_createdomain cfg = {
		.ssidref = Int32_val(VAL_SSIDREF),
		.max_vcpus = Int_val(VAL_MAX_VCPUS),
		.max_evtchn_port = Int_val(VAL_MAX_EVTCHN_PORT),
		.max_grant_frames = Int_val(VAL_MAX_GRANT_FRAMES),
		.max_maptrack_frames = Int_val(VAL_MAX_MAPTRACK_FRAMES),
		.grant_opts =
		    XEN_DOMCTL_GRANT_version(Int_val(VAL_MAX_GRANT_VERSION)),
		.vmtrace_size = vmtrace_size,
		.cpupool_id = Int32_val(VAL_CPUPOOL_ID),
	};

	domain_handle_of_uuid_string(cfg.handle, String_val(VAL_HANDLE));

	cfg.flags = ocaml_list_to_c_bitmap
		/* ! domain_create_flag CDF_ lc */
		/* ! XEN_DOMCTL_CDF_ XEN_DOMCTL_CDF_MAX max */
		(VAL_FLAGS);

	cfg.iommu_opts = ocaml_list_to_c_bitmap
		/* ! domain_create_iommu_opts IOMMU_ lc */
		/* ! XEN_DOMCTL_IOMMU_ XEN_DOMCTL_IOMMU_MAX max */
		(VAL_IOMMU_OPTS);

	arch_domconfig = Field(VAL_ARCH, 0);
	switch ( Tag_val(VAL_ARCH) )
	{
	case 0: /* ARM - nothing to do */
		caml_failwith("Unhandled: ARM");
		break;

	case 1: /* X86 - emulation flags in the block */
#if defined(__i386__) || defined(__x86_64__)

		/* Quick & dirty check for ABI changes. */
		BUILD_BUG_ON(sizeof(cfg) != 68);

        /* Mnemonics for the named fields inside xen_x86_arch_domainconfig */
#define VAL_EMUL_FLAGS          Field(arch_domconfig, 0)
#define VAL_MISC_FLAGS          Field(arch_domconfig, 1)

		cfg.arch.emulation_flags = ocaml_list_to_c_bitmap
			/* ! x86_arch_emulation_flags X86_EMU_ none */
			/* ! XEN_X86_EMU_ XEN_X86_EMU_ALL all */
			(VAL_EMUL_FLAGS);

		cfg.arch.misc_flags = ocaml_list_to_c_bitmap
			/* ! x86_arch_misc_flags X86_ none */
			/* ! XEN_X86_ XEN_X86_MSR_RELAXED all */
			(VAL_MISC_FLAGS);

#undef VAL_MISC_FLAGS
#undef VAL_EMUL_FLAGS

#else
		caml_failwith("Unhandled: x86");
#endif
		break;

	default:
		caml_failwith("Unhandled domconfig type");
	}

#undef VAL_ARCH
#undef VAL_CPUPOOL_ID
#undef VAL_VMTRACE_BUF_KB
#undef VAL_MAX_GRANT_VERSION
#undef VAL_MAX_MAPTRACK_FRAMES
#undef VAL_MAX_GRANT_FRAMES
#undef VAL_MAX_EVTCHN_PORT
#undef VAL_MAX_VCPUS
#undef VAL_IOMMU_OPTS
#undef VAL_FLAGS
#undef VAL_HANDLE
#undef VAL_SSIDREF

	caml_enter_blocking_section();
	result = xc_domain_create(xch, &domid, &cfg);
	caml_leave_blocking_section();

	if (result < 0)
		failwith_xc(xch);

	CAMLreturn(Val_int(domid));
}

CAMLprim value stub_xc_domain_max_vcpus(value xch_val, value domid,
                                        value max_vcpus)
{
	CAMLparam3(xch_val, domid, max_vcpus);
	xc_interface *xch = xch_of_val(xch_val);
	int r;

	r = xc_domain_max_vcpus(xch, Int_val(domid), Int_val(max_vcpus));
	if (r)
		failwith_xc(xch);

	CAMLreturn(Val_unit);
}


value stub_xc_domain_sethandle(value xch_val, value domid, value handle)
{
	CAMLparam3(xch_val, domid, handle);
	xc_interface *xch = xch_of_val(xch_val);
	xen_domain_handle_t h;
	int i;

	domain_handle_of_uuid_string(h, String_val(handle));

	i = xc_domain_sethandle(xch, Int_val(domid), h);
	if (i)
		failwith_xc(xch);

	CAMLreturn(Val_unit);
}

static value dom_op(value xch_val, value domid,
		    int (*fn)(xc_interface *, uint32_t))
{
	CAMLparam2(xch_val, domid);
	xc_interface *xch = xch_of_val(xch_val);
	int result;

	uint32_t c_domid = Int_val(domid);

	caml_enter_blocking_section();
	result = fn(xch, c_domid);
	caml_leave_blocking_section();
        if (result)
		failwith_xc(xch);
	CAMLreturn(Val_unit);
}

CAMLprim value stub_xc_domain_pause(value xch_val, value domid)
{
	return dom_op(xch_val, domid, xc_domain_pause);
}


CAMLprim value stub_xc_domain_unpause(value xch_val, value domid)
{
	return dom_op(xch_val, domid, xc_domain_unpause);
}

CAMLprim value stub_xc_domain_destroy(value xch_val, value domid)
{
	return dom_op(xch_val, domid, xc_domain_destroy);
}

CAMLprim value stub_xc_domain_resume_fast(value xch_val, value domid)
{
	CAMLparam2(xch_val, domid);
	xc_interface *xch = xch_of_val(xch_val);
	int result;

	uint32_t c_domid = Int_val(domid);

	caml_enter_blocking_section();
	result = xc_domain_resume(xch, c_domid, 1);
	caml_leave_blocking_section();
        if (result)
		failwith_xc(xch);
	CAMLreturn(Val_unit);
}

CAMLprim value stub_xc_domain_shutdown(value xch_val, value domid, value reason)
{
	CAMLparam3(xch_val, domid, reason);
	xc_interface *xch = xch_of_val(xch_val);
	int ret;

	ret = xc_domain_shutdown(xch, Int_val(domid), Int_val(reason));
	if (ret < 0)
		failwith_xc(xch);

	CAMLreturn(Val_unit);
}

static value alloc_domaininfo(xc_domaininfo_t * info)
{
	CAMLparam0();
	CAMLlocal5(result, tmp, arch_config, x86_arch_config, emul_list);
	int i;

	result = caml_alloc_tuple(17);

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

#if defined(__i386__) || defined(__x86_64__)
	/*
	 * emulation_flags: x86_arch_emulation_flags list;
	 */
	emul_list = c_bitmap_to_ocaml_list
		/* ! x86_arch_emulation_flags */
		(info->arch_config.emulation_flags);

	/* xen_x86_arch_domainconfig */
	x86_arch_config = caml_alloc_tuple(1);
	Store_field(x86_arch_config, 0, emul_list);

	/* arch_config: arch_domainconfig */
	arch_config = caml_alloc_small(1, 1);

	Store_field(arch_config, 0, x86_arch_config);

	Store_field(result, 16, arch_config);
#endif

	CAMLreturn(result);
}

CAMLprim value stub_xc_domain_getinfolist(value xch_val, value first_domain, value nb)
{
	CAMLparam3(xch_val, first_domain, nb);
	CAMLlocal2(result, temp);
	xc_interface *xch = xch_of_val(xch_val);
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

	c_first_domain = Int_val(first_domain);
	c_max_domains = Int_val(nb);
	caml_enter_blocking_section();
	retval = xc_domain_getinfolist(xch, c_first_domain,
				       c_max_domains, info);
	caml_leave_blocking_section();

	if (retval < 0) {
		free(info);
		failwith_xc(xch);
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

CAMLprim value stub_xc_domain_getinfo(value xch_val, value domid)
{
	CAMLparam2(xch_val, domid);
	CAMLlocal1(result);
	xc_interface *xch = xch_of_val(xch_val);
	xc_domaininfo_t info;
	int ret;

	ret = xc_domain_getinfo_single(xch, Int_val(domid), &info);
	if (ret < 0)
		failwith_xc(xch);

	result = alloc_domaininfo(&info);
	CAMLreturn(result);
}

CAMLprim value stub_xc_vcpu_getinfo(value xch_val, value domid, value vcpu)
{
	CAMLparam3(xch_val, domid, vcpu);
	CAMLlocal1(result);
	xc_interface *xch = xch_of_val(xch_val);
	xc_vcpuinfo_t info;
	int retval;

	uint32_t c_domid = Int_val(domid);
	uint32_t c_vcpu = Int_val(vcpu);
	caml_enter_blocking_section();
	retval = xc_vcpu_getinfo(xch, c_domid, c_vcpu, &info);
	caml_leave_blocking_section();
	if (retval < 0)
		failwith_xc(xch);

	result = caml_alloc_tuple(5);
	Store_field(result, 0, Val_bool(info.online));
	Store_field(result, 1, Val_bool(info.blocked));
	Store_field(result, 2, Val_bool(info.running));
	Store_field(result, 3, caml_copy_int64(info.cpu_time));
	Store_field(result, 4, caml_copy_int32(info.cpu));

	CAMLreturn(result);
}

CAMLprim value stub_xc_vcpu_context_get(value xch_val, value domid,
                                        value cpu)
{
	CAMLparam3(xch_val, domid, cpu);
	xc_interface *xch = xch_of_val(xch_val);
	CAMLlocal1(context);
	int ret;
	vcpu_guest_context_any_t ctxt;

	ret = xc_vcpu_getcontext(xch, Int_val(domid), Int_val(cpu), &ctxt);
	if ( ret < 0 )
		failwith_xc(xch);

	context = caml_alloc_string(sizeof(ctxt));
	memcpy((char *) String_val(context), &ctxt.c, sizeof(ctxt.c));

	CAMLreturn(context);
}

static int get_cpumap_len(xc_interface *xch, value cpumap)
{
	int ml_len = Wosize_val(cpumap);
	int xc_len = xc_get_max_cpus(xch);

	if (ml_len < xc_len)
		return ml_len;
	else
		return xc_len;
}

CAMLprim value stub_xc_vcpu_setaffinity(value xch_val, value domid,
                                        value vcpu, value cpumap)
{
	CAMLparam4(xch_val, domid, vcpu, cpumap);
	xc_interface *xch = xch_of_val(xch_val);
	int i, len = get_cpumap_len(xch, cpumap);
	xc_cpumap_t c_cpumap;
	int retval;

	c_cpumap = xc_cpumap_alloc(xch);
	if (c_cpumap == NULL)
		failwith_xc(xch);

	for (i=0; i<len; i++) {
		if (Bool_val(Field(cpumap, i)))
			c_cpumap[i/8] |= 1 << (i&7);
	}
	retval = xc_vcpu_setaffinity(xch, Int_val(domid),
				     Int_val(vcpu),
				     c_cpumap, NULL,
				     XEN_VCPUAFFINITY_HARD);
	free(c_cpumap);

	if (retval < 0)
		failwith_xc(xch);
	CAMLreturn(Val_unit);
}

CAMLprim value stub_xc_vcpu_getaffinity(value xch_val, value domid,
                                        value vcpu)
{
	CAMLparam3(xch_val, domid, vcpu);
	CAMLlocal1(ret);
	xc_interface *xch = xch_of_val(xch_val);
	xc_cpumap_t c_cpumap;
	int i, len = xc_get_max_cpus(xch);
	int retval;

	if (len < 1)
		failwith_xc(xch);

	c_cpumap = xc_cpumap_alloc(xch);
	if (c_cpumap == NULL)
		failwith_xc(xch);

	retval = xc_vcpu_getaffinity(xch, Int_val(domid),
				     Int_val(vcpu),
				     c_cpumap, NULL,
				     XEN_VCPUAFFINITY_HARD);
	if (retval < 0) {
		free(c_cpumap);
		failwith_xc(xch);
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

CAMLprim value stub_xc_sched_id(value xch_val)
{
	CAMLparam1(xch_val);
	xc_interface *xch = xch_of_val(xch_val);
	int sched_id;

	if (xc_sched_id(xch, &sched_id))
		failwith_xc(xch);

	CAMLreturn(Val_int(sched_id));
}

CAMLprim value stub_xc_evtchn_alloc_unbound(value xch_val,
                                            value local_domid,
                                            value remote_domid)
{
	CAMLparam3(xch_val, local_domid, remote_domid);
	xc_interface *xch = xch_of_val(xch_val);
	int result;

	uint32_t c_local_domid = Int_val(local_domid);
	uint32_t c_remote_domid = Int_val(remote_domid);

	caml_enter_blocking_section();
	result = xc_evtchn_alloc_unbound(xch, c_local_domid,
	                                     c_remote_domid);
	caml_leave_blocking_section();

	if (result < 0)
		failwith_xc(xch);
	CAMLreturn(Val_int(result));
}

CAMLprim value stub_xc_evtchn_reset(value xch_val, value domid)
{
	CAMLparam2(xch_val, domid);
	xc_interface *xch = xch_of_val(xch_val);
	int r;

	r = xc_evtchn_reset(xch, Int_val(domid));
	if (r < 0)
		failwith_xc(xch);
	CAMLreturn(Val_unit);
}

CAMLprim value stub_xc_evtchn_status(value xch_val, value domid, value port)
{
	CAMLparam3(xch_val, domid, port);
	CAMLlocal4(result, result_status, stat, interdomain);
	xc_interface *xch = xch_of_val(xch_val);
	xc_evtchn_status_t status = {
		.dom = Int_val(domid),
		.port = Int_val(port),
	};
	int rc;

	caml_enter_blocking_section();
	rc = xc_evtchn_status(xch, &status);
	caml_leave_blocking_section();

	if ( rc < 0 )
		failwith_xc(xch);

	switch ( status.status )
	{
	case EVTCHNSTAT_closed:
		CAMLreturn(Val_none); /* Early exit, no allocations needed */

	case EVTCHNSTAT_unbound:
		stat = caml_alloc(1, 0); /* 1st non-constant constructor */
		Store_field(stat, 0, Val_int(status.u.unbound.dom));
		break;

	case EVTCHNSTAT_interdomain:
		interdomain = caml_alloc_tuple(2);
		Store_field(interdomain, 0, Val_int(status.u.interdomain.dom));
		Store_field(interdomain, 1, Val_int(status.u.interdomain.port));
		stat = caml_alloc(1, 1); /*  2nd non-constant constructor */
		Store_field(stat, 0, interdomain);
		break;

	case EVTCHNSTAT_pirq:
		stat = caml_alloc(1, 2); /* 3rd non-constant constructor */
		Store_field(stat, 0, Val_int(status.u.pirq));
		break;

	case EVTCHNSTAT_virq:
		stat = caml_alloc(1, 3); /* 4th non-constant constructor */
		Store_field(stat, 0, Val_int(status.u.virq));
		break;

	case EVTCHNSTAT_ipi:
		stat = Val_int(0); /* 1st constant constructor */
		break;

	default:
		caml_failwith("Unknown evtchn status");
	}

	result_status = caml_alloc_tuple(2);
	Store_field(result_status, 0, Val_int(status.vcpu));
	Store_field(result_status, 1, stat);

	result = caml_alloc_small(1, Tag_some);
	Store_field(result, 0, result_status);

	CAMLreturn(result);
}

CAMLprim value stub_xc_readconsolering(value xch_val)
{
	/* Safe to use outside of blocking sections because of Ocaml GC lock. */
	static unsigned int conring_size = 16384 + 1;

	unsigned int count = conring_size, size = count, index = 0;
	char *str = NULL, *ptr;
	int ret;

	CAMLparam1(xch_val);
	CAMLlocal1(ring);
	xc_interface *xch = xch_of_val(xch_val);

	str = malloc(size);
	if (!str)
		caml_raise_out_of_memory();

	/* Hopefully our conring_size guess is sufficient */
	caml_enter_blocking_section();
	ret = xc_readconsolering(xch, str, &count, 0, 0, &index);
	caml_leave_blocking_section();

	if (ret < 0) {
		free(str);
		failwith_xc(xch);
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
		ret = xc_readconsolering(xch, str, &count, 0, 1, &index);
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
	memcpy((char *) String_val(ring), str, count);
	free(str);

	CAMLreturn(ring);
}

CAMLprim value stub_xc_send_debug_keys(value xch_val, value keys)
{
	CAMLparam2(xch_val, keys);
	xc_interface *xch = xch_of_val(xch_val);
	int r;

	r = xc_send_debug_keys(xch, String_val(keys));
	if (r)
		failwith_xc(xch);
	CAMLreturn(Val_unit);
}

CAMLprim value physinfo_arch_caps(const xc_physinfo_t *info)
{
	CAMLparam0();
	CAMLlocal2(arch_cap_flags, arch_obj);
	int tag = -1;

#if defined(__arm__) || defined(__aarch64__)

	tag = 0; /* tag ARM */

	arch_obj = caml_alloc_tuple(1);

	Store_field(arch_obj, 0,
		    Val_int(MASK_EXTR(info->arch_capabilities,
				      XEN_SYSCTL_PHYSCAP_ARM_SVE_MASK) * 128));

#elif defined(__i386__) || defined(__x86_64__)

	tag = 1; /* tag x86 */

	arch_obj = Val_emptylist;

#endif

	if ( tag < 0 )
		caml_failwith("Unhandled architecture");

	arch_cap_flags = caml_alloc_small(1, tag);
	Store_field(arch_cap_flags, 0, arch_obj);

	CAMLreturn(arch_cap_flags);
}

CAMLprim value stub_xc_physinfo(value xch_val)
{
	CAMLparam1(xch_val);
	CAMLlocal2(physinfo, cap_list);
	xc_interface *xch = xch_of_val(xch_val);
	xc_physinfo_t c_physinfo;
	int r;

	caml_enter_blocking_section();
	r = xc_physinfo(xch, &c_physinfo);
	caml_leave_blocking_section();

	if (r)
		failwith_xc(xch);

	/*
	 * capabilities: physinfo_cap_flag list;
	 */
	cap_list = c_bitmap_to_ocaml_list
		/* ! physinfo_cap_flag CAP_ lc */
		/* ! XEN_SYSCTL_PHYSCAP_ XEN_SYSCTL_PHYSCAP_MAX max */
		(c_physinfo.capabilities);

	physinfo = caml_alloc_tuple(11);
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
	Store_field(physinfo, 10, physinfo_arch_caps(&c_physinfo));

	CAMLreturn(physinfo);
}

CAMLprim value stub_xc_pcpu_info(value xch_val, value nr_cpus)
{
	CAMLparam2(xch_val, nr_cpus);
	CAMLlocal2(pcpus, v);
	xc_interface *xch = xch_of_val(xch_val);
	xc_cpuinfo_t *info;
	int r, size;

	if (Int_val(nr_cpus) < 1)
		caml_invalid_argument("nr_cpus");

	info = calloc(Int_val(nr_cpus) + 1, sizeof(*info));
	if (!info)
		caml_raise_out_of_memory();

	caml_enter_blocking_section();
	r = xc_getcpuinfo(xch, Int_val(nr_cpus), info, &size);
	caml_leave_blocking_section();

	if (r) {
		free(info);
		failwith_xc(xch);
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

CAMLprim value stub_xc_domain_setmaxmem(value xch_val, value domid,
                                        value max_memkb)
{
	CAMLparam3(xch_val, domid, max_memkb);
	xc_interface *xch = xch_of_val(xch_val);
	int retval;

	uint32_t c_domid = Int_val(domid);
	unsigned int c_max_memkb = Int64_val(max_memkb);
	caml_enter_blocking_section();
	retval = xc_domain_setmaxmem(xch, c_domid, c_max_memkb);
	caml_leave_blocking_section();
	if (retval)
		failwith_xc(xch);
	CAMLreturn(Val_unit);
}

CAMLprim value stub_xc_domain_set_memmap_limit(value xch_val, value domid,
                                               value map_limitkb)
{
	CAMLparam3(xch_val, domid, map_limitkb);
	xc_interface *xch = xch_of_val(xch_val);
	unsigned long v;
	int retval;

	v = Int64_val(map_limitkb);
	retval = xc_domain_set_memmap_limit(xch, Int_val(domid), v);
	if (retval)
		failwith_xc(xch);

	CAMLreturn(Val_unit);
}

CAMLprim value stub_xc_domain_memory_increase_reservation(value xch_val,
                                                          value domid,
                                                          value mem_kb)
{
	CAMLparam3(xch_val, domid, mem_kb);
	xc_interface *xch = xch_of_val(xch_val);
	int retval;

	unsigned long nr_extents = ((unsigned long)(Int64_val(mem_kb))) >> (XC_PAGE_SHIFT - 10);

	uint32_t c_domid = Int_val(domid);
	caml_enter_blocking_section();
	retval = xc_domain_increase_reservation_exact(xch, c_domid,
							  nr_extents, 0, 0, NULL);
	caml_leave_blocking_section();

	if (retval)
		failwith_xc(xch);
	CAMLreturn(Val_unit);
}

CAMLprim value stub_xc_version_version(value xch_val)
{
	CAMLparam1(xch_val);
	CAMLlocal1(result);
	xc_interface *xch = xch_of_val(xch_val);
	xen_extraversion_t extra;
	long packed;
	int retval;

	caml_enter_blocking_section();
	packed = xc_version(xch, XENVER_version, NULL);
	caml_leave_blocking_section();

	if (packed < 0)
		failwith_xc(xch);

	caml_enter_blocking_section();
	retval = xc_version(xch, XENVER_extraversion, &extra);
	caml_leave_blocking_section();

	if (retval)
		failwith_xc(xch);

	result = caml_alloc_tuple(3);

	Store_field(result, 0, Val_int(packed >> 16));
	Store_field(result, 1, Val_int(packed & 0xffff));
	Store_field(result, 2, caml_copy_string(extra));

	CAMLreturn(result);
}


CAMLprim value stub_xc_version_compile_info(value xch_val)
{
	CAMLparam1(xch_val);
	CAMLlocal1(result);
	xc_interface *xch = xch_of_val(xch_val);
	xen_compile_info_t ci;
	int retval;

	caml_enter_blocking_section();
	retval = xc_version(xch, XENVER_compile_info, &ci);
	caml_leave_blocking_section();

	if (retval)
		failwith_xc(xch);

	result = caml_alloc_tuple(4);

	Store_field(result, 0, caml_copy_string(ci.compiler));
	Store_field(result, 1, caml_copy_string(ci.compile_by));
	Store_field(result, 2, caml_copy_string(ci.compile_domain));
	Store_field(result, 3, caml_copy_string(ci.compile_date));

	CAMLreturn(result);
}


static value xc_version_single_string(value xch_val, int code, void *info)
{
	CAMLparam1(xch_val);
	xc_interface *xch = xch_of_val(xch_val);
	int retval;

	caml_enter_blocking_section();
	retval = xc_version(xch, code, info);
	caml_leave_blocking_section();

	if (retval)
		failwith_xc(xch);

	CAMLreturn(caml_copy_string((char *)info));
}


CAMLprim value stub_xc_version_changeset(value xch_val)
{
	xen_changeset_info_t ci;

	return xc_version_single_string(xch_val, XENVER_changeset, &ci);
}


CAMLprim value stub_xc_version_capabilities(value xch_val)
{
	xen_capabilities_info_t ci;

	return xc_version_single_string(xch_val, XENVER_capabilities, &ci);
}


CAMLprim value stub_pages_to_kib(value pages)
{
	CAMLparam1(pages);

	CAMLreturn(caml_copy_int64(Int64_val(pages) << (XC_PAGE_SHIFT - 10)));
}


CAMLprim value stub_map_foreign_range(value xch_val, value dom,
                                      value size, value mfn)
{
	CAMLparam4(xch_val, dom, size, mfn);
	CAMLlocal1(result);
	xc_interface *xch = xch_of_val(xch_val);
	struct mmap_interface *intf;
	unsigned long c_mfn = Nativeint_val(mfn);
	int len = Int_val(size);
	void *ptr;

	BUILD_BUG_ON((sizeof(struct mmap_interface) % sizeof(value)) != 0);
	result = caml_alloc(Wsize_bsize(sizeof(struct mmap_interface)),
			    Abstract_tag);

	caml_enter_blocking_section();
	ptr = xc_map_foreign_range(xch, Int_val(dom), len,
				   PROT_READ|PROT_WRITE, c_mfn);
	caml_leave_blocking_section();

	if (!ptr)
		caml_failwith("xc_map_foreign_range error");

	intf = Data_abstract_val(result);
	*intf = (struct mmap_interface){ ptr, len };

	CAMLreturn(result);
}

CAMLprim value stub_sched_credit_domain_get(value xch_val, value domid)
{
	CAMLparam2(xch_val, domid);
	CAMLlocal1(sdom);
	xc_interface *xch = xch_of_val(xch_val);
	struct xen_domctl_sched_credit c_sdom;
	int ret;

	caml_enter_blocking_section();
	ret = xc_sched_credit_domain_get(xch, Int_val(domid), &c_sdom);
	caml_leave_blocking_section();
	if (ret != 0)
		failwith_xc(xch);

	sdom = caml_alloc_tuple(2);
	Store_field(sdom, 0, Val_int(c_sdom.weight));
	Store_field(sdom, 1, Val_int(c_sdom.cap));

	CAMLreturn(sdom);
}

CAMLprim value stub_sched_credit_domain_set(value xch_val, value domid,
                                            value sdom)
{
	CAMLparam3(xch_val, domid, sdom);
	xc_interface *xch = xch_of_val(xch_val);
	struct xen_domctl_sched_credit c_sdom;
	int ret;

	c_sdom.weight = Int_val(Field(sdom, 0));
	c_sdom.cap = Int_val(Field(sdom, 1));
	caml_enter_blocking_section();
	ret = xc_sched_credit_domain_set(xch, Int_val(domid), &c_sdom);
	caml_leave_blocking_section();
	if (ret != 0)
		failwith_xc(xch);

	CAMLreturn(Val_unit);
}

CAMLprim value stub_shadow_allocation_get(value xch_val, value domid)
{
	CAMLparam2(xch_val, domid);
	CAMLlocal1(mb);
	xc_interface *xch = xch_of_val(xch_val);
	unsigned int c_mb;
	int ret;

	caml_enter_blocking_section();
	ret = xc_shadow_control(xch, Int_val(domid),
				XEN_DOMCTL_SHADOW_OP_GET_ALLOCATION,
				&c_mb, 0);
	caml_leave_blocking_section();
	if (ret != 0)
		failwith_xc(xch);

	mb = Val_int(c_mb);
	CAMLreturn(mb);
}

CAMLprim value stub_shadow_allocation_set(value xch_val, value domid,
					  value mb)
{
	CAMLparam3(xch_val, domid, mb);
	xc_interface *xch = xch_of_val(xch_val);
	unsigned int c_mb;
	int ret;

	c_mb = Int_val(mb);
	caml_enter_blocking_section();
	ret = xc_shadow_control(xch, Int_val(domid),
				XEN_DOMCTL_SHADOW_OP_SET_ALLOCATION,
				&c_mb, 0);
	caml_leave_blocking_section();
	if (ret != 0)
		failwith_xc(xch);

	CAMLreturn(Val_unit);
}

CAMLprim value stub_xc_domain_ioport_permission(value xch_val, value domid,
					       value start_port, value nr_ports,
					       value allow)
{
	CAMLparam5(xch_val, domid, start_port, nr_ports, allow);
	xc_interface *xch = xch_of_val(xch_val);
	uint32_t c_start_port, c_nr_ports;
	uint8_t c_allow;
	int ret;

	c_start_port = Int_val(start_port);
	c_nr_ports = Int_val(nr_ports);
	c_allow = Bool_val(allow);

	ret = xc_domain_ioport_permission(xch, Int_val(domid),
					 c_start_port, c_nr_ports, c_allow);
	if (ret < 0)
		failwith_xc(xch);

	CAMLreturn(Val_unit);
}

CAMLprim value stub_xc_domain_iomem_permission(value xch_val, value domid,
					       value start_pfn, value nr_pfns,
					       value allow)
{
	CAMLparam5(xch_val, domid, start_pfn, nr_pfns, allow);
	xc_interface *xch = xch_of_val(xch_val);
	unsigned long c_start_pfn, c_nr_pfns;
	uint8_t c_allow;
	int ret;

	c_start_pfn = Nativeint_val(start_pfn);
	c_nr_pfns = Nativeint_val(nr_pfns);
	c_allow = Bool_val(allow);

	ret = xc_domain_iomem_permission(xch, Int_val(domid),
					 c_start_pfn, c_nr_pfns, c_allow);
	if (ret < 0)
		failwith_xc(xch);

	CAMLreturn(Val_unit);
}

CAMLprim value stub_xc_domain_irq_permission(value xch_val, value domid,
					     value pirq, value allow)
{
	CAMLparam4(xch_val, domid, pirq, allow);
	xc_interface *xch = xch_of_val(xch_val);
	uint32_t c_pirq;
	bool c_allow;
	int ret;

	c_pirq = Int_val(pirq);
	c_allow = Bool_val(allow);

	ret = xc_domain_irq_permission(xch, Int_val(domid),
				       c_pirq, c_allow);
	if (ret < 0)
		failwith_xc(xch);

	CAMLreturn(Val_unit);
}

CAMLprim value stub_xc_hvm_param_get(value xch_val, value domid, value param)
{
	CAMLparam3(xch_val, domid, param);
	xc_interface *xch = xch_of_val(xch_val);
	uint64_t val;
	int ret;

	caml_enter_blocking_section();
	ret = xc_hvm_param_get(xch, Int_val(domid), Int_val(param), &val);
	caml_leave_blocking_section();

	if ( ret )
		failwith_xc(xch);

	CAMLreturn(caml_copy_int64(val));
}

CAMLprim value stub_xc_hvm_param_set(value xch_val, value domid, value param, value val)
{
	CAMLparam4(xch_val, domid, param, val);
	xc_interface *xch = xch_of_val(xch_val);
	uint64_t val64 = Int64_val(val);
	int ret;

	caml_enter_blocking_section();
	ret = xc_hvm_param_set(xch, Int_val(domid), Int_val(param), val64);
	caml_leave_blocking_section();

	if ( ret )
		failwith_xc(xch);

	CAMLreturn(Val_unit);
}

static uint32_t encode_sbdf(int domain, int bus, int dev, int func)
{
	return  ((uint32_t)domain & 0xffff) << 16 |
		((uint32_t)bus    &   0xff) << 8  |
		((uint32_t)dev    &   0x1f) << 3  |
		((uint32_t)func   &    0x7);
}

CAMLprim value stub_xc_domain_test_assign_device(value xch_val, value domid, value desc)
{
	CAMLparam3(xch_val, domid, desc);
	xc_interface *xch = xch_of_val(xch_val);
	int ret;
	int domain, bus, dev, func;
	uint32_t sbdf;

	domain = Int_val(Field(desc, 0));
	bus = Int_val(Field(desc, 1));
	dev = Int_val(Field(desc, 2));
	func = Int_val(Field(desc, 3));
	sbdf = encode_sbdf(domain, bus, dev, func);

	ret = xc_test_assign_device(xch, Int_val(domid), sbdf);

	CAMLreturn(Val_bool(ret == 0));
}

CAMLprim value stub_xc_domain_assign_device(value xch_val, value domid, value desc)
{
	CAMLparam3(xch_val, domid, desc);
	xc_interface *xch = xch_of_val(xch_val);
	int ret;
	int domain, bus, dev, func;
	uint32_t sbdf;

	domain = Int_val(Field(desc, 0));
	bus = Int_val(Field(desc, 1));
	dev = Int_val(Field(desc, 2));
	func = Int_val(Field(desc, 3));
	sbdf = encode_sbdf(domain, bus, dev, func);

	ret = xc_assign_device(xch, Int_val(domid), sbdf,
			       XEN_DOMCTL_DEV_RDM_RELAXED);

	if (ret < 0)
		failwith_xc(xch);
	CAMLreturn(Val_unit);
}

CAMLprim value stub_xc_domain_deassign_device(value xch_val, value domid, value desc)
{
	CAMLparam3(xch_val, domid, desc);
	xc_interface *xch = xch_of_val(xch_val);
	int ret;
	int domain, bus, dev, func;
	uint32_t sbdf;

	domain = Int_val(Field(desc, 0));
	bus = Int_val(Field(desc, 1));
	dev = Int_val(Field(desc, 2));
	func = Int_val(Field(desc, 3));
	sbdf = encode_sbdf(domain, bus, dev, func);

	ret = xc_deassign_device(xch, Int_val(domid), sbdf);

	if (ret < 0)
		failwith_xc(xch);
	CAMLreturn(Val_unit);
}

CAMLprim value stub_xc_get_cpu_featureset(value xch_val, value idx)
{
	CAMLparam2(xch_val, idx);
	CAMLlocal1(bitmap_val);
#if defined(__i386__) || defined(__x86_64__)
	xc_interface *xch = xch_of_val(xch_val);

	/* Safe, because of the global ocaml lock. */
	static uint32_t fs_len;

	if (fs_len == 0)
	{
		int ret = xc_get_cpu_featureset(xch, 0, &fs_len, NULL);

		if (ret || (fs_len == 0))
			failwith_xc(xch);
	}

	{
		/* To/from hypervisor to retrieve actual featureset */
		uint32_t fs[fs_len], len = fs_len;
		unsigned int i;

		int ret = xc_get_cpu_featureset(xch, Int_val(idx), &len, fs);

		if (ret)
			failwith_xc(xch);

		bitmap_val = caml_alloc(len, 0);

		for (i = 0; i < len; ++i)
			Store_field(bitmap_val, i, caml_copy_int64(fs[i]));
	}
#else
	caml_failwith("xc_get_cpu_featureset: not implemented");
#endif
	CAMLreturn(bitmap_val);
}

CAMLprim value stub_xc_watchdog(value xch_val, value domid, value timeout)
{
	CAMLparam3(xch_val, domid, timeout);
	xc_interface *xch = xch_of_val(xch_val);
	int ret;
	unsigned int c_timeout = Int32_val(timeout);

	ret = xc_watchdog(xch, Int_val(domid), c_timeout);
	if (ret < 0)
		failwith_xc(xch);

	CAMLreturn(Val_int(ret));
}

/*
 * Local variables:
 *  indent-tabs-mode: t
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
