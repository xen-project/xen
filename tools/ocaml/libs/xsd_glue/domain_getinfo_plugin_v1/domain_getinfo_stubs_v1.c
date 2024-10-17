/* SPDX-License-Identifier: LGPL-2.1-only WITH OCaml-LGPL-linking-exception */

#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define CAML_NAME_SPACE
#include <caml/alloc.h>
#include <caml/memory.h>
#include <caml/signals.h>
#include <caml/fail.h>
#include <caml/callback.h>
#include <caml/custom.h>

#include <xen-tools/common-macros.h>
#include <xenctrl.h>

#include "xen-caml-compat.h"

static inline xc_interface *xsd_glue_xch_of_val(value v)
{
	xc_interface *xch = *(xc_interface **)Data_custom_val(v);

	return xch;
}

static void xsd_glue_xenctrl_finalize(value v)
{
	xc_interface *xch = xsd_glue_xch_of_val(v);

	xc_interface_close(xch);
}

static struct custom_operations xsd_glue_xenctrl_ops = {
	.identifier  = "xsd_glue.domain_getinfo_v1.xenctrl",
	.finalize    = xsd_glue_xenctrl_finalize,
	.compare     = custom_compare_default,     /* Can't compare     */
	.hash        = custom_hash_default,        /* Can't hash        */
	.serialize   = custom_serialize_default,   /* Can't serialize   */
	.deserialize = custom_deserialize_default, /* Can't deserialize */
	.compare_ext = custom_compare_ext_default, /* Can't compare     */
};

static void Noreturn xsd_glue_failwith(
	xc_interface *xch, const char *func, unsigned int line)
{
	CAMLparam0();
	CAMLlocal1(msg);
	const xc_error *error = xch ? xc_get_last_error(xch) : NULL;
	char *str = NULL;

#define ERR (error && error->code != XC_ERROR_NONE)

	int ret = asprintf(&str,
			"%d: %s%s%s - called from %s:%u",
			ERR ? error->code : errno,
			ERR ? xc_error_code_to_desc(error->code) : strerror(errno),
			ERR ? ": " : "",
			ERR ? error->message : "",
			func, line);

#undef ERR

	if (!*str || (ret == -1))
		caml_raise_out_of_memory();

	msg = caml_copy_string(str);
	free(str);

	caml_raise_with_arg(*caml_named_value("xsg.error_v1"), msg);
	CAMLnoreturn;
}
#define xsd_glue_failwith(xch) xsd_glue_failwith(xch, __func__, __LINE__)

CAMLprim value stub_xsd_glue_xc_interface_open(value unit)
{
	CAMLparam1(unit);
	CAMLlocal1(result);
	xc_interface *xch;

	result = caml_alloc_custom(&xsd_glue_xenctrl_ops, sizeof(xch), 0, 1);

	caml_enter_blocking_section();
	xch = xc_interface_open(NULL, NULL, 0);
	caml_leave_blocking_section();

	if (!xch)
		xsd_glue_failwith(xch);

	*(xc_interface **)Data_custom_val(result) = xch;

	CAMLreturn(result);
}

static value xsd_glue_alloc_domaininfo(const xc_domaininfo_t *info)
{
	CAMLparam0();
	CAMLlocal1(result);

	result = caml_alloc_tuple(4);

	Store_field(result,  0, Val_int(info->domain));
	Store_field(result,  1, Val_bool(info->flags & XEN_DOMINF_dying));
	Store_field(result,  2, Val_bool(info->flags & XEN_DOMINF_shutdown));
	Store_field(result,  3, Val_int(MASK_EXTR(info->flags, XEN_DOMINF_shutdownmask)));

	CAMLreturn(result);
}

CAMLprim value stub_xsd_glue_xc_domain_getinfo(value xch_val, value domid)
{
	CAMLparam2(xch_val, domid);
	CAMLlocal1(result);
	xc_interface *xch = xsd_glue_xch_of_val(xch_val);
	xc_domaininfo_t info;
	int ret;
	int domid_c = Int_val(domid);

	caml_enter_blocking_section();
	ret = xc_domain_getinfo_single(xch, domid_c, &info);
	caml_leave_blocking_section();

	if (ret < 0)
		xsd_glue_failwith(xch);

	result = xsd_glue_alloc_domaininfo(&info);

	CAMLreturn(result);
}

CAMLprim value stub_xsd_glue_xc_domain_getinfolist(value xch_val)
{
	CAMLparam1(xch_val);
	CAMLlocal1(result);
	xc_interface *xch = xsd_glue_xch_of_val(xch_val);
	xc_domaininfo_t *info;
	int i, retval;

	/* get the minimum number of allocate byte we need and bump it up to page boundary */
	info = malloc(sizeof(xc_domaininfo_t) * DOMID_FIRST_RESERVED);
	if (!info)
		caml_raise_out_of_memory();

	caml_enter_blocking_section();
	retval = xc_domain_getinfolist(xch, 0, DOMID_FIRST_RESERVED, info);
	caml_leave_blocking_section();

	if (retval <= 0) {
		free(info);
		xsd_glue_failwith(xch);
	}

	result = caml_alloc(retval, 0);
	for (i = 0; i < retval; i++) {
		caml_modify(&Field(result, i), xsd_glue_alloc_domaininfo(info + i));
	}

	free(info);
	CAMLreturn(result);
}
