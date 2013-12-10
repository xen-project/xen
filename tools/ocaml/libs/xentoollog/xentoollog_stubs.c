/*
 * Copyright (C) 2012      Citrix Ltd.
 * Author Ian Campbell <ian.campbell@citrix.com>
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

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#define CAML_NAME_SPACE
#include <caml/alloc.h>
#include <caml/memory.h>
#include <caml/signals.h>
#include <caml/fail.h>
#include <caml/callback.h>
#include <caml/custom.h>

#include <xentoollog.h>

#include "caml_xentoollog.h"

/* The following is equal to the CAMLreturn macro, but without the return */
#define CAMLdone do{ \
caml_local_roots = caml__frame; \
}while (0)

#define XTL ((xentoollog_logger *) Xtl_val(handle))

static char * dup_String_val(value s)
{
	int len;
	char *c;
	len = caml_string_length(s);
	c = calloc(len + 1, sizeof(char));
	if (!c)
		caml_raise_out_of_memory();
	memcpy(c, String_val(s), len);
	return c;
}

#include "_xtl_levels.inc"

/* Option type support as per http://www.linux-nantes.org/~fmonnier/ocaml/ocaml-wrapping-c.php */
#define Val_none Val_int(0)
#define Some_val(v) Field(v,0)

static value Val_some(value v)
{
	CAMLparam1(v);
	CAMLlocal1(some);
	some = caml_alloc(1, 0);
	Store_field(some, 0, v);
	CAMLreturn(some);
}

static value Val_errno(int errnoval)
{
	if (errnoval == -1)
		return Val_none;
	return Val_some(Val_int(errnoval));
}

static value Val_context(const char *context)
{
	if (context == NULL)
		return Val_none;
	return Val_some(caml_copy_string(context));
}

static void stub_xtl_ocaml_vmessage(struct xentoollog_logger *logger,
	xentoollog_level level,
	int errnoval,
	const char *context,
	const char *format,
	va_list al)
{
	caml_leave_blocking_section();
	CAMLparam0();
	CAMLlocalN(args, 4);
	struct caml_xtl *xtl = (struct caml_xtl*)logger;
	value *func = caml_named_value(xtl->vmessage_cb) ;
	char *msg;

	if (func == NULL)
		caml_raise_sys_error(caml_copy_string("Unable to find callback"));
	if (vasprintf(&msg, format, al) < 0)
		caml_raise_out_of_memory();

	/* vmessage : level -> int option -> string option -> string -> unit; */
	args[0] = Val_level(level);
	args[1] = Val_errno(errnoval);
	args[2] = Val_context(context);
	args[3] = caml_copy_string(msg);

	free(msg);

	caml_callbackN(*func, 4, args);
	CAMLdone;
	caml_enter_blocking_section();
}

static void stub_xtl_ocaml_progress(struct xentoollog_logger *logger,
	const char *context,
	const char *doing_what /* no \r,\n */,
	int percent, unsigned long done, unsigned long total)
{
	caml_leave_blocking_section();
	CAMLparam0();
	CAMLlocalN(args, 5);
	struct caml_xtl *xtl = (struct caml_xtl*)logger;
	value *func = caml_named_value(xtl->progress_cb) ;

	if (func == NULL)
		caml_raise_sys_error(caml_copy_string("Unable to find callback"));

	/* progress : string option -> string -> int -> int64 -> int64 -> unit; */
	args[0] = Val_context(context);
	args[1] = caml_copy_string(doing_what);
	args[2] = Val_int(percent);
	args[3] = caml_copy_int64(done);
	args[4] = caml_copy_int64(total);

	caml_callbackN(*func, 5, args);
	CAMLdone;
	caml_enter_blocking_section();
}

static void xtl_destroy(struct xentoollog_logger *logger)
{
	struct caml_xtl *xtl = (struct caml_xtl*)logger;
	free(xtl->vmessage_cb);
	free(xtl->progress_cb);
	free(xtl);
}

void xtl_finalize(value handle)
{
	xtl_destroy(XTL);
}

static struct custom_operations xentoollogger_custom_operations = {
	"xentoollogger_custom_operations",
	xtl_finalize /* custom_finalize_default */,
	custom_compare_default,
	custom_hash_default,
	custom_serialize_default,
	custom_deserialize_default
};

/* external _create_logger: (string * string) -> handle = "stub_xtl_create_logger" */
CAMLprim value stub_xtl_create_logger(value cbs)
{
	CAMLparam1(cbs);
	CAMLlocal1(handle);
	struct caml_xtl *xtl = malloc(sizeof(*xtl));
	if (xtl == NULL)
		caml_raise_out_of_memory();

	memset(xtl, 0, sizeof(*xtl));

	xtl->vtable.vmessage = &stub_xtl_ocaml_vmessage;
	xtl->vtable.progress = &stub_xtl_ocaml_progress;
	xtl->vtable.destroy = &xtl_destroy;

	xtl->vmessage_cb = dup_String_val(Field(cbs, 0));
	xtl->progress_cb = dup_String_val(Field(cbs, 1));

	handle = caml_alloc_custom(&xentoollogger_custom_operations, sizeof(xtl), 0, 1);
	Xtl_val(handle) = xtl;

	CAMLreturn(handle);
}

/* external test: handle -> unit = "stub_xtl_test" */
CAMLprim value stub_xtl_test(value handle)
{
	unsigned long l;
	CAMLparam1(handle);
	xtl_log(XTL, XTL_DEBUG, -1, "debug", "%s -- debug", __func__);
	xtl_log(XTL, XTL_INFO, -1, "test", "%s -- test 1", __func__);
	xtl_log(XTL, XTL_INFO, ENOSYS, "test errno", "%s -- test 2", __func__);
	xtl_log(XTL, XTL_CRITICAL, -1, "critical", "%s -- critical", __func__);
	for (l = 0UL; l<=100UL; l += 10UL) {
		xtl_progress(XTL, "progress", "testing", l, 100UL);
		usleep(10000);
	}
	CAMLreturn(Val_unit);
}

