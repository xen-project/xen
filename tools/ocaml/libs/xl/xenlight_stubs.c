/*
 * Copyright (C) 2009-2011 Citrix Ltd.
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

#include <stdlib.h>

#define CAML_NAME_SPACE
#include <caml/alloc.h>
#include <caml/memory.h>
#include <caml/signals.h>
#include <caml/fail.h>
#include <caml/callback.h>
#include <caml/custom.h>

#include <sys/mman.h>
#include <stdint.h>
#include <string.h>

#include <libxl.h>
#include <libxl_utils.h>

#include <unistd.h>
#include <assert.h>

#include "caml_xentoollog.h"

/*
 * Starting with ocaml-3.09.3, CAMLreturn can only be used for ``value''
 * types. CAMLreturnT was only added in 3.09.4, so we define our own
 * version here if needed.
 */
#ifndef CAMLreturnT
#define CAMLreturnT(type, result) do { \
    type caml__temp_result = (result); \
    caml_local_roots = caml__frame; \
    return (caml__temp_result); \
} while (0)
#endif

/* The following is equal to the CAMLreturn macro, but without the return */
#define CAMLdone do{ \
caml_local_roots = caml__frame; \
}while (0)

#define Ctx_val(x)(*((libxl_ctx **) Data_custom_val(x)))
#define CTX ((libxl_ctx *) Ctx_val(ctx))

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

/* Forward reference: this is defined in the auto-generated include file below. */
static value Val_error (libxl_error error_c);

static void failwith_xl(int error, char *fname)
{
	CAMLparam0();
	CAMLlocal1(arg);
	static value *exc = NULL;

	/* First time around, lookup by name */
	if (!exc)
		exc = caml_named_value("Xenlight.Error");

	if (!exc)
		caml_invalid_argument("Exception Xenlight.Error not initialized, please link xenlight.cma");

	arg = caml_alloc(2, 0);

	Store_field(arg, 0, Val_error(error));
	Store_field(arg, 1, caml_copy_string(fname));

	caml_raise_with_arg(*exc, arg);
	CAMLreturn0;
}

CAMLprim value stub_raise_exception(value unit)
{
	CAMLparam1(unit);
	failwith_xl(ERROR_FAIL, "test exception");
	CAMLreturn(Val_unit);
}

void ctx_finalize(value ctx)
{
	libxl_ctx_free(CTX);
}

static struct custom_operations libxl_ctx_custom_operations = {
	"libxl_ctx_custom_operations",
	ctx_finalize /* custom_finalize_default */,
	custom_compare_default,
	custom_hash_default,
	custom_serialize_default,
	custom_deserialize_default
};

CAMLprim value stub_libxl_ctx_alloc(value logger)
{
	CAMLparam1(logger);
	CAMLlocal1(handle);
	libxl_ctx *ctx;
	int ret;

	ret = libxl_ctx_alloc(&ctx, LIBXL_VERSION, 0, (xentoollog_logger *) Xtl_val(logger));
	if (ret != 0) \
		failwith_xl(ERROR_FAIL, "cannot init context");

	handle = caml_alloc_custom(&libxl_ctx_custom_operations, sizeof(ctx), 0, 1);
	Ctx_val(handle) = ctx;

	CAMLreturn(handle);
}

static int list_len(value v)
{
	int len = 0;
	while ( v != Val_emptylist ) {
		len++;
		v = Field(v, 1);
	}
	return len;
}

static int libxl_key_value_list_val(libxl_key_value_list *c_val,
	value v)
{
	CAMLparam1(v);
	CAMLlocal1(elem);
	int nr, i;
	libxl_key_value_list array;

	nr = list_len(v);

	array = calloc((nr + 1) * 2, sizeof(char *));
	if (!array)
		caml_raise_out_of_memory();

	for (i=0; v != Val_emptylist; i++, v = Field(v, 1) ) {
		elem = Field(v, 0);

		array[i * 2] = dup_String_val(Field(elem, 0));
		array[i * 2 + 1] = dup_String_val(Field(elem, 1));
	}

	*c_val = array;
	CAMLreturn(0);
}

static value Val_key_value_list(libxl_key_value_list *c_val)
{
	CAMLparam0();
	CAMLlocal5(list, cons, key, val, kv);
	int i;

	list = Val_emptylist;
	for (i = libxl_string_list_length((libxl_string_list *) c_val) - 1; i >= 0; i -= 2) {
		val = caml_copy_string((*c_val)[i]);
		key = caml_copy_string((*c_val)[i - 1]);
		kv = caml_alloc_tuple(2);
		Store_field(kv, 0, key);
		Store_field(kv, 1, val);

		cons = caml_alloc(2, 0);
		Store_field(cons, 0, kv);   // head
		Store_field(cons, 1, list);   // tail
		list = cons;
	}

	CAMLreturn(list);
}

static int libxl_string_list_val(libxl_string_list *c_val, value v)
{
	CAMLparam1(v);
	int nr, i;
	libxl_string_list array;

	nr = list_len(v);

	array = calloc(nr + 1, sizeof(char *));
	if (!array)
		caml_raise_out_of_memory();

	for (i=0; v != Val_emptylist; i++, v = Field(v, 1) )
		array[i] = dup_String_val(Field(v, 0));

	*c_val = array;
	CAMLreturn(0);
}

static value Val_string_list(libxl_string_list *c_val)
{
	CAMLparam0();
	CAMLlocal3(list, cons, string);
	int i;

	list = Val_emptylist;
	for (i = libxl_string_list_length(c_val) - 1; i >= 0; i--) {
		string = caml_copy_string((*c_val)[i]);
		cons = caml_alloc(2, 0);
		Store_field(cons, 0, string);   // head
		Store_field(cons, 1, list);     // tail
		list = cons;
	}

	CAMLreturn(list);
}

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

static value Val_mac (libxl_mac *c_val)
{
	CAMLparam0();
	CAMLlocal1(v);
	int i;

	v = caml_alloc_tuple(6);

	for(i=0; i<6; i++)
		Store_field(v, i, Val_int((*c_val)[i]));

	CAMLreturn(v);
}

static int Mac_val(libxl_mac *c_val, value v)
{
	CAMLparam1(v);
	int i;

	for(i=0; i<6; i++)
		(*c_val)[i] = Int_val(Field(v, i));

	CAMLreturn(0);
}

static value Val_bitmap (libxl_bitmap *c_val)
{
	CAMLparam0();
	CAMLlocal1(v);
	int i;

	if (c_val->size == 0)
		v = Atom(0);
	else {
	    v = caml_alloc(8 * (c_val->size), 0);
	    libxl_for_each_bit(i, *c_val) {
		    if (libxl_bitmap_test(c_val, i))
			    Store_field(v, i, Val_true);
		    else
			    Store_field(v, i, Val_false);
	    }
	}
	CAMLreturn(v);
}

static int Bitmap_val(libxl_ctx *ctx, libxl_bitmap *c_val, value v)
{
	CAMLparam1(v);
	int i, len = Wosize_val(v);

	c_val->size = 0;
	if (len > 0 && libxl_bitmap_alloc(ctx, c_val, len))
		failwith_xl(ERROR_NOMEM, "cannot allocate bitmap");
	for (i=0; i<len; i++) {
		if (Int_val(Field(v, i)))
			libxl_bitmap_set(c_val, i);
		else
			libxl_bitmap_reset(c_val, i);
	}
	CAMLreturn(0);
}

static value Val_uuid (libxl_uuid *c_val)
{
	CAMLparam0();
	CAMLlocal1(v);
	uint8_t *uuid = libxl_uuid_bytearray(c_val);
	int i;

	v = caml_alloc_tuple(16);

	for(i=0; i<16; i++)
		Store_field(v, i, Val_int(uuid[i]));

	CAMLreturn(v);
}

static int Uuid_val(libxl_uuid *c_val, value v)
{
	CAMLparam1(v);
	int i;
	uint8_t *uuid = libxl_uuid_bytearray(c_val);

	for(i=0; i<16; i++)
		uuid[i] = Int_val(Field(v, i));

	CAMLreturn(0);
}

static value Val_defbool(libxl_defbool c_val)
{
	CAMLparam0();
	CAMLlocal2(v1, v2);
	bool b;

	if (libxl_defbool_is_default(c_val))
		v2 = Val_none;
	else {
		b = libxl_defbool_val(c_val);
		v1 = b ? Val_bool(true) : Val_bool(false);
		v2 = Val_some(v1);
	}
	CAMLreturn(v2);
}

static libxl_defbool Defbool_val(value v)
{
	CAMLparam1(v);
	libxl_defbool db;
	if (v == Val_none)
		libxl_defbool_unset(&db);
	else {
		bool b = Bool_val(Some_val(v));
		libxl_defbool_set(&db, b);
	}
	CAMLreturnT(libxl_defbool, db);
}

static value Val_hwcap(libxl_hwcap *c_val)
{
	CAMLparam0();
	CAMLlocal1(hwcap);
	int i;

	hwcap = caml_alloc_tuple(8);
	for (i = 0; i < 8; i++)
		Store_field(hwcap, i, caml_copy_int32((*c_val)[i]));

	CAMLreturn(hwcap);
}

static value Val_ms_vm_genid (libxl_ms_vm_genid *c_val)
{
	CAMLparam0();
	CAMLlocal1(v);
	int i;

	v = caml_alloc_tuple(LIBXL_MS_VM_GENID_LEN);

	for(i=0; i<LIBXL_MS_VM_GENID_LEN; i++)
		Store_field(v, i, Val_int(c_val->bytes[i]));

	CAMLreturn(v);
}

static int Ms_vm_genid_val(libxl_ms_vm_genid *c_val, value v)
{
	CAMLparam1(v);
	int i;

	for(i=0; i<LIBXL_MS_VM_GENID_LEN; i++)
		c_val->bytes[i] = Int_val(Field(v, i));

	CAMLreturn(0);
}

static value Val_string_option(const char *c_val)
{
	CAMLparam0();
	CAMLlocal2(tmp1, tmp2);
	if (c_val) {
		tmp1 = caml_copy_string(c_val);
		tmp2 = Val_some(tmp1);
		CAMLreturn(tmp2);
	}
	else
		CAMLreturn(Val_none);
}

static char *String_option_val(value v)
{
	CAMLparam1(v);
	char *s = NULL;
	if (v != Val_none)
		s = dup_String_val(Some_val(v));
	CAMLreturnT(char *, s);
}

#include "_libxl_types.inc"

void async_callback(libxl_ctx *ctx, int rc, void *for_callback)
{
	caml_leave_blocking_section();
	CAMLparam0();
	CAMLlocal2(error, tmp);
	static value *func = NULL;
	value *p = (value *) for_callback;

	if (func == NULL) {
		/* First time around, lookup by name */
		func = caml_named_value("libxl_async_callback");
	}

	if (rc == 0)
		error = Val_none;
	else {
		tmp = Val_error(rc);
		error = Val_some(tmp);
	}

	/* for_callback is a pointer to a "value" that was malloc'ed and
	 * registered with the OCaml GC. The value is handed back to OCaml
	 * in the following callback, after which the pointer is unregistered
	 * and freed. */
	caml_callback2(*func, error, *p);

	caml_remove_global_root(p);
	free(p);

	CAMLdone;
	caml_enter_blocking_section();
}

static libxl_asyncop_how *aohow_val(value async)
{
	CAMLparam1(async);
	libxl_asyncop_how *ao_how = NULL;
	value *p;

	if (async != Val_none) {
		/* for_callback must be a pointer to a "value" that is malloc'ed and
		 * registered with the OCaml GC. This ensures that the GC does not remove
		 * the corresponding OCaml heap blocks, and allows the GC to update the value
		 * when blocks are moved around, while libxl is free to copy the pointer if
		 * it needs to.
		 * The for_callback pointer must always be non-NULL. */
		p = malloc(sizeof(value));
		if (!p)
			failwith_xl(ERROR_NOMEM, "cannot allocate value");
		*p = Some_val(async);
		caml_register_global_root(p);
		ao_how = malloc(sizeof(*ao_how));
		ao_how->callback = async_callback;
		ao_how->u.for_callback = (void *) p;
	}

	CAMLreturnT(libxl_asyncop_how *, ao_how);
}

value stub_libxl_domain_create_new(value ctx, value domain_config, value async, value unit)
{
	CAMLparam4(ctx, async, domain_config, unit);
	int ret;
	libxl_domain_config c_dconfig;
	uint32_t c_domid;
	libxl_asyncop_how *ao_how;

	libxl_domain_config_init(&c_dconfig);
	ret = domain_config_val(CTX, &c_dconfig, domain_config);
	if (ret != 0) {
		libxl_domain_config_dispose(&c_dconfig);
		failwith_xl(ret, "domain_create_new");
	}

	ao_how = aohow_val(async);

	caml_enter_blocking_section();
	ret = libxl_domain_create_new(CTX, &c_dconfig, &c_domid, ao_how, NULL);
	caml_leave_blocking_section();

	free(ao_how);
	libxl_domain_config_dispose(&c_dconfig);

	if (ret != 0)
		failwith_xl(ret, "domain_create_new");

	CAMLreturn(Val_int(c_domid));
}

value stub_libxl_domain_create_restore(value ctx, value domain_config, value params,
	value async, value unit)
{
	CAMLparam5(ctx, domain_config, params, async, unit);
	int ret;
	libxl_domain_config c_dconfig;
	libxl_domain_restore_params c_params;
	uint32_t c_domid;
	libxl_asyncop_how *ao_how;
	int restore_fd;

	libxl_domain_config_init(&c_dconfig);
	ret = domain_config_val(CTX, &c_dconfig, domain_config);
	if (ret != 0) {
		libxl_domain_config_dispose(&c_dconfig);
		failwith_xl(ret, "domain_create_restore");
	}

	libxl_domain_restore_params_init(&c_params);
	ret = domain_restore_params_val(CTX, &c_params, Field(params, 1));
	if (ret != 0) {
		libxl_domain_restore_params_dispose(&c_params);
		failwith_xl(ret, "domain_create_restore");
	}

	ao_how = aohow_val(async);
	restore_fd = Int_val(Field(params, 0));

	caml_enter_blocking_section();
	ret = libxl_domain_create_restore(CTX, &c_dconfig, &c_domid, restore_fd,
		-1, &c_params, ao_how, NULL);
	caml_leave_blocking_section();

	free(ao_how);
	libxl_domain_config_dispose(&c_dconfig);
	libxl_domain_restore_params_dispose(&c_params);

	if (ret != 0)
		failwith_xl(ret, "domain_create_restore");

	CAMLreturn(Val_int(c_domid));
}

value stub_libxl_domain_shutdown(value ctx, value domid)
{
	CAMLparam2(ctx, domid);
	int ret;
	uint32_t c_domid = Int_val(domid);

	caml_enter_blocking_section();
	ret = libxl_domain_shutdown(CTX, c_domid);
	caml_leave_blocking_section();

	if (ret != 0)
		failwith_xl(ret, "domain_shutdown");

	CAMLreturn(Val_unit);
}

value stub_libxl_domain_reboot(value ctx, value domid)
{
	CAMLparam2(ctx, domid);
	int ret;
	uint32_t c_domid = Int_val(domid);

	caml_enter_blocking_section();
	ret = libxl_domain_reboot(CTX, c_domid);
	caml_leave_blocking_section();

	if (ret != 0)
		failwith_xl(ret, "domain_reboot");

	CAMLreturn(Val_unit);
}

value stub_libxl_domain_destroy(value ctx, value domid, value async, value unit)
{
	CAMLparam4(ctx, domid, async, unit);
	int ret;
	uint32_t c_domid = Int_val(domid);
	libxl_asyncop_how *ao_how = aohow_val(async);

	caml_enter_blocking_section();
	ret = libxl_domain_destroy(CTX, c_domid, ao_how);
	caml_leave_blocking_section();

	free(ao_how);

	if (ret != 0)
		failwith_xl(ret, "domain_destroy");

	CAMLreturn(Val_unit);
}

value stub_libxl_domain_suspend(value ctx, value domid, value fd, value async, value unit)
{
	CAMLparam5(ctx, domid, fd, async, unit);
	int ret;
	uint32_t c_domid = Int_val(domid);
	int c_fd = Int_val(fd);
	libxl_asyncop_how *ao_how = aohow_val(async);

	caml_enter_blocking_section();
	ret = libxl_domain_suspend(CTX, c_domid, c_fd, 0, ao_how);
	caml_leave_blocking_section();

	free(ao_how);

	if (ret != 0)
		failwith_xl(ret, "domain_suspend");

	CAMLreturn(Val_unit);
}

value stub_libxl_domain_pause(value ctx, value domid)
{
	CAMLparam2(ctx, domid);
	int ret;
	uint32_t c_domid = Int_val(domid);

	caml_enter_blocking_section();
	ret = libxl_domain_pause(CTX, c_domid);
	caml_leave_blocking_section();

	if (ret != 0)
		failwith_xl(ret, "domain_pause");

	CAMLreturn(Val_unit);
}

value stub_libxl_domain_unpause(value ctx, value domid)
{
	CAMLparam2(ctx, domid);
	int ret;
	uint32_t c_domid = Int_val(domid);

	caml_enter_blocking_section();
	ret = libxl_domain_unpause(CTX, c_domid);
	caml_leave_blocking_section();

	if (ret != 0)
		failwith_xl(ret, "domain_unpause");

	CAMLreturn(Val_unit);
}

#define _STRINGIFY(x) #x
#define STRINGIFY(x) _STRINGIFY(x)

#define _DEVICE_ADDREMOVE(type,fn,op)					\
value stub_xl_device_##type##_##op(value ctx, value info, value domid,	\
	value async, value unit)					\
{									\
	CAMLparam5(ctx, info, domid, async, unit);			\
	libxl_device_##type c_info;					\
	int ret, marker_var;						\
	uint32_t c_domid = Int_val(domid);				\
	libxl_asyncop_how *ao_how = aohow_val(async);			\
									\
	device_##type##_val(CTX, &c_info, info);			\
									\
	caml_enter_blocking_section();					\
	ret = libxl_##fn##_##op(CTX, c_domid, &c_info, ao_how);		\
	caml_leave_blocking_section();					\
									\
	free(ao_how);							\
	libxl_device_##type##_dispose(&c_info);				\
									\
	if (ret != 0)							\
		failwith_xl(ret, STRINGIFY(type) "_" STRINGIFY(op));	\
									\
	CAMLreturn(Val_unit);						\
}

#define DEVICE_ADDREMOVE(type) \
	_DEVICE_ADDREMOVE(type, device_##type, add) \
	_DEVICE_ADDREMOVE(type, device_##type, remove) \
	_DEVICE_ADDREMOVE(type, device_##type, destroy)

DEVICE_ADDREMOVE(disk)
DEVICE_ADDREMOVE(nic)
DEVICE_ADDREMOVE(vfb)
DEVICE_ADDREMOVE(vkb)
DEVICE_ADDREMOVE(pci)
_DEVICE_ADDREMOVE(disk, cdrom, insert)

value stub_xl_device_nic_of_devid(value ctx, value domid, value devid)
{
	CAMLparam3(ctx, domid, devid);
	CAMLlocal1(nic);
	libxl_device_nic c_nic;
	uint32_t c_domid = Int_val(domid);
	int c_devid = Int_val(devid);

	caml_enter_blocking_section();
	libxl_devid_to_device_nic(CTX, c_domid, c_devid, &c_nic);
	caml_leave_blocking_section();

	nic = Val_device_nic(&c_nic);
	libxl_device_nic_dispose(&c_nic);

	CAMLreturn(nic);
}

value stub_xl_device_nic_list(value ctx, value domid)
{
	CAMLparam2(ctx, domid);
	CAMLlocal2(list, temp);
	libxl_device_nic *c_list;
	int i, nb;
	uint32_t c_domid = Int_val(domid);

	caml_enter_blocking_section();
	c_list = libxl_device_nic_list(CTX, c_domid, &nb);
	caml_leave_blocking_section();

	if (!c_list)
		failwith_xl(ERROR_FAIL, "nic_list");

	list = temp = Val_emptylist;
	for (i = 0; i < nb; i++) {
		list = caml_alloc_small(2, Tag_cons);
		Field(list, 0) = Val_int(0);
		Field(list, 1) = temp;
		temp = list;
		Store_field(list, 0, Val_device_nic(&c_list[i]));
		libxl_device_nic_dispose(&c_list[i]);
	}
	free(c_list);

	CAMLreturn(list);
}

value stub_xl_device_disk_list(value ctx, value domid)
{
	CAMLparam2(ctx, domid);
	CAMLlocal2(list, temp);
	libxl_device_disk *c_list;
	int i, nb;
	uint32_t c_domid = Int_val(domid);

	caml_enter_blocking_section();
	c_list = libxl_device_disk_list(CTX, c_domid, &nb);
	caml_leave_blocking_section();

	if (!c_list)
		failwith_xl(ERROR_FAIL, "disk_list");

	list = temp = Val_emptylist;
	for (i = 0; i < nb; i++) {
		list = caml_alloc_small(2, Tag_cons);
		Field(list, 0) = Val_int(0);
		Field(list, 1) = temp;
		temp = list;
		Store_field(list, 0, Val_device_disk(&c_list[i]));
		libxl_device_disk_dispose(&c_list[i]);
	}
	free(c_list);

	CAMLreturn(list);
}

value stub_xl_device_disk_of_vdev(value ctx, value domid, value vdev)
{
	CAMLparam3(ctx, domid, vdev);
	CAMLlocal1(disk);
	libxl_device_disk c_disk;
	char *c_vdev;
	uint32_t c_domid = Int_val(domid);

	c_vdev = strdup(String_val(vdev));

	caml_enter_blocking_section();
	libxl_vdev_to_device_disk(CTX, c_domid, c_vdev, &c_disk);
	caml_leave_blocking_section();

	disk = Val_device_disk(&c_disk);
	libxl_device_disk_dispose(&c_disk);
	free(c_vdev);

	CAMLreturn(disk);
}

value stub_xl_device_pci_list(value ctx, value domid)
{
	CAMLparam2(ctx, domid);
	CAMLlocal2(list, temp);
	libxl_device_pci *c_list;
	int i, nb;
	uint32_t c_domid = Int_val(domid);

	caml_enter_blocking_section();
	c_list = libxl_device_pci_list(CTX, c_domid, &nb);
	caml_leave_blocking_section();

	if (!c_list)
		failwith_xl(ERROR_FAIL, "pci_list");

	list = temp = Val_emptylist;
	for (i = 0; i < nb; i++) {
		list = caml_alloc_small(2, Tag_cons);
		Field(list, 0) = Val_int(0);
		Field(list, 1) = temp;
		temp = list;
		Store_field(list, 0, Val_device_pci(&c_list[i]));
		libxl_device_pci_dispose(&c_list[i]);
	}
	free(c_list);

	CAMLreturn(list);
}

value stub_xl_device_pci_assignable_add(value ctx, value info, value rebind)
{
	CAMLparam3(ctx, info, rebind);
	libxl_device_pci c_info;
	int ret, marker_var;
	int c_rebind = (int) Bool_val(rebind);

	device_pci_val(CTX, &c_info, info);

	caml_enter_blocking_section();
	ret = libxl_device_pci_assignable_add(CTX, &c_info, c_rebind);
	caml_leave_blocking_section();

	libxl_device_pci_dispose(&c_info);

	if (ret != 0)
		failwith_xl(ret, "pci_assignable_add");

	CAMLreturn(Val_unit);
}

value stub_xl_device_pci_assignable_remove(value ctx, value info, value rebind)
{
	CAMLparam3(ctx, info, rebind);
	libxl_device_pci c_info;
	int ret, marker_var;
	int c_rebind = (int) Bool_val(rebind);

	device_pci_val(CTX, &c_info, info);

	caml_enter_blocking_section();
	ret = libxl_device_pci_assignable_remove(CTX, &c_info, c_rebind);
	caml_leave_blocking_section();

	libxl_device_pci_dispose(&c_info);

	if (ret != 0)
		failwith_xl(ret, "pci_assignable_remove");

	CAMLreturn(Val_unit);
}

value stub_xl_device_pci_assignable_list(value ctx)
{
	CAMLparam1(ctx);
	CAMLlocal2(list, temp);
	libxl_device_pci *c_list;
	int i, nb;
	uint32_t c_domid;

	caml_enter_blocking_section();
	c_list = libxl_device_pci_assignable_list(CTX, &nb);
	caml_leave_blocking_section();

	if (!c_list)
		failwith_xl(ERROR_FAIL, "pci_assignable_list");

	list = temp = Val_emptylist;
	for (i = 0; i < nb; i++) {
		list = caml_alloc_small(2, Tag_cons);
		Field(list, 0) = Val_int(0);
		Field(list, 1) = temp;
		temp = list;
		Store_field(list, 0, Val_device_pci(&c_list[i]));
		libxl_device_pci_dispose(&c_list[i]);
	}
	free(c_list);

	CAMLreturn(list);
}

value stub_xl_physinfo_get(value ctx)
{
	CAMLparam1(ctx);
	CAMLlocal1(physinfo);
	libxl_physinfo c_physinfo;
	int ret;

	caml_enter_blocking_section();
	ret = libxl_get_physinfo(CTX, &c_physinfo);
	caml_leave_blocking_section();

	if (ret != 0)
		failwith_xl(ret, "get_physinfo");

	physinfo = Val_physinfo(&c_physinfo);

	libxl_physinfo_dispose(&c_physinfo);

	CAMLreturn(physinfo);
}

value stub_xl_cputopology_get(value ctx)
{
	CAMLparam1(ctx);
	CAMLlocal3(topology, v, v0);
	libxl_cputopology *c_topology;
	int i, nr;

	caml_enter_blocking_section();
	c_topology = libxl_get_cpu_topology(CTX, &nr);
	caml_leave_blocking_section();

	if (!c_topology)
		failwith_xl(ERROR_FAIL, "get_cpu_topologyinfo");

	topology = caml_alloc_tuple(nr);
	for (i = 0; i < nr; i++) {
		if (c_topology[i].core != LIBXL_CPUTOPOLOGY_INVALID_ENTRY) {
			v0 = Val_cputopology(&c_topology[i]);
			v = Val_some(v0);
		}
		else
			v = Val_none;
		Store_field(topology, i, v);
	}

	libxl_cputopology_list_free(c_topology, nr);

	CAMLreturn(topology);
}

value stub_xl_dominfo_list(value ctx)
{
	CAMLparam1(ctx);
	CAMLlocal2(domlist, temp);
	libxl_dominfo *c_domlist;
	int i, nb;

	caml_enter_blocking_section();
	c_domlist = libxl_list_domain(CTX, &nb);
	caml_leave_blocking_section();

	if (!c_domlist)
		failwith_xl(ERROR_FAIL, "dominfo_list");

	domlist = temp = Val_emptylist;
	for (i = nb - 1; i >= 0; i--) {
		domlist = caml_alloc_small(2, Tag_cons);
		Field(domlist, 0) = Val_int(0);
		Field(domlist, 1) = temp;
		temp = domlist;

		Store_field(domlist, 0, Val_dominfo(&c_domlist[i]));
	}

	libxl_dominfo_list_free(c_domlist, nb);

	CAMLreturn(domlist);
}

value stub_xl_dominfo_get(value ctx, value domid)
{
	CAMLparam2(ctx, domid);
	CAMLlocal1(dominfo);
	libxl_dominfo c_dominfo;
	int ret;
	uint32_t c_domid = Int_val(domid);

	caml_enter_blocking_section();
	ret = libxl_domain_info(CTX, &c_dominfo, c_domid);
	caml_leave_blocking_section();

	if (ret != 0)
		failwith_xl(ERROR_FAIL, "domain_info");
	dominfo = Val_dominfo(&c_dominfo);

	CAMLreturn(dominfo);
}

value stub_xl_domain_sched_params_get(value ctx, value domid)
{
	CAMLparam2(ctx, domid);
	CAMLlocal1(scinfo);
	libxl_domain_sched_params c_scinfo;
	int ret;
	uint32_t c_domid = Int_val(domid);

	caml_enter_blocking_section();
	ret = libxl_domain_sched_params_get(CTX, c_domid, &c_scinfo);
	caml_leave_blocking_section();

	if (ret != 0)
		failwith_xl(ret, "domain_sched_params_get");

	scinfo = Val_domain_sched_params(&c_scinfo);

	libxl_domain_sched_params_dispose(&c_scinfo);

	CAMLreturn(scinfo);
}

value stub_xl_domain_sched_params_set(value ctx, value domid, value scinfo)
{
	CAMLparam3(ctx, domid, scinfo);
	libxl_domain_sched_params c_scinfo;
	int ret;
	uint32_t c_domid = Int_val(domid);

	domain_sched_params_val(CTX, &c_scinfo, scinfo);

	caml_enter_blocking_section();
	ret = libxl_domain_sched_params_set(CTX, c_domid, &c_scinfo);
	caml_leave_blocking_section();

	libxl_domain_sched_params_dispose(&c_scinfo);

	if (ret != 0)
		failwith_xl(ret, "domain_sched_params_set");

	CAMLreturn(Val_unit);
}

value stub_xl_send_trigger(value ctx, value domid, value trigger, value vcpuid)
{
	CAMLparam4(ctx, domid, trigger, vcpuid);
	int ret;
	uint32_t c_domid = Int_val(domid);
	libxl_trigger c_trigger = LIBXL_TRIGGER_UNKNOWN;
	int c_vcpuid = Int_val(vcpuid);

	trigger_val(CTX, &c_trigger, trigger);

	caml_enter_blocking_section();
	ret = libxl_send_trigger(CTX, c_domid, c_trigger, c_vcpuid);
	caml_leave_blocking_section();

	if (ret != 0)
		failwith_xl(ret, "send_trigger");

	CAMLreturn(Val_unit);
}

value stub_xl_send_sysrq(value ctx, value domid, value sysrq)
{
	CAMLparam3(ctx, domid, sysrq);
	int ret;
	uint32_t c_domid = Int_val(domid);
	int c_sysrq = Int_val(sysrq);

	caml_enter_blocking_section();
	ret = libxl_send_sysrq(CTX, c_domid, c_sysrq);
	caml_leave_blocking_section();

	if (ret != 0)
		failwith_xl(ret, "send_sysrq");

	CAMLreturn(Val_unit);
}

value stub_xl_send_debug_keys(value ctx, value keys)
{
	CAMLparam2(ctx, keys);
	int ret;
	char *c_keys;

	c_keys = dup_String_val(keys);

	caml_enter_blocking_section();
	ret = libxl_send_debug_keys(CTX, c_keys);
	caml_leave_blocking_section();

	free(c_keys);

	if (ret != 0)
		failwith_xl(ret, "send_debug_keys");

	CAMLreturn(Val_unit);
}

static struct custom_operations libxl_console_reader_custom_operations = {
	"libxl_console_reader_custom_operations",
	custom_finalize_default,
	custom_compare_default,
	custom_hash_default,
	custom_serialize_default,
	custom_deserialize_default
};

#define Console_reader_val(x)(*((libxl_xen_console_reader **) Data_custom_val(x)))

value stub_libxl_xen_console_read_start(value ctx, value clear)
{
	CAMLparam2(ctx, clear);
	CAMLlocal1(handle);
	int c_clear = Int_val(clear);
	libxl_xen_console_reader *cr;

	caml_enter_blocking_section();
	cr = libxl_xen_console_read_start(CTX, c_clear);
	caml_leave_blocking_section();

	handle = caml_alloc_custom(&libxl_console_reader_custom_operations, sizeof(cr), 0, 1);
	Console_reader_val(handle) = cr;

	CAMLreturn(handle);
}

static void raise_eof(void)
{
	static value *exc = NULL;

	/* First time around, lookup by name */
	if (!exc)
		exc = caml_named_value("Xenlight.Host.End_of_file");

	if (!exc)
		caml_invalid_argument("Exception Xenlight.Host.End_of_file not initialized, please link xenlight.cma");

	caml_raise_constant(*exc);
}

value stub_libxl_xen_console_read_line(value ctx, value reader)
{
	CAMLparam2(ctx, reader);
	CAMLlocal1(line);
	int ret;
	char *c_line;
	libxl_xen_console_reader *cr = (libxl_xen_console_reader *) Console_reader_val(reader);

	caml_enter_blocking_section();
	ret = libxl_xen_console_read_line(CTX, cr, &c_line);
	caml_leave_blocking_section();

	if (ret < 0)
		failwith_xl(ret, "xen_console_read_line");
	if (ret == 0)
		raise_eof();

	line = caml_copy_string(c_line);

	CAMLreturn(line);
}

value stub_libxl_xen_console_read_finish(value ctx, value reader)
{
	CAMLparam2(ctx, reader);
	libxl_xen_console_reader *cr = (libxl_xen_console_reader *) Console_reader_val(reader);

	caml_enter_blocking_section();
	libxl_xen_console_read_finish(CTX, cr);
	caml_leave_blocking_section();

	CAMLreturn(Val_unit);
}

/* Event handling */

short Poll_val(value event)
{
	CAMLparam1(event);
	short res = -1;

	switch (Int_val(event)) {
		case 0: res = POLLIN; break;
		case 1: res = POLLPRI; break;
		case 2: res = POLLOUT; break;
		case 3: res = POLLERR; break;
		case 4: res = POLLHUP; break;
		case 5: res = POLLNVAL; break;
	}

	CAMLreturn(res);
}

short Poll_events_val(value event_list)
{
	CAMLparam1(event_list);
	short events = 0;

	while (event_list != Val_emptylist) {
		events |= Poll_val(Field(event_list, 0));
		event_list = Field(event_list, 1);
	}

	CAMLreturn(events);
}

value Val_poll(short event)
{
	CAMLparam0();
	CAMLlocal1(res);

	switch (event) {
		case POLLIN: res = Val_int(0); break;
		case POLLPRI: res = Val_int(1); break;
		case POLLOUT: res = Val_int(2); break;
		case POLLERR: res = Val_int(3); break;
		case POLLHUP: res = Val_int(4); break;
		case POLLNVAL: res = Val_int(5); break;
		default: failwith_xl(ERROR_FAIL, "cannot convert poll event value"); break;
	}

	CAMLreturn(res);
}

value add_event(value event_list, short event)
{
	CAMLparam1(event_list);
	CAMLlocal1(new_list);

	new_list = caml_alloc(2, 0);
	Store_field(new_list, 0, Val_poll(event));
	Store_field(new_list, 1, event_list);

	CAMLreturn(new_list);
}

value Val_poll_events(short events)
{
	CAMLparam0();
	CAMLlocal1(event_list);

	event_list = Val_emptylist;
	if (events & POLLIN)
		event_list = add_event(event_list, POLLIN);
	if (events & POLLPRI)
		event_list = add_event(event_list, POLLPRI);
	if (events & POLLOUT)
		event_list = add_event(event_list, POLLOUT);
	if (events & POLLERR)
		event_list = add_event(event_list, POLLERR);
	if (events & POLLHUP)
		event_list = add_event(event_list, POLLHUP);
	if (events & POLLNVAL)
		event_list = add_event(event_list, POLLNVAL);

	CAMLreturn(event_list);
}

/* The process for dealing with the for_app_registration_  values in the
 * callbacks below (GC registrations etc) is similar to the way for_callback is
 * handled in the asynchronous operations above. */

int fd_register(void *user, int fd, void **for_app_registration_out,
                     short events, void *for_libxl)
{
	caml_leave_blocking_section();
	CAMLparam0();
	CAMLlocalN(args, 4);
	int ret = 0;
	static value *func = NULL;
	value *p = (value *) user;
	value *for_app;

	if (func == NULL) {
		/* First time around, lookup by name */
		func = caml_named_value("libxl_fd_register");
	}

	args[0] = *p;
	args[1] = Val_int(fd);
	args[2] = Val_poll_events(events);
	args[3] = (value) for_libxl;

	for_app = malloc(sizeof(value));
	if (!for_app) {
		ret = ERROR_OSEVENT_REG_FAIL;
		goto err;
	}

	*for_app = caml_callbackN_exn(*func, 4, args);
	if (Is_exception_result(*for_app)) {
		ret = ERROR_OSEVENT_REG_FAIL;
		free(for_app);
		goto err;
	}

	caml_register_global_root(for_app);
	*for_app_registration_out = for_app;

err:
	CAMLdone;
	caml_enter_blocking_section();
	return ret;
}

int fd_modify(void *user, int fd, void **for_app_registration_update,
                   short events)
{
	caml_leave_blocking_section();
	CAMLparam0();
	CAMLlocalN(args, 4);
	int ret = 0;
	static value *func = NULL;
	value *p = (value *) user;
	value *for_app = *for_app_registration_update;

	/* If for_app == NULL, then something is very wrong */
	assert(for_app);

	if (func == NULL) {
		/* First time around, lookup by name */
		func = caml_named_value("libxl_fd_modify");
	}

	args[0] = *p;
	args[1] = Val_int(fd);
	args[2] = *for_app;
	args[3] = Val_poll_events(events);

	*for_app = caml_callbackN_exn(*func, 4, args);
	if (Is_exception_result(*for_app)) {
		/* If an exception is caught, *for_app_registration_update is not
		 * changed. It remains a valid pointer to a value that is registered
		 * with the GC. */
		ret = ERROR_OSEVENT_REG_FAIL;
		goto err;
	}

	*for_app_registration_update = for_app;

err:
	CAMLdone;
	caml_enter_blocking_section();
	return ret;
}

void fd_deregister(void *user, int fd, void *for_app_registration)
{
	caml_leave_blocking_section();
	CAMLparam0();
	CAMLlocalN(args, 3);
	static value *func = NULL;
	value *p = (value *) user;
	value *for_app = for_app_registration;

	/* If for_app == NULL, then something is very wrong */
	assert(for_app);

	if (func == NULL) {
		/* First time around, lookup by name */
		func = caml_named_value("libxl_fd_deregister");
	}

	args[0] = *p;
	args[1] = Val_int(fd);
	args[2] = *for_app;

	caml_callbackN_exn(*func, 3, args);
	/* This hook does not return error codes, so the best thing we can do
	 * to avoid trouble, if we catch an exception from the app, is abort. */
	if (Is_exception_result(*for_app))
		abort();

	caml_remove_global_root(for_app);
	free(for_app);

	CAMLdone;
	caml_enter_blocking_section();
}

struct timeout_handles {
	void *for_libxl;
	value for_app;
};

int timeout_register(void *user, void **for_app_registration_out,
                          struct timeval abs, void *for_libxl)
{
	caml_leave_blocking_section();
	CAMLparam0();
	CAMLlocal2(sec, usec);
	CAMLlocalN(args, 4);
	int ret = 0;
	static value *func = NULL;
	value *p = (value *) user;
	struct timeout_handles *handles;

	if (func == NULL) {
		/* First time around, lookup by name */
		func = caml_named_value("libxl_timeout_register");
	}

	sec = caml_copy_int64(abs.tv_sec);
	usec = caml_copy_int64(abs.tv_usec);

	/* This struct of "handles" will contain "for_libxl" as well as "for_app".
	 * We'll give a pointer to the struct to the app, and get it back in
	 * occurred_timeout, where we can clean it all up. */
	handles = malloc(sizeof(*handles));
	if (!handles) {
		ret = ERROR_OSEVENT_REG_FAIL;
		goto err;
	}

	handles->for_libxl = for_libxl;

	args[0] = *p;
	args[1] = sec;
	args[2] = usec;
	args[3] = (value) handles;

	handles->for_app = caml_callbackN_exn(*func, 4, args);
	if (Is_exception_result(handles->for_app)) {
		ret = ERROR_OSEVENT_REG_FAIL;
		free(handles);
		goto err;
	}

	caml_register_global_root(&handles->for_app);
	*for_app_registration_out = handles;

err:
	CAMLdone;
	caml_enter_blocking_section();
	return ret;
}

int timeout_modify(void *user, void **for_app_registration_update,
                         struct timeval abs)
{
	caml_leave_blocking_section();
	CAMLparam0();
	CAMLlocal1(for_app_update);
	CAMLlocalN(args, 2);
	int ret = 0;
	static value *func = NULL;
	value *p = (value *) user;
	struct timeout_handles *handles = *for_app_registration_update;

	/* If for_app == NULL, then something is very wrong */
	assert(handles->for_app);

	/* Libxl currently promises that timeout_modify is only ever called with
	 * abs={0,0}, meaning "right away". We cannot deal with other values. */
	assert(abs.tv_sec == 0 && abs.tv_usec == 0);

	if (func == NULL) {
		/* First time around, lookup by name */
		func = caml_named_value("libxl_timeout_fire_now");
	}

	args[0] = *p;
	args[1] = handles->for_app;

	for_app_update = caml_callbackN_exn(*func, 2, args);
	if (Is_exception_result(for_app_update)) {
		/* If an exception is caught, *for_app_registration_update is not
		 * changed. It remains a valid pointer to a value that is registered
		 * with the GC. */
		ret = ERROR_OSEVENT_REG_FAIL;
		goto err;
	}

	handles->for_app = for_app_update;

err:
	CAMLdone;
	caml_enter_blocking_section();
	return ret;
}

void timeout_deregister(void *user, void *for_app_registration)
{
	/* This hook will never be called by libxl. */
	abort();
}

value stub_libxl_osevent_register_hooks(value ctx, value user)
{
	CAMLparam2(ctx, user);
	CAMLlocal1(result);
	libxl_osevent_hooks *hooks;
	value *p;

	hooks = malloc(sizeof(*hooks));
	if (!hooks)
		failwith_xl(ERROR_NOMEM, "cannot allocate osevent hooks");
	hooks->fd_register = fd_register;
	hooks->fd_modify = fd_modify;
	hooks->fd_deregister = fd_deregister;
	hooks->timeout_register = timeout_register;
	hooks->timeout_modify = timeout_modify;
	hooks->timeout_deregister = timeout_deregister;

	p = malloc(sizeof(value));
	if (!p)
		failwith_xl(ERROR_NOMEM, "cannot allocate value");
	*p = user;
	caml_register_global_root(p);

	caml_enter_blocking_section();
	libxl_osevent_register_hooks(CTX, hooks, (void *) p);
	caml_leave_blocking_section();

	result = caml_alloc(1, Abstract_tag);
	*((libxl_osevent_hooks **) result) = hooks;

	CAMLreturn(result);
}

value stub_libxl_osevent_occurred_fd(value ctx, value for_libxl, value fd,
	value events, value revents)
{
	CAMLparam5(ctx, for_libxl, fd, events, revents);
	int c_fd = Int_val(fd);
	short c_events = Poll_events_val(events);
	short c_revents = Poll_events_val(revents);

	caml_enter_blocking_section();
	libxl_osevent_occurred_fd(CTX, (void *) for_libxl, c_fd, c_events, c_revents);
	caml_leave_blocking_section();

	CAMLreturn(Val_unit);
}

value stub_libxl_osevent_occurred_timeout(value ctx, value handles)
{
	CAMLparam1(ctx);
	struct timeout_handles *c_handles = (struct timeout_handles *) handles;

	caml_enter_blocking_section();
	libxl_osevent_occurred_timeout(CTX, (void *) c_handles->for_libxl);
	caml_leave_blocking_section();

	caml_remove_global_root(&c_handles->for_app);
	free(c_handles);

	CAMLreturn(Val_unit);
}

struct user_with_ctx {
	libxl_ctx *ctx;
	value user;
};

void event_occurs(void *user, libxl_event *event)
{
	caml_leave_blocking_section();
	CAMLparam0();
	CAMLlocalN(args, 2);
	struct user_with_ctx *c_user = (struct user_with_ctx *) user;
	static value *func = NULL;

	if (func == NULL) {
		/* First time around, lookup by name */
		func = caml_named_value("libxl_event_occurs_callback");
	}

	args[0] = c_user->user;
	args[1] = Val_event(event);
	libxl_event_free(c_user->ctx, event);

	caml_callbackN(*func, 2, args);
	CAMLdone;
	caml_enter_blocking_section();
}

void disaster(void *user, libxl_event_type type,
                     const char *msg, int errnoval)
{
	caml_leave_blocking_section();
	CAMLparam0();
	CAMLlocalN(args, 4);
	struct user_with_ctx *c_user = (struct user_with_ctx *) user;
	static value *func = NULL;

	if (func == NULL) {
		/* First time around, lookup by name */
		func = caml_named_value("libxl_event_disaster_callback");
	}

	args[0] = c_user->user;
	args[1] = Val_event_type(type);
	args[2] = caml_copy_string(msg);
	args[3] = Val_int(errnoval);

	caml_callbackN(*func, 4, args);
	CAMLdone;
	caml_enter_blocking_section();
}

value stub_libxl_event_register_callbacks(value ctx, value user)
{
	CAMLparam2(ctx, user);
	CAMLlocal1(result);
	struct user_with_ctx *c_user = NULL;
	libxl_event_hooks *hooks;

	c_user = malloc(sizeof(*c_user));
	if (!c_user)
		failwith_xl(ERROR_NOMEM, "cannot allocate user value");
	c_user->user = user;
	c_user->ctx = CTX;
	caml_register_global_root(&c_user->user);

	hooks = malloc(sizeof(*hooks));
	if (!hooks)
		failwith_xl(ERROR_NOMEM, "cannot allocate event hooks");
	hooks->event_occurs_mask = LIBXL_EVENTMASK_ALL;
	hooks->event_occurs = event_occurs;
	hooks->disaster = disaster;

	caml_enter_blocking_section();
	libxl_event_register_callbacks(CTX, hooks, (void *) c_user);
	caml_leave_blocking_section();

	result = caml_alloc(1, Abstract_tag);
	*((libxl_event_hooks **) result) = hooks;

	CAMLreturn(result);
}

value stub_libxl_evenable_domain_death(value ctx, value domid, value user)
{
	CAMLparam3(ctx, domid, user);
	uint32_t c_domid = Int_val(domid);
	int c_user = Int_val(user);
	libxl_evgen_domain_death *evgen_out;

	caml_enter_blocking_section();
	libxl_evenable_domain_death(CTX, c_domid, c_user, &evgen_out);
	caml_leave_blocking_section();

	CAMLreturn(Val_unit);
}

/*
 * Local variables:
 *  indent-tabs-mode: t
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
