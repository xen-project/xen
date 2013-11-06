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

#include <sys/mman.h>
#include <stdint.h>
#include <string.h>

#include <libxl.h>
#include <libxl_utils.h>

struct caml_logger {
	struct xentoollog_logger logger;
	int log_offset;
	char log_buf[2048];
};

typedef struct caml_gc {
	int offset;
	void *ptrs[64];
} caml_gc;

static void log_vmessage(struct xentoollog_logger *logger, xentoollog_level level,
                  int errnoval, const char *context, const char *format, va_list al)
{
	struct caml_logger *ologger = (struct caml_logger *) logger;

	ologger->log_offset += vsnprintf(ologger->log_buf + ologger->log_offset,
	                                 2048 - ologger->log_offset, format, al);
}

static void log_destroy(struct xentoollog_logger *logger)
{
}

#define INIT_STRUCT() libxl_ctx *ctx; struct caml_logger lg; struct caml_gc gc; gc.offset = 0;

#define INIT_CTX()  \
	lg.logger.vmessage = log_vmessage; \
	lg.logger.destroy = log_destroy; \
	lg.logger.progress = NULL; \
	caml_enter_blocking_section(); \
	ret = libxl_ctx_alloc(&ctx, LIBXL_VERSION, 0, (struct xentoollog_logger *) &lg); \
	if (ret != 0) \
		failwith_xl("cannot init context", &lg);

#define FREE_CTX()  \
	gc_free(&gc); \
	caml_leave_blocking_section(); \
	libxl_ctx_free(ctx)

static char * dup_String_val(caml_gc *gc, value s)
{
	int len;
	char *c;
	len = caml_string_length(s);
	c = calloc(len + 1, sizeof(char));
	if (!c)
		caml_raise_out_of_memory();
	gc->ptrs[gc->offset++] = c;
	memcpy(c, String_val(s), len);
	return c;
}

static void gc_free(caml_gc *gc)
{
	int i;
	for (i = 0; i < gc->offset; i++) {
		free(gc->ptrs[i]);
	}
}

static void failwith_xl(char *fname, struct caml_logger *lg)
{
	char *s;
	s = (lg) ? lg->log_buf : fname;
	caml_raise_with_string(*caml_named_value("xl.error"), s);
}

static void * gc_calloc(caml_gc *gc, size_t nmemb, size_t size)
{
	void *ptr;
	ptr = calloc(nmemb, size);
	if (!ptr)
		caml_raise_out_of_memory();
	gc->ptrs[gc->offset++] = ptr;
	return ptr;
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

static int libxl_key_value_list_val(caml_gc *gc, struct caml_logger *lg,
				    libxl_key_value_list *c_val,
				    value v)
{
	CAMLparam1(v);
	CAMLlocal1(elem);
	int nr, i;
	libxl_key_value_list array;

	nr = list_len(v);

	array = gc_calloc(gc, (nr + 1) * 2, sizeof(char *));
	if (!array)
		caml_raise_out_of_memory();

	for (i=0; v != Val_emptylist; i++, v = Field(v, 1) ) {
		elem = Field(v, 0);

		array[i * 2] = dup_String_val(gc, Field(elem, 0));
		array[i * 2 + 1] = dup_String_val(gc, Field(elem, 1));
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
		val = caml_copy_string((char *) c_val[i]);
		key = caml_copy_string((char *) c_val[i - 1]);
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

static int libxl_string_list_val(caml_gc *gc, struct caml_logger *lg,
				 libxl_string_list *c_val,
				 value v)
{
	CAMLparam1(v);
	int nr, i;
	libxl_string_list array;

	nr = list_len(v);

	array = gc_calloc(gc, (nr + 1), sizeof(char *));
	if (!array)
		caml_raise_out_of_memory();

	for (i=0; v != Val_emptylist; i++, v = Field(v, 1) )
		array[i] = dup_String_val(gc, Field(v, 0));

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
		string = caml_copy_string((char *) c_val[i]);
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

static int Mac_val(caml_gc *gc, struct caml_logger *lg, libxl_mac *c_val, value v)
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

static int Bitmap_val(caml_gc *gc, struct caml_logger *lg,
		      libxl_bitmap *c_val, value v)
{
	abort(); /* XXX */
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

static int Uuid_val(caml_gc *gc, struct caml_logger *lg, libxl_uuid *c_val, value v)
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
	CAMLlocal1(v);

	if (libxl_defbool_is_default(c_val))
		v = Val_none;
	else {
		bool b = libxl_defbool_val(c_val);
		v = Val_some(b ? Val_bool(true) : Val_bool(false));
	}
	CAMLreturn(v);
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
	return db;
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

#include "_libxl_types.inc"

value stub_xl_device_disk_add(value info, value domid)
{
	CAMLparam2(info, domid);
	libxl_device_disk c_info;
	int ret;
	INIT_STRUCT();

	device_disk_val(&gc, &lg, &c_info, info);

	INIT_CTX();
	ret = libxl_device_disk_add(ctx, Int_val(domid), &c_info, 0);
	if (ret != 0)
		failwith_xl("disk_add", &lg);
	FREE_CTX();
	CAMLreturn(Val_unit);
}

value stub_xl_device_disk_del(value info, value domid)
{
	CAMLparam2(info, domid);
	libxl_device_disk c_info;
	int ret;
	INIT_STRUCT();

	device_disk_val(&gc, &lg, &c_info, info);

	INIT_CTX();
	ret = libxl_device_disk_remove(ctx, Int_val(domid), &c_info, 0);
	if (ret != 0)
		failwith_xl("disk_del", &lg);
	FREE_CTX();
	CAMLreturn(Val_unit);
}

value stub_xl_device_nic_add(value info, value domid)
{
	CAMLparam2(info, domid);
	libxl_device_nic c_info;
	int ret;
	INIT_STRUCT();

	device_nic_val(&gc, &lg, &c_info, info);

	INIT_CTX();
	ret = libxl_device_nic_add(ctx, Int_val(domid), &c_info, 0);
	if (ret != 0)
		failwith_xl("nic_add", &lg);
	FREE_CTX();
	CAMLreturn(Val_unit);
}

value stub_xl_device_nic_del(value info, value domid)
{
	CAMLparam2(info, domid);
	libxl_device_nic c_info;
	int ret;
	INIT_STRUCT();

	device_nic_val(&gc, &lg, &c_info, info);

	INIT_CTX();
	ret = libxl_device_nic_remove(ctx, Int_val(domid), &c_info, 0);
	if (ret != 0)
		failwith_xl("nic_del", &lg);
	FREE_CTX();
	CAMLreturn(Val_unit);
}

value stub_xl_device_vkb_add(value info, value domid)
{
	CAMLparam2(info, domid);
	libxl_device_vkb c_info;
	int ret;
	INIT_STRUCT();

	device_vkb_val(&gc, &lg, &c_info, info);

	INIT_CTX();
	ret = libxl_device_vkb_add(ctx, Int_val(domid), &c_info, 0);
	if (ret != 0)
		failwith_xl("vkb_add", &lg);
	FREE_CTX();

	CAMLreturn(Val_unit);
}

value stub_xl_device_vkb_remove(value info, value domid)
{
	CAMLparam1(domid);
	libxl_device_vkb c_info;
	int ret;
	INIT_STRUCT();

	device_vkb_val(&gc, &lg, &c_info, info);

	INIT_CTX();
	ret = libxl_device_vkb_remove(ctx, Int_val(domid), &c_info, 0);
	if (ret != 0)
		failwith_xl("vkb_clean_shutdown", &lg);
	FREE_CTX();

	CAMLreturn(Val_unit);
}

value stub_xl_device_vkb_destroy(value info, value domid)
{
	CAMLparam1(domid);
	libxl_device_vkb c_info;
	int ret;
	INIT_STRUCT();

	device_vkb_val(&gc, &lg, &c_info, info);

	INIT_CTX();
	ret = libxl_device_vkb_destroy(ctx, Int_val(domid), &c_info, 0);
	if (ret != 0)
		failwith_xl("vkb_hard_shutdown", &lg);
	FREE_CTX();

	CAMLreturn(Val_unit);
}

value stub_xl_device_vfb_add(value info, value domid)
{
	CAMLparam2(info, domid);
	libxl_device_vfb c_info;
	int ret;
	INIT_STRUCT();

	device_vfb_val(&gc, &lg, &c_info, info);

	INIT_CTX();
	ret = libxl_device_vfb_add(ctx, Int_val(domid), &c_info, 0);
	if (ret != 0)
		failwith_xl("vfb_add", &lg);
	FREE_CTX();

	CAMLreturn(Val_unit);
}

value stub_xl_device_vfb_remove(value info, value domid)
{
	CAMLparam1(domid);
	libxl_device_vfb c_info;
	int ret;
	INIT_STRUCT();

	device_vfb_val(&gc, &lg, &c_info, info);

	INIT_CTX();
	ret = libxl_device_vfb_remove(ctx, Int_val(domid), &c_info, 0);
	if (ret != 0)
		failwith_xl("vfb_clean_shutdown", &lg);
	FREE_CTX();

	CAMLreturn(Val_unit);
}

value stub_xl_device_vfb_destroy(value info, value domid)
{
	CAMLparam1(domid);
	libxl_device_vfb c_info;
	int ret;
	INIT_STRUCT();

	device_vfb_val(&gc, &lg, &c_info, info);

	INIT_CTX();
	ret = libxl_device_vfb_destroy(ctx, Int_val(domid), &c_info, 0);
	if (ret != 0)
		failwith_xl("vfb_hard_shutdown", &lg);
	FREE_CTX();

	CAMLreturn(Val_unit);
}

value stub_xl_device_pci_add(value info, value domid)
{
	CAMLparam2(info, domid);
	libxl_device_pci c_info;
	int ret;
	INIT_STRUCT();

	device_pci_val(&gc, &lg, &c_info, info);

	INIT_CTX();
	ret = libxl_device_pci_add(ctx, Int_val(domid), &c_info, 0);
	if (ret != 0)
		failwith_xl("pci_add", &lg);
	FREE_CTX();

	CAMLreturn(Val_unit);
}

value stub_xl_device_pci_remove(value info, value domid)
{
	CAMLparam2(info, domid);
	libxl_device_pci c_info;
	int ret;
	INIT_STRUCT();

	device_pci_val(&gc, &lg, &c_info, info);

	INIT_CTX();
	ret = libxl_device_pci_remove(ctx, Int_val(domid), &c_info, 0);
	if (ret != 0)
		failwith_xl("pci_remove", &lg);
	FREE_CTX();

	CAMLreturn(Val_unit);
}

value stub_xl_physinfo_get(value unit)
{
	CAMLparam1(unit);
	CAMLlocal1(physinfo);
	libxl_physinfo c_physinfo;
	int ret;
	INIT_STRUCT();

	INIT_CTX();
	ret = libxl_get_physinfo(ctx, &c_physinfo);
	if (ret != 0)
		failwith_xl("physinfo", &lg);
	FREE_CTX();

	physinfo = Val_physinfo(&gc, &lg, &c_physinfo);
	CAMLreturn(physinfo);
}

value stub_xl_cputopology_get(value unit)
{
	CAMLparam1(unit);
	CAMLlocal2(topology, v);
	libxl_cputopology *c_topology;
	int i, nr, ret;
	INIT_STRUCT();

	INIT_CTX();

	c_topology = libxl_get_cpu_topology(ctx, &nr);
	if (ret != 0)
		failwith_xl("topologyinfo", &lg);

	topology = caml_alloc_tuple(nr);
	for (i = 0; i < nr; i++) {
		if (c_topology[i].core != LIBXL_CPUTOPOLOGY_INVALID_ENTRY)
			v = Val_some(Val_cputopology(&gc, &lg, &c_topology[i]));
		else
			v = Val_none;
		Store_field(topology, i, v);
	}

	libxl_cputopology_list_free(c_topology, nr);

	FREE_CTX();
	CAMLreturn(topology);
}

value stub_xl_domain_sched_params_get(value domid)
{
	CAMLparam1(domid);
	CAMLlocal1(scinfo);
	libxl_domain_sched_params c_scinfo;
	int ret;
	INIT_STRUCT();

	INIT_CTX();
	ret = libxl_domain_sched_params_get(ctx, Int_val(domid), &c_scinfo);
	if (ret != 0)
		failwith_xl("domain_sched_params_get", &lg);
	FREE_CTX();

	scinfo = Val_domain_sched_params(&gc, &lg, &c_scinfo);
	CAMLreturn(scinfo);
}

value stub_xl_domain_sched_params_set(value domid, value scinfo)
{
	CAMLparam2(domid, scinfo);
	libxl_domain_sched_params c_scinfo;
	int ret;
	INIT_STRUCT();

	domain_sched_params_val(&gc, &lg, &c_scinfo, scinfo);

	INIT_CTX();
	ret = libxl_domain_sched_params_set(ctx, Int_val(domid), &c_scinfo);
	if (ret != 0)
		failwith_xl("domain_sched_params_set", &lg);
	FREE_CTX();

	CAMLreturn(Val_unit);
}

value stub_xl_send_trigger(value domid, value trigger, value vcpuid)
{
	CAMLparam3(domid, trigger, vcpuid);
	int ret;
	libxl_trigger c_trigger = LIBXL_TRIGGER_UNKNOWN;
	INIT_STRUCT();

	trigger_val(&gc, &lg, &c_trigger, trigger);

	INIT_CTX();
	ret = libxl_send_trigger(ctx, Int_val(domid), c_trigger, Int_val(vcpuid));
	if (ret != 0)
		failwith_xl("send_trigger", &lg);
	FREE_CTX();
	CAMLreturn(Val_unit);
}

value stub_xl_send_sysrq(value domid, value sysrq)
{
	CAMLparam2(domid, sysrq);
	int ret;
	INIT_STRUCT();

	INIT_CTX();
	ret = libxl_send_sysrq(ctx, Int_val(domid), Int_val(sysrq));
	if (ret != 0)
		failwith_xl("send_sysrq", &lg);
	FREE_CTX();
	CAMLreturn(Val_unit);
}

value stub_xl_send_debug_keys(value keys)
{
	CAMLparam1(keys);
	int ret;
	char *c_keys;
	INIT_STRUCT();

	c_keys = dup_String_val(&gc, keys);

	INIT_CTX();
	ret = libxl_send_debug_keys(ctx, c_keys);
	if (ret != 0)
		failwith_xl("send_debug_keys", &lg);
	FREE_CTX();
	CAMLreturn(Val_unit);
}

/*
 * Local variables:
 *  indent-tabs-mode: t
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
