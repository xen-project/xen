/*
 * Copyright (C) 2009-2010 Citrix Ltd.
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

#include "libxl.h"

struct caml_logger {
	struct xentoollog_logger logger;
	int log_offset;
	char log_buf[2048];
};

void log_vmessage(struct xentoollog_logger *logger, xentoollog_level level,
                  int errnoval, const char *context, const char *format, va_list al)
{
	struct caml_logger *ologger = (struct caml_logger *) logger;

	ologger->log_offset += vsnprintf(ologger->log_buf + ologger->log_offset,
	                                 2048 - ologger->log_offset, format, al);
}

void log_destroy(struct xentoollog_logger *logger)
{
}

#define INIT_CTX()  \
	lg.logger.vmessage = log_vmessage; \
	lg.logger.destroy = log_destroy; \
	lg.logger.progress = NULL; \
	ret = libxl_ctx_init(&ctx, LIBXL_VERSION, (struct xentoollog_logger *) &lg); \
	if (ret != 0) \
		failwith_xl("cannot init context", &lg);

#define FREE_CTX()  \
	libxl_ctx_free(&ctx)

void failwith_xl(char *fname, struct caml_logger *lg)
{
	char *s;
	s = (lg) ? lg->log_buf : fname;
	caml_raise_with_string(*caml_named_value("xl.error"), s);
}

static int string_string_tuple_array_val (char ***c_val, value v)
{
	CAMLparam1(v);
	CAMLlocal1(a);
	int i;
	char **array;

	for (i = 0, a = Field(v, 5); a != Val_emptylist; a = Field(a, 1)) { i++; }

	array = calloc((i + 1) * 2, sizeof(char *));
	if (!array)
		return 1;
	for (i = 0, a = Field(v, 5); a != Val_emptylist; a = Field(a, 1), i++) {
		value b = Field(a, 0);
		array[i * 2] = String_val(Field(b, 0));
		array[i * 2 + 1] = String_val(Field(b, 1));
	}
	*c_val = array;
	CAMLreturn(0);
}

static int domain_create_info_val (libxl_domain_create_info *c_val, value v)
{
	CAMLparam1(v);
	CAMLlocal1(a);
	int i;

	c_val->hvm = Bool_val(Field(v, 0));
	c_val->hap = Bool_val(Field(v, 1));
	c_val->oos = Bool_val(Field(v, 2));
	c_val->ssidref = Int32_val(Field(v, 3));
	c_val->name = String_val(Field(v, 4));
	a = Field(v, 5);
	for (i = 0; i < 16; i++)
		c_val->uuid[i] = Int_val(Field(a, i));
	string_string_tuple_array_val(&(c_val->xsdata), Field(v, 6));
	string_string_tuple_array_val(&(c_val->platformdata), Field(v, 7));

	c_val->poolid = Int32_val(Field(v, 8));
	c_val->poolname = String_val(Field(v, 9));

	CAMLreturn(0);
}

static int domain_build_info_val (libxl_domain_build_info *c_val, value v)
{
	CAMLparam1(v);
	CAMLlocal1(infopriv);

	c_val->max_vcpus = Int_val(Field(v, 0));
	c_val->cur_vcpus = Int_val(Field(v, 1));
	c_val->max_memkb = Int64_val(Field(v, 2));
	c_val->target_memkb = Int64_val(Field(v, 3));
	c_val->video_memkb = Int64_val(Field(v, 4));
	c_val->shadow_memkb = Int64_val(Field(v, 5));
	c_val->kernel.path = String_val(Field(v, 6));
	c_val->hvm = Tag_val(Field(v, 7)) == 0;
	infopriv = Field(Field(v, 7), 0);
	if (c_val->hvm) {
		c_val->u.hvm.pae = Bool_val(Field(infopriv, 0));
		c_val->u.hvm.apic = Bool_val(Field(infopriv, 1));
		c_val->u.hvm.acpi = Bool_val(Field(infopriv, 2));
		c_val->u.hvm.nx = Bool_val(Field(infopriv, 3));
		c_val->u.hvm.viridian = Bool_val(Field(infopriv, 4));
		c_val->u.hvm.timeoffset = String_val(Field(infopriv, 5));
		c_val->u.hvm.timer_mode = Int_val(Field(infopriv, 6));
		c_val->u.hvm.hpet = Int_val(Field(infopriv, 7));
		c_val->u.hvm.vpt_align = Int_val(Field(infopriv, 8));
	} else {
		c_val->u.pv.slack_memkb = Int64_val(Field(infopriv, 0));
		c_val->u.pv.cmdline = String_val(Field(infopriv, 1));
		c_val->u.pv.ramdisk.path = String_val(Field(infopriv, 2));
		c_val->u.pv.features = String_val(Field(infopriv, 3));
	}

	CAMLreturn(0);
}

static int device_disk_val(libxl_device_disk *c_val, value v)
{
	CAMLparam1(v);

	c_val->backend_domid = Int_val(Field(v, 0));
	c_val->physpath = String_val(Field(v, 1));
	c_val->phystype = (Int_val(Field(v, 2))) + PHYSTYPE_QCOW;
	c_val->virtpath = String_val(Field(v, 3));
	c_val->unpluggable = Bool_val(Field(v, 4));
	c_val->readwrite = Bool_val(Field(v, 5));
	c_val->is_cdrom = Bool_val(Field(v, 6));

	CAMLreturn(0);
}

static int device_nic_val(libxl_device_nic *c_val, value v)
{
	CAMLparam1(v);
	int i;
	int ret = 0;
	c_val->backend_domid = Int_val(Field(v, 0));
	c_val->devid = Int_val(Field(v, 1));
	c_val->mtu = Int_val(Field(v, 2));
	c_val->model = String_val(Field(v, 3));

	if (Wosize_val(Field(v, 4)) != 6) {
		ret = 1;
		goto out;
	}
	for (i = 0; i < 6; i++)
		c_val->mac[i] = Int_val(Field(Field(v, 4), i));

	/* not handling c_val->ip */
	c_val->bridge = String_val(Field(v, 5));
	c_val->ifname = String_val(Field(v, 6));
	c_val->script = String_val(Field(v, 7));
	c_val->nictype = (Int_val(Field(v, 8))) + NICTYPE_IOEMU;

out:
	CAMLreturn(ret);
}

static int device_console_val(libxl_device_console *c_val, value v)
{
	CAMLparam1(v);

	c_val->backend_domid = Int_val(Field(v, 0));
	c_val->devid = Int_val(Field(v, 1));
	c_val->constype = (Int_val(Field(v, 2))) + CONSTYPE_XENCONSOLED;

	CAMLreturn(0);
}

static int device_vkb_val(libxl_device_vkb *c_val, value v)
{
	CAMLparam1(v);

	c_val->backend_domid = Int_val(Field(v, 0));
	c_val->devid = Int_val(Field(v, 1));

	CAMLreturn(0);
}

static int device_vfb_val(libxl_device_vfb *c_val, value v)
{
	CAMLparam1(v);

	c_val->backend_domid = Int_val(Field(v, 0));
	c_val->devid = Int_val(Field(v, 1));
	c_val->vnc = Bool_val(Field(v, 2));
	c_val->vnclisten = String_val(Field(v, 3));
	c_val->vncpasswd = String_val(Field(v, 4));
	c_val->vncdisplay = Int_val(Field(v, 5));
	c_val->keymap = String_val(Field(v, 6));
	c_val->sdl = Bool_val(Field(v, 7));
	c_val->opengl = Bool_val(Field(v, 8));
	c_val->display = String_val(Field(v, 9));
	c_val->xauthority = String_val(Field(v, 10));

	CAMLreturn(0);
}

static int device_pci_val(libxl_device_pci *c_val, value v)
{
	CAMLparam1(v);

	c_val->value = Int_val(Field(v, 0));
	c_val->domain = Int_val(Field(v, 1));
	c_val->vdevfn = Int_val(Field(v, 2));
	c_val->msitranslate = Bool_val(Field(v, 3));
	c_val->power_mgmt = Bool_val(Field(v, 4));

	CAMLreturn(0);
}

static int sched_credit_val(struct libxl_sched_credit *c_val, value v)
{
	CAMLparam1(v);
	c_val->weight = Int_val(Field(v, 0));
	c_val->cap = Int_val(Field(v, 1));
	CAMLreturn(0);
}

static int domain_build_state_val(libxl_domain_build_state *c_val, value v)
{
	CAMLparam1(v);

	c_val->store_port = Int_val(Field(v, 0));
	c_val->store_mfn = Int64_val(Field(v, 1));
	c_val->console_port = Int_val(Field(v, 2));
	c_val->console_mfn = Int64_val(Field(v, 3));
	
	CAMLreturn(0);
}

static value Val_sched_credit(struct libxl_sched_credit *c_val)
{
	CAMLparam0();
	CAMLlocal1(v);

	v = caml_alloc_tuple(2);

	Store_field(v, 0, Val_int(c_val->weight));
	Store_field(v, 1, Val_int(c_val->cap));

	CAMLreturn(v);
}

static value Val_domain_build_state(libxl_domain_build_state *c_val)
{
	CAMLparam0();
	CAMLlocal1(v);

	v = caml_alloc_tuple(4);

	Store_field(v, 0, Val_int(c_val->store_port));
	Store_field(v, 1, caml_copy_int64(c_val->store_mfn));
	Store_field(v, 2, Val_int(c_val->console_port));
	Store_field(v, 3, caml_copy_int64(c_val->console_mfn));

	CAMLreturn(v);
}

static value Val_physinfo(struct libxl_physinfo *c_val)
{
	CAMLparam0();
	CAMLlocal2(v, hwcap);
	int i;

	hwcap = caml_alloc_tuple(8);
	for (i = 0; i < 8; i++)
		Store_field(hwcap, i, caml_copy_int32(c_val->hw_cap[i]));

	v = caml_alloc_tuple(11);
	Store_field(v, 0, Val_int(c_val->threads_per_core));
	Store_field(v, 1, Val_int(c_val->cores_per_socket));
	Store_field(v, 2, Val_int(c_val->max_cpu_id));
	Store_field(v, 3, Val_int(c_val->nr_cpus));
	Store_field(v, 4, Val_int(c_val->cpu_khz));
	Store_field(v, 5, caml_copy_int64(c_val->total_pages));
	Store_field(v, 6, caml_copy_int64(c_val->free_pages));
	Store_field(v, 7, caml_copy_int64(c_val->scrub_pages));
	Store_field(v, 8, Val_int(c_val->nr_nodes));
	Store_field(v, 9, hwcap);
	Store_field(v, 10, caml_copy_int32(c_val->phys_cap));

	CAMLreturn(v);
}

value stub_xl_domain_make(value info)
{
	CAMLparam1(info);
	struct libxl_ctx ctx; struct caml_logger lg;
	uint32_t domid;
	libxl_domain_create_info c_info;
	int ret;

	domain_create_info_val (&c_info, info);

	INIT_CTX();

	ret = libxl_domain_make(&ctx, &c_info, &domid);
	if (ret != 0)
		failwith_xl("domain make", &lg);

	FREE_CTX();

	free(c_info.xsdata);
	free(c_info.platformdata);

	CAMLreturn(Val_int(domid));
}

value stub_xl_domain_build(value info, value domid)
{
	CAMLparam2(info, domid);
	CAMLlocal1(result);
	struct libxl_ctx ctx; struct caml_logger lg;
	libxl_domain_build_info c_info;
	libxl_domain_build_state c_state;
	int ret;
	int c_domid;

	domain_build_info_val (&c_info, info);
	c_domid = Int_val(domid);

	INIT_CTX();

	ret = libxl_domain_build(&ctx, &c_info, c_domid, &c_state);
	if (ret != 0)
		failwith_xl("domain_build", &lg);

	result = Val_domain_build_state(&c_state);
	FREE_CTX();

	CAMLreturn(result);
}

value stub_xl_disk_add(value info, value domid)
{
	CAMLparam2(info, domid);
	libxl_device_disk c_info;
	struct libxl_ctx ctx; struct caml_logger lg;
	int ret;

	device_disk_val(&c_info, info);
	c_info.domid = Int_val(domid);

	INIT_CTX();
	ret = libxl_device_disk_add(&ctx, Int_val(domid), &c_info);
	if (ret != 0)
		failwith_xl("disk_add", &lg);
	FREE_CTX();
	CAMLreturn(Val_unit);
}

value stub_xl_disk_remove(value info, value domid)
{
	CAMLparam2(info, domid);
	libxl_device_disk c_info;
	struct libxl_ctx ctx; struct caml_logger lg;
	int ret;

	device_disk_val(&c_info, info);
	c_info.domid = Int_val(domid);

	INIT_CTX();
	ret = libxl_device_disk_del(&ctx, &c_info, 0);
	if (ret != 0)
		failwith_xl("disk_remove", &lg);
	FREE_CTX();
	CAMLreturn(Val_unit);
}

value stub_xl_nic_add(value info, value domid)
{
	CAMLparam2(info, domid);
	struct libxl_ctx ctx; struct caml_logger lg;
	libxl_device_nic c_info;
	int ret;

	device_nic_val(&c_info, info);
	c_info.domid = Int_val(domid);

	INIT_CTX();
	ret = libxl_device_nic_add(&ctx, Int_val(domid), &c_info);
	if (ret != 0)
		failwith_xl("nic_add", &lg);
	FREE_CTX();
	CAMLreturn(Val_unit);
}

value stub_xl_nic_remove(value info, value domid)
{
	CAMLparam2(info, domid);
	struct libxl_ctx ctx; struct caml_logger lg;
	libxl_device_nic c_info;
	int ret;

	device_nic_val(&c_info, info);
	c_info.domid = Int_val(domid);

	INIT_CTX();
	ret = libxl_device_nic_del(&ctx, &c_info, 0);
	if (ret != 0)
		failwith_xl("nic_remove", &lg);
	FREE_CTX();
	CAMLreturn(Val_unit);
}

value stub_xl_console_add(value info, value state, value domid)
{
	CAMLparam3(info, state, domid);
	struct libxl_ctx ctx; struct caml_logger lg;
	libxl_device_console c_info;
	libxl_domain_build_state c_state;
	int ret;

	device_console_val(&c_info, info);
	domain_build_state_val(&c_state, state);
	c_info.domid = Int_val(domid);
	c_info.build_state = &c_state;

	INIT_CTX();
	ret = libxl_device_console_add(&ctx, Int_val(domid), &c_info);
	if (ret != 0)
		failwith_xl("console_add", &lg);
	FREE_CTX();
	CAMLreturn(Val_unit);
}

value stub_xl_vkb_add(value info, value domid)
{
	CAMLparam2(info, domid);
	struct libxl_ctx ctx; struct caml_logger lg;
	libxl_device_vkb c_info;
	int ret;

	device_vkb_val(&c_info, info);
	c_info.domid = Int_val(domid);

	INIT_CTX();
	ret = libxl_device_vkb_add(&ctx, Int_val(domid), &c_info);
	if (ret != 0)
		failwith_xl("vkb_add", &lg);
	FREE_CTX();
	
	CAMLreturn(Val_unit);
}

value stub_xl_vkb_clean_shutdown(value domid)
{
	CAMLparam1(domid);
	struct libxl_ctx ctx; struct caml_logger lg;
	int ret;

	INIT_CTX();
	ret = libxl_device_vkb_clean_shutdown(&ctx, Int_val(domid));
	if (ret != 0)
		failwith_xl("vkb_clean_shutdown", &lg);
	FREE_CTX();
	
	CAMLreturn(Val_unit);
}

value stub_xl_vkb_hard_shutdown(value domid)
{
	CAMLparam1(domid);
	struct libxl_ctx ctx; struct caml_logger lg;
	int ret;

	INIT_CTX();
	ret = libxl_device_vkb_hard_shutdown(&ctx, Int_val(domid));
	if (ret != 0)
		failwith_xl("vkb_hard_shutdown", &lg);
	FREE_CTX();
	
	CAMLreturn(Val_unit);
}

value stub_xl_vfb_add(value info, value domid)
{
	CAMLparam2(info, domid);
	struct libxl_ctx ctx; struct caml_logger lg;
	libxl_device_vfb c_info;
	int ret;

	device_vfb_val(&c_info, info);
	c_info.domid = Int_val(domid);

	INIT_CTX();
	ret = libxl_device_vfb_add(&ctx, Int_val(domid), &c_info);
	if (ret != 0)
		failwith_xl("vfb_add", &lg);
	FREE_CTX();
	
	CAMLreturn(Val_unit);
}

value stub_xl_vfb_clean_shutdown(value domid)
{
	CAMLparam1(domid);
	struct libxl_ctx ctx; struct caml_logger lg;
	int ret;

	INIT_CTX();
	ret = libxl_device_vfb_clean_shutdown(&ctx, Int_val(domid));
	if (ret != 0)
		failwith_xl("vfb_clean_shutdown", &lg);
	FREE_CTX();
	
	CAMLreturn(Val_unit);
}

value stub_xl_vfb_hard_shutdown(value domid)
{
	CAMLparam1(domid);
	struct libxl_ctx ctx; struct caml_logger lg;
	int ret;

	INIT_CTX();
	ret = libxl_device_vfb_hard_shutdown(&ctx, Int_val(domid));
	if (ret != 0)
		failwith_xl("vfb_hard_shutdown", &lg);
	FREE_CTX();
	
	CAMLreturn(Val_unit);
}

value stub_xl_pci_add(value info, value domid)
{
	CAMLparam2(info, domid);
	struct libxl_ctx ctx; struct caml_logger lg;
	libxl_device_pci c_info;
	int ret;

	device_pci_val(&c_info, info);

	INIT_CTX();
	ret = libxl_device_pci_add(&ctx, Int_val(domid), &c_info);
	if (ret != 0)
		failwith_xl("pci_add", &lg);
	FREE_CTX();
	
	CAMLreturn(Val_unit);
}

value stub_xl_pci_remove(value info, value domid)
{
	CAMLparam2(info, domid);
	struct libxl_ctx ctx; struct caml_logger lg;
	libxl_device_pci c_info;
	int ret;

	device_pci_val(&c_info, info);

	INIT_CTX();
	ret = libxl_device_pci_remove(&ctx, Int_val(domid), &c_info);
	if (ret != 0)
		failwith_xl("pci_remove", &lg);
	FREE_CTX();
	
	CAMLreturn(Val_unit);
}

value stub_xl_pci_shutdown(value domid)
{
	CAMLparam1(domid);
	struct libxl_ctx ctx; struct caml_logger lg;
	int ret;

	INIT_CTX();
	ret = libxl_device_pci_shutdown(&ctx, Int_val(domid));
	if (ret != 0)
		failwith_xl("pci_shutdown", &lg);
	FREE_CTX();
	
	CAMLreturn(Val_unit);
}

value stub_xl_button_press(value domid, value button)
{
	CAMLparam2(domid, button);
	struct libxl_ctx ctx; struct caml_logger lg;
	int ret;
	
	INIT_CTX();
	ret = libxl_button_press(&ctx, Int_val(domid), Int_val(button) + POWER_BUTTON);
	if (ret != 0)
		failwith_xl("button_press", &lg);
	FREE_CTX();

	CAMLreturn(Val_unit);
}

value stub_xl_physinfo(value unit)
{
	CAMLparam1(unit);
	CAMLlocal1(physinfo);
	struct libxl_ctx ctx; struct caml_logger lg;
	struct libxl_physinfo c_physinfo;
	int ret;

	INIT_CTX();
	ret = libxl_get_physinfo(&ctx, &c_physinfo);
	if (ret != 0)
		failwith_xl("physinfo", &lg);
	FREE_CTX();
	
	physinfo = Val_physinfo(&c_physinfo);
	CAMLreturn(physinfo);
}

value stub_xl_sched_credit_domain_get(value domid)
{
	CAMLparam1(domid);
	CAMLlocal1(scinfo);
	struct libxl_ctx ctx; struct caml_logger lg;
	struct libxl_sched_credit c_scinfo;
	int ret;

	INIT_CTX();
	ret = libxl_sched_credit_domain_get(&ctx, Int_val(domid), &c_scinfo);
	if (ret != 0)
		failwith_xl("sched_credit_domain_get", &lg);
	FREE_CTX();
	
	scinfo = Val_sched_credit(&c_scinfo);
	CAMLreturn(scinfo);
}

value stub_xl_sched_credit_domain_set(value domid, value scinfo)
{
	CAMLparam2(domid, scinfo);
	struct libxl_ctx ctx; struct caml_logger lg;
	struct libxl_sched_credit c_scinfo;
	int ret;

	sched_credit_val(&c_scinfo, scinfo);

	INIT_CTX();
	ret = libxl_sched_credit_domain_set(&ctx, Int_val(domid), &c_scinfo);
	if (ret != 0)
		failwith_xl("sched_credit_domain_set", &lg);
	FREE_CTX();
	
	CAMLreturn(Val_unit);
}

value stub_xl_send_trigger(value domid, value trigger, value vcpuid)
{
	CAMLparam3(domid, trigger, vcpuid);
	struct libxl_ctx ctx; struct caml_logger lg;
	int ret;

	INIT_CTX();
	ret = libxl_send_trigger(&ctx, Int_val(domid), String_val(trigger), Int_val(vcpuid));
	if (ret != 0)
		failwith_xl("send_trigger", &lg);
	FREE_CTX();
	CAMLreturn(Val_unit);
}

value stub_xl_send_sysrq(value domid, value sysrq)
{
	CAMLparam2(domid, sysrq);
	struct libxl_ctx ctx; struct caml_logger lg;
	int ret;

	INIT_CTX();
	ret = libxl_send_sysrq(&ctx, Int_val(domid), Int_val(sysrq));
	if (ret != 0)
		failwith_xl("send_sysrq", &lg);
	FREE_CTX();
	CAMLreturn(Val_unit);
}

value stub_xl_send_debug_keys(value keys)
{
	CAMLparam1(keys);
	struct libxl_ctx ctx; struct caml_logger lg;
	int ret;

	INIT_CTX();
	ret = libxl_send_debug_keys(&ctx, String_val(keys));
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
