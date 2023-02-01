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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <xen/xen.h>
#include <xenevtchn.h>

#define CAML_NAME_SPACE
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/custom.h>
#include <caml/callback.h>
#include <caml/fail.h>
#include <caml/signals.h>

static inline xenevtchn_handle *xce_of_val(value v)
{
	return *(xenevtchn_handle **)Data_custom_val(v);
}

static void stub_evtchn_finalize(value v)
{
	xenevtchn_close(xce_of_val(v));
}

static struct custom_operations xenevtchn_ops = {
	.identifier  = "xenevtchn",
	.finalize    = stub_evtchn_finalize,
	.compare     = custom_compare_default,     /* Can't compare     */
	.hash        = custom_hash_default,        /* Can't hash        */
	.serialize   = custom_serialize_default,   /* Can't serialize   */
	.deserialize = custom_deserialize_default, /* Can't deserialize */
	.compare_ext = custom_compare_ext_default, /* Can't compare     */
};

CAMLprim value stub_eventchn_init(value cloexec)
{
	CAMLparam1(cloexec);
	CAMLlocal1(result);
	xenevtchn_handle *xce;
	unsigned int flags = 0;

	if ( !Bool_val(cloexec) )
		flags |= XENEVTCHN_NO_CLOEXEC;

	result = caml_alloc_custom(&xenevtchn_ops, sizeof(xce), 0, 1);

	caml_enter_blocking_section();
	xce = xenevtchn_open(NULL, flags);
	caml_leave_blocking_section();

	if (xce == NULL)
		caml_failwith("open failed");

	*(xenevtchn_handle **)Data_custom_val(result) = xce;

	CAMLreturn(result);
}

CAMLprim value stub_eventchn_fdopen(value fdval)
{
	CAMLparam1(fdval);
	CAMLlocal1(result);
	xenevtchn_handle *xce;

	result = caml_alloc_custom(&xenevtchn_ops, sizeof(xce), 0, 1);

	caml_enter_blocking_section();
	xce = xenevtchn_fdopen(NULL, Int_val(fdval), 0);
	caml_leave_blocking_section();

	if (xce == NULL)
		caml_failwith("evtchn fdopen failed");

	*(xenevtchn_handle **)Data_custom_val(result) = xce;

	CAMLreturn(result);
}

CAMLprim value stub_eventchn_fd(value xce_val)
{
	CAMLparam1(xce_val);
	xenevtchn_handle *xce = xce_of_val(xce_val);
	int fd;

	/* Don't drop the GC lock.  This is a simple read out of memory */
	fd = xenevtchn_fd(xce);
	if (fd == -1)
		caml_failwith("evtchn fd failed");

	CAMLreturn(Val_int(fd));
}

CAMLprim value stub_eventchn_notify(value xce_val, value port)
{
	CAMLparam2(xce_val, port);
	xenevtchn_handle *xce = xce_of_val(xce_val);
	int rc;

	caml_enter_blocking_section();
	rc = xenevtchn_notify(xce, Int_val(port));
	caml_leave_blocking_section();

	if (rc == -1)
		caml_failwith("evtchn notify failed");

	CAMLreturn(Val_unit);
}

CAMLprim value stub_eventchn_bind_interdomain(value xce_val, value domid,
                                              value remote_port)
{
	CAMLparam3(xce_val, domid, remote_port);
	xenevtchn_handle *xce = xce_of_val(xce_val);
	xenevtchn_port_or_error_t rc;

	caml_enter_blocking_section();
	rc = xenevtchn_bind_interdomain(xce, Int_val(domid),
					Int_val(remote_port));
	caml_leave_blocking_section();

	if (rc == -1)
		caml_failwith("evtchn bind_interdomain failed");

	CAMLreturn(Val_int(rc));
}

CAMLprim value stub_eventchn_bind_virq(value xce_val, value virq)
{
	CAMLparam2(xce_val, virq);
	xenevtchn_handle *xce = xce_of_val(xce_val);
	xenevtchn_port_or_error_t rc;

	caml_enter_blocking_section();
	rc = xenevtchn_bind_virq(xce, Int_val(virq));
	caml_leave_blocking_section();

	if (rc == -1)
		caml_failwith("evtchn bind_virq failed");

	CAMLreturn(Val_int(rc));
}

CAMLprim value stub_eventchn_unbind(value xce_val, value port)
{
	CAMLparam2(xce_val, port);
	xenevtchn_handle *xce = xce_of_val(xce_val);
	int rc;

	caml_enter_blocking_section();
	rc = xenevtchn_unbind(xce, Int_val(port));
	caml_leave_blocking_section();

	if (rc == -1)
		caml_failwith("evtchn unbind failed");

	CAMLreturn(Val_unit);
}

CAMLprim value stub_eventchn_pending(value xce_val)
{
	CAMLparam1(xce_val);
	xenevtchn_handle *xce = xce_of_val(xce_val);
	xenevtchn_port_or_error_t rc;

	caml_enter_blocking_section();
	rc = xenevtchn_pending(xce);
	caml_leave_blocking_section();

	if (rc == -1)
		caml_failwith("evtchn pending failed");

	CAMLreturn(Val_int(rc));
}

CAMLprim value stub_eventchn_unmask(value xce_val, value port)
{
	CAMLparam2(xce_val, port);
	xenevtchn_handle *xce = xce_of_val(xce_val);
	int rc;

	caml_enter_blocking_section();
	rc = xenevtchn_unmask(xce, Int_val(port));
	caml_leave_blocking_section();

	if (rc == -1)
		caml_failwith("evtchn unmask failed");

	CAMLreturn(Val_unit);
}
