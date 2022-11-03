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

#define _H(__h) (*((xenevtchn_handle **)Data_custom_val(__h)))

static void stub_evtchn_finalize(value v)
{
	xenevtchn_close(_H(v));
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

	caml_enter_blocking_section();
	xce = xenevtchn_open(NULL, flags);
	caml_leave_blocking_section();

	if (xce == NULL)
		caml_failwith("open failed");

	result = caml_alloc_custom(&xenevtchn_ops, sizeof(xce), 0, 1);
	_H(result) = xce;

	CAMLreturn(result);
}

CAMLprim value stub_eventchn_fdopen(value fdval)
{
	CAMLparam1(fdval);
	CAMLlocal1(result);
	xenevtchn_handle *xce;

	caml_enter_blocking_section();
	xce = xenevtchn_fdopen(NULL, Int_val(fdval), 0);
	caml_leave_blocking_section();

	if (xce == NULL)
		caml_failwith("evtchn fdopen failed");

	result = caml_alloc_custom(&xenevtchn_ops, sizeof(xce), 0, 1);
	_H(result) = xce;

	CAMLreturn(result);
}

CAMLprim value stub_eventchn_fd(value xce)
{
	CAMLparam1(xce);
	CAMLlocal1(result);
	int fd;

	fd = xenevtchn_fd(_H(xce));
	if (fd == -1)
		caml_failwith("evtchn fd failed");

	result = Val_int(fd);

	CAMLreturn(result);
}

CAMLprim value stub_eventchn_notify(value xce, value port)
{
	CAMLparam2(xce, port);
	int rc;

	caml_enter_blocking_section();
	rc = xenevtchn_notify(_H(xce), Int_val(port));
	caml_leave_blocking_section();

	if (rc == -1)
		caml_failwith("evtchn notify failed");

	CAMLreturn(Val_unit);
}

CAMLprim value stub_eventchn_bind_interdomain(value xce, value domid,
                                              value remote_port)
{
	CAMLparam3(xce, domid, remote_port);
	CAMLlocal1(port);
	xenevtchn_port_or_error_t rc;

	caml_enter_blocking_section();
	rc = xenevtchn_bind_interdomain(_H(xce), Int_val(domid), Int_val(remote_port));
	caml_leave_blocking_section();

	if (rc == -1)
		caml_failwith("evtchn bind_interdomain failed");
	port = Val_int(rc);

	CAMLreturn(port);
}

CAMLprim value stub_eventchn_bind_virq(value xce, value virq_type)
{
	CAMLparam2(xce, virq_type);
	CAMLlocal1(port);
	xenevtchn_port_or_error_t rc;

	caml_enter_blocking_section();
	rc = xenevtchn_bind_virq(_H(xce), Int_val(virq_type));
	caml_leave_blocking_section();

	if (rc == -1)
		caml_failwith("evtchn bind_virq failed");
	port = Val_int(rc);

	CAMLreturn(port);
}

CAMLprim value stub_eventchn_unbind(value xce, value port)
{
	CAMLparam2(xce, port);
	int rc;

	caml_enter_blocking_section();
	rc = xenevtchn_unbind(_H(xce), Int_val(port));
	caml_leave_blocking_section();

	if (rc == -1)
		caml_failwith("evtchn unbind failed");

	CAMLreturn(Val_unit);
}

CAMLprim value stub_eventchn_pending(value xce)
{
	CAMLparam1(xce);
	CAMLlocal1(result);
	xenevtchn_port_or_error_t port;

	caml_enter_blocking_section();
	port = xenevtchn_pending(_H(xce));
	caml_leave_blocking_section();

	if (port == -1)
		caml_failwith("evtchn pending failed");
	result = Val_int(port);

	CAMLreturn(result);
}

CAMLprim value stub_eventchn_unmask(value xce, value _port)
{
	CAMLparam2(xce, _port);
	evtchn_port_t port;
	int rc;

	port = Int_val(_port);

	caml_enter_blocking_section();
	rc = xenevtchn_unmask(_H(xce), port);
	caml_leave_blocking_section();

	if (rc)
		caml_failwith("evtchn unmask failed");
	CAMLreturn(Val_unit);
}
