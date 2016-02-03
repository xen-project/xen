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
#include <xen/sys/evtchn.h>
#include <xenevtchn.h>

#define CAML_NAME_SPACE
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/custom.h>
#include <caml/callback.h>
#include <caml/fail.h>

#define _H(__h) ((xenevtchn_handle *)(__h))

CAMLprim value stub_eventchn_init(void)
{
	CAMLparam0();
	CAMLlocal1(result);

	xenevtchn_handle *xce = xenevtchn_open(NULL, 0);
	if (xce == NULL)
		caml_failwith("open failed");

	result = (value)xce;
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

	rc = xenevtchn_notify(_H(xce), Int_val(port));
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

	rc = xenevtchn_bind_interdomain(_H(xce), Int_val(domid), Int_val(remote_port));
	if (rc == -1)
		caml_failwith("evtchn bind_interdomain failed");
	port = Val_int(rc);

	CAMLreturn(port);
}

CAMLprim value stub_eventchn_bind_dom_exc_virq(value xce)
{
	CAMLparam1(xce);
	CAMLlocal1(port);
	xenevtchn_port_or_error_t rc;

	rc = xenevtchn_bind_virq(_H(xce), VIRQ_DOM_EXC);
	if (rc == -1)
		caml_failwith("evtchn bind_dom_exc_virq failed");
	port = Val_int(rc);

	CAMLreturn(port);
}

CAMLprim value stub_eventchn_unbind(value xce, value port)
{
	CAMLparam2(xce, port);
	int rc;

	rc = xenevtchn_unbind(_H(xce), Int_val(port));
	if (rc == -1)
		caml_failwith("evtchn unbind failed");

	CAMLreturn(Val_unit);
}

CAMLprim value stub_eventchn_pending(value xce)
{
	CAMLparam1(xce);
	CAMLlocal1(result);
	xenevtchn_port_or_error_t port;

	port = xenevtchn_pending(_H(xce));
	if (port == -1)
		caml_failwith("evtchn pending failed");
	result = Val_int(port);

	CAMLreturn(result);
}

CAMLprim value stub_eventchn_unmask(value xce, value _port)
{
	CAMLparam2(xce, _port);
	evtchn_port_t port;

	port = Int_val(_port);
	if (xenevtchn_unmask(_H(xce), port))
		caml_failwith("evtchn unmask failed");
	CAMLreturn(Val_unit);
}
