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
#include <xen/sysctl.h>
#include <xen/xen.h>
#include <xen/sys/evtchn.h>
#include <xenctrl.h>

#define CAML_NAME_SPACE
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/custom.h>
#include <caml/callback.h>
#include <caml/fail.h>

#define EVENTCHN_PATH "/dev/xen/evtchn"

static int do_ioctl(int handle, int cmd, void *arg)
{
	return ioctl(handle, cmd, arg);
}

static int do_read_port(int handle, evtchn_port_t *port)
{
	return (read(handle, port, sizeof(evtchn_port_t)) != sizeof(evtchn_port_t));
}

static int do_write_port(int handle, evtchn_port_t port)
{
	return (write(handle, &port, sizeof(evtchn_port_t)) != sizeof(evtchn_port_t));
}

int eventchn_do_open(void)
{
	return open(EVENTCHN_PATH, O_RDWR);
}

CAMLprim value stub_eventchn_init(value unit)
{
	CAMLparam1(unit);
	int fd = eventchn_do_open();
	if (fd == -1)
		caml_failwith("open failed");
	CAMLreturn(Val_int(fd));
}

CAMLprim value stub_eventchn_notify(value fd, value port)
{
	CAMLparam2(fd, port);
	struct ioctl_evtchn_notify notify;
	int rc;

	notify.port = Int_val(port);
	rc = do_ioctl(Int_val(fd), IOCTL_EVTCHN_NOTIFY, &notify);
	if (rc == -1)
		caml_failwith("ioctl notify failed");

	CAMLreturn(Val_unit);
}

CAMLprim value stub_eventchn_bind_interdomain(value fd, value domid,
                                              value remote_port)
{
	CAMLparam3(fd, domid, remote_port);
	CAMLlocal1(port);
	struct ioctl_evtchn_bind_interdomain bind;
	int rc;

	bind.remote_domain = Int_val(domid);
	bind.remote_port = Int_val(remote_port);
	rc = do_ioctl(Int_val(fd), IOCTL_EVTCHN_BIND_INTERDOMAIN, &bind);
	if (rc == -1)
		caml_failwith("ioctl bind_interdomain failed");
	port = Val_int(rc);

	CAMLreturn(port);
}

CAMLprim value stub_eventchn_bind_virq(value fd)
{
	CAMLparam1(fd);
	CAMLlocal1(port);
	struct ioctl_evtchn_bind_virq bind;
	int rc;

	bind.virq = VIRQ_DOM_EXC;
	rc = do_ioctl(Int_val(fd), IOCTL_EVTCHN_BIND_VIRQ, &bind);
	if (rc == -1)
		caml_failwith("ioctl bind_virq failed");
	port = Val_int(rc);

	CAMLreturn(port);
}

CAMLprim value stub_eventchn_unbind(value fd, value port)
{
	CAMLparam2(fd, port);
	struct ioctl_evtchn_unbind unbind;
	int rc;

	unbind.port = Int_val(port);
	rc = do_ioctl(Int_val(fd), IOCTL_EVTCHN_UNBIND, &unbind);
	if (rc == -1)
		caml_failwith("ioctl unbind failed");

	CAMLreturn(Val_unit);
}

CAMLprim value stub_eventchn_read_port(value fd)
{
	CAMLparam1(fd);
	CAMLlocal1(result);
	evtchn_port_t port;

	if (do_read_port(Int_val(fd), &port))
		caml_failwith("read port failed");
	result = Val_int(port);

	CAMLreturn(result);
}

CAMLprim value stub_eventchn_write_port(value fd, value _port)
{
	CAMLparam2(fd, _port);
	evtchn_port_t port;

	port = Int_val(_port);
	if (do_write_port(Int_val(fd), port))
		caml_failwith("write port failed");
	CAMLreturn(Val_unit);
}
