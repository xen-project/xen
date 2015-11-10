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
#include <string.h>
#include <stdint.h>

#include <xenctrl.h>
#include <xen/io/xs_wire.h>

#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/custom.h>
#include <caml/fail.h>
#include <caml/callback.h>

#include "mmap_stubs.h"

#define GET_C_STRUCT(a) ((struct mmap_interface *) a)

CAMLprim value ml_interface_read(value ml_interface,
                                 value ml_buffer,
                                 value ml_len)
{
	CAMLparam3(ml_interface, ml_buffer, ml_len);
	CAMLlocal1(ml_result);

	struct mmap_interface *interface = GET_C_STRUCT(ml_interface);
	char *buffer = String_val(ml_buffer);
	int len = Int_val(ml_len);
	int result;

	struct xenstore_domain_interface *intf = interface->addr;
	XENSTORE_RING_IDX cons, prod; /* offsets only */
	int total_data, data;
	uint32_t connection;

	cons = *(volatile uint32_t*)&intf->req_cons;
	prod = *(volatile uint32_t*)&intf->req_prod;
	connection = *(volatile uint32_t*)&intf->connection;

	if (connection != XENSTORE_CONNECTED)
		caml_raise_constant(*caml_named_value("Xb.Reconnect"));

	xen_mb();

	if ((prod - cons) > XENSTORE_RING_SIZE)
		caml_failwith("bad connection");

	/* Check for any pending data at all. */
	total_data = prod - cons;
	if (total_data == 0) {
		/* No pending data at all. */
		result = 0;
		goto exit;
	}
	else if (total_data < len)
		/* Some data - make a partial read. */
		len = total_data;

	/* Check whether data crosses the end of the ring. */
	data = XENSTORE_RING_SIZE - MASK_XENSTORE_IDX(cons);
	if (len < data)
		/* Data within the remaining part of the ring. */
		memcpy(buffer, intf->req + MASK_XENSTORE_IDX(cons), len);
	else {
		/* Data crosses the ring boundary. Read both halves. */
		memcpy(buffer, intf->req + MASK_XENSTORE_IDX(cons), data);
		memcpy(buffer + data, intf->req, len - data);
	}

	xen_mb();
	intf->req_cons += len;
	result = len;
exit:
	ml_result = Val_int(result);
	CAMLreturn(ml_result);
}

CAMLprim value ml_interface_write(value ml_interface,
                                  value ml_buffer,
                                  value ml_len)
{
	CAMLparam3(ml_interface, ml_buffer, ml_len);
	CAMLlocal1(ml_result);

	struct mmap_interface *interface = GET_C_STRUCT(ml_interface);
	char *buffer = String_val(ml_buffer);
	int len = Int_val(ml_len);
	int result;

	struct xenstore_domain_interface *intf = interface->addr;
	XENSTORE_RING_IDX cons, prod;
	int total_space, space;
	uint32_t connection;

	cons = *(volatile uint32_t*)&intf->rsp_cons;
	prod = *(volatile uint32_t*)&intf->rsp_prod;
	connection = *(volatile uint32_t*)&intf->connection;

	if (connection != XENSTORE_CONNECTED)
		caml_raise_constant(*caml_named_value("Xb.Reconnect"));

	xen_mb();

	if ((prod - cons) > XENSTORE_RING_SIZE)
		caml_failwith("bad connection");

	/* Check for space to write the full message. */
	total_space = XENSTORE_RING_SIZE - (prod - cons);
	if (total_space == 0) {
		/* No space at all - exit having done nothing. */
		result = 0;
		goto exit;
	}
	else if (total_space < len)
		/* Some space - make a partial write. */
		len = total_space;

	/* Check for space until the ring wraps. */
	space = XENSTORE_RING_SIZE - MASK_XENSTORE_IDX(prod);
	if (len < space)
		/* Message fits inside the remaining part of the ring. */
		memcpy(intf->rsp + MASK_XENSTORE_IDX(prod), buffer, len);
	else {
		/* Message wraps around the end of the ring. Write both halves. */
		memcpy(intf->rsp + MASK_XENSTORE_IDX(prod), buffer, space);
		memcpy(intf->rsp, buffer + space, len - space);
	}

	xen_mb();
	intf->rsp_prod += len;
	result = len;
exit:
	ml_result = Val_int(result);
	CAMLreturn(ml_result);
}

CAMLprim value ml_interface_set_server_features(value interface, value v)
{
	CAMLparam2(interface, v);
	struct xenstore_domain_interface *intf = GET_C_STRUCT(interface)->addr;

	intf->server_features = Int_val(v);

	CAMLreturn(Val_unit);
}

CAMLprim value ml_interface_get_server_features(value interface)
{
	CAMLparam1(interface);
	struct xenstore_domain_interface *intf = GET_C_STRUCT(interface)->addr;

	CAMLreturn(Val_int (intf->server_features));
}

CAMLprim value ml_interface_close(value interface)
{
	CAMLparam1(interface);
	struct xenstore_domain_interface *intf = GET_C_STRUCT(interface)->addr;
	int i;

	intf->req_cons = intf->req_prod = intf->rsp_cons = intf->rsp_prod = 0;
	/* Ensure the unused space is full of invalid xenstore packets. */
	for (i = 0; i < XENSTORE_RING_SIZE; i++) {
		intf->req[i] = 0xff; /* XS_INVALID = 0xffff */
		intf->rsp[i] = 0xff;
	}
	xen_mb ();
	intf->connection = XENSTORE_CONNECTED;
	CAMLreturn(Val_unit);
}
