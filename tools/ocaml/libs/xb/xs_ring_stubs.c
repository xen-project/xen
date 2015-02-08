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
	int to_read;
	uint32_t connection;

	cons = *(volatile uint32_t*)&intf->req_cons;
	prod = *(volatile uint32_t*)&intf->req_prod;
	connection = *(volatile uint32_t*)&intf->connection;

	if (connection != XENSTORE_CONNECTED)
		caml_raise_constant(*caml_named_value("Xb.Reconnect"));

	xen_mb();

	if ((prod - cons) > XENSTORE_RING_SIZE)
		caml_failwith("bad connection");

	if (prod == cons) {
		result = 0;
		goto exit;
	}
	cons = MASK_XENSTORE_IDX(cons);
	prod = MASK_XENSTORE_IDX(prod);
	if (prod > cons)
		to_read = prod - cons;
	else
		to_read = XENSTORE_RING_SIZE - cons;
	if (to_read < len)
		len = to_read;
	memcpy(buffer, intf->req + cons, len);
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
	int can_write;
	uint32_t connection;

	cons = *(volatile uint32_t*)&intf->rsp_cons;
	prod = *(volatile uint32_t*)&intf->rsp_prod;
	connection = *(volatile uint32_t*)&intf->connection;

	if (connection != XENSTORE_CONNECTED)
		caml_raise_constant(*caml_named_value("Xb.Reconnect"));

	xen_mb();
	if ( (prod - cons) >= XENSTORE_RING_SIZE ) {
		result = 0;
		goto exit;
	}
	if (MASK_XENSTORE_IDX(prod) >= MASK_XENSTORE_IDX(cons))
		can_write = XENSTORE_RING_SIZE - MASK_XENSTORE_IDX(prod);
	else 
		can_write = MASK_XENSTORE_IDX(cons) - MASK_XENSTORE_IDX(prod);
	if (can_write < len)
		len = can_write;
	memcpy(intf->rsp + MASK_XENSTORE_IDX(prod), buffer, len);
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
