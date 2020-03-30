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

#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>

#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/custom.h>
#include <caml/fail.h>
#include <caml/callback.h>

#include <xenctrl.h>
#include <xen/io/xs_wire.h>

CAMLprim value stub_header_size(void)
{
	CAMLparam0();
	CAMLreturn(Val_int(sizeof(struct xsd_sockmsg)));
}

CAMLprim value stub_header_of_string(value s)
{
	CAMLparam1(s);
	CAMLlocal1(ret);
	const struct xsd_sockmsg *hdr;

	if (caml_string_length(s) != sizeof(struct xsd_sockmsg))
		caml_failwith("xb header incomplete");
	ret = caml_alloc_tuple(4);
	hdr = (const struct xsd_sockmsg *) String_val(s);
	Store_field(ret, 0, Val_int(hdr->tx_id));
	Store_field(ret, 1, Val_int(hdr->req_id));
	Store_field(ret, 2, Val_int(hdr->type));
	Store_field(ret, 3, Val_int(hdr->len));
	CAMLreturn(ret);
}

CAMLprim value stub_string_of_header(value tid, value rid, value ty, value len)
{
	CAMLparam4(tid, rid, ty, len);
	CAMLlocal1(ret);
	struct xsd_sockmsg xsd = {
		.type = Int_val(ty),
		.tx_id = Int_val(tid),
		.req_id = Int_val(rid),
		.len = Int_val(len),
	};

	ret = caml_alloc_string(sizeof(struct xsd_sockmsg));
	memcpy((char *) String_val(ret), &xsd, sizeof(struct xsd_sockmsg));

	CAMLreturn(ret);
}
