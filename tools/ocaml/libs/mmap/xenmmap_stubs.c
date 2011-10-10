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
#include "mmap_stubs.h"

#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/custom.h>
#include <caml/fail.h>
#include <caml/callback.h>

#define Intf_val(a) ((struct mmap_interface *) a)

static int mmap_interface_init(struct mmap_interface *intf,
                               int fd, int pflag, int mflag,
                               int len, int offset)
{
	intf->len = len;
	intf->addr = mmap(NULL, len, pflag, mflag, fd, offset);
	return (intf->addr == MAP_FAILED) ? errno : 0;
}

CAMLprim value stub_mmap_init(value fd, value pflag, value mflag,
                              value len, value offset)
{
	CAMLparam5(fd, pflag, mflag, len, offset);
	CAMLlocal1(result);
	int c_pflag, c_mflag;

	switch (Int_val(pflag)) {
	case 0: c_pflag = PROT_READ; break;
	case 1: c_pflag = PROT_WRITE; break;
	case 2: c_pflag = PROT_READ|PROT_WRITE; break;
	default: caml_invalid_argument("protectiontype");
	}

	switch (Int_val(mflag)) {
	case 0: c_mflag = MAP_SHARED; break;
	case 1: c_mflag = MAP_PRIVATE; break;
	default: caml_invalid_argument("maptype");
	}

	result = caml_alloc(sizeof(struct mmap_interface), Abstract_tag);

	if (mmap_interface_init(Intf_val(result), Int_val(fd),
	                        c_pflag, c_mflag,
	                        Int_val(len), Int_val(offset)))
		caml_failwith("mmap");
	CAMLreturn(result);
}

CAMLprim value stub_mmap_final(value intf)
{
	CAMLparam1(intf);

	if (Intf_val(intf)->addr != MAP_FAILED)
		munmap(Intf_val(intf)->addr, Intf_val(intf)->len);
	Intf_val(intf)->addr = MAP_FAILED;

	CAMLreturn(Val_unit);
}

CAMLprim value stub_mmap_read(value intf, value start, value len)
{
	CAMLparam3(intf, start, len);
	CAMLlocal1(data);
	int c_start;
	int c_len;

	c_start = Int_val(start);
	c_len = Int_val(len);

	if (c_start > Intf_val(intf)->len)
		caml_invalid_argument("start invalid");
	if (c_start + c_len > Intf_val(intf)->len)
		caml_invalid_argument("len invalid");

	data = caml_alloc_string(c_len);
	memcpy((char *) data, Intf_val(intf)->addr + c_start, c_len);

	CAMLreturn(data);
}

CAMLprim value stub_mmap_write(value intf, value data,
                               value start, value len)
{
	CAMLparam4(intf, data, start, len);
	int c_start;
	int c_len;

	c_start = Int_val(start);
	c_len = Int_val(len);

	if (c_start > Intf_val(intf)->len)
		caml_invalid_argument("start invalid");
	if (c_start + c_len > Intf_val(intf)->len)
		caml_invalid_argument("len invalid");

	memcpy(Intf_val(intf)->addr + c_start, (char *) data, c_len);

	CAMLreturn(Val_unit);
}

CAMLprim value stub_mmap_getpagesize(value unit)
{
	CAMLparam1(unit);
	CAMLlocal1(data);

	data = Val_int(getpagesize());
	CAMLreturn(data);
}
