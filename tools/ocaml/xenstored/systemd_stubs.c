/*
 * Copyright (C) 2014 Luis R. Rodriguez <mcgrof@suse.com>
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

#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/custom.h>
#include <caml/signals.h>
#include <caml/fail.h>

#if defined(HAVE_SYSTEMD)

#include <systemd/sd-daemon.h>

#include "_paths.h"

CAMLprim value ocaml_sd_notify_ready(value ignore)
{
	CAMLparam1(ignore);
	CAMLlocal1(ret);

	ret = Val_int(0);

	sd_notify(1, "READY=1");

	CAMLreturn(ret);
}

#else

CAMLprim value ocaml_sd_notify_ready(value ignore)
{
	CAMLparam1(ignore);
	CAMLlocal1(ret);

	ret = Val_int(-1U);

	CAMLreturn(ret);
}
#endif
