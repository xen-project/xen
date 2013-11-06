/*
 * Copyright (C) 2013      Citrix Ltd.
 * Author Ian Campbell <ian.campbell@citrix.com>
 * Author Rob Hoes <rob.hoes@citrix.com>
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

struct caml_xtl {
	xentoollog_logger vtable;
	char *vmessage_cb;
	char *progress_cb;
};

#define Xtl_val(x)(*((struct caml_xtl **) Data_custom_val(x)))

