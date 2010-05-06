(*
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
 *)

exception Error of string

external init: unit -> Unix.file_descr = "stub_eventchn_init"
external notify: Unix.file_descr -> int -> unit = "stub_eventchn_notify"
external bind_interdomain: Unix.file_descr -> int -> int -> int = "stub_eventchn_bind_interdomain"
external bind_virq: Unix.file_descr -> int = "stub_eventchn_bind_virq"
external unbind: Unix.file_descr -> int -> unit = "stub_eventchn_unbind"
external read_port: Unix.file_descr -> int = "stub_eventchn_read_port"
external write_port: Unix.file_descr -> int -> unit = "stub_eventchn_write_port"

let _ = Callback.register_exception "eventchn.error" (Error "register_callback")
