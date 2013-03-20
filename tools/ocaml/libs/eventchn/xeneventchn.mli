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

type handle

type t

val to_int: t -> int
val of_int: int -> t

external init : unit -> handle = "stub_eventchn_init"
external fd: handle -> Unix.file_descr = "stub_eventchn_fd"

external notify : handle -> t -> unit = "stub_eventchn_notify"
external bind_interdomain : handle -> int -> int -> t
  = "stub_eventchn_bind_interdomain"
external bind_dom_exc_virq : handle -> t = "stub_eventchn_bind_dom_exc_virq"
external unbind : handle -> t -> unit = "stub_eventchn_unbind"
external pending : handle -> t = "stub_eventchn_pending"
external unmask : handle -> t -> unit
  = "stub_eventchn_unmask"
