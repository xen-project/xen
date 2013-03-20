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

val init: unit -> handle
val fd: handle -> Unix.file_descr

val notify : handle -> t -> unit
val bind_interdomain : handle -> int -> int -> t

val bind_dom_exc_virq : handle -> t
val unbind : handle -> t -> unit
val pending : handle -> t
val unmask : handle -> t -> unit
