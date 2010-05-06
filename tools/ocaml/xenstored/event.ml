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

(**************** high level binding ****************)
type t = {
	fd: Unix.file_descr;
	mutable virq_port: int;
}

let init () = { fd = Eventchn.init (); virq_port = -1; }
let bind_virq eventchn = eventchn.virq_port <- Eventchn.bind_virq eventchn.fd
let bind_interdomain eventchn domid port = Eventchn.bind_interdomain eventchn.fd domid port
let unbind eventchn port = Eventchn.unbind eventchn.fd port
let notify eventchn port = Eventchn.notify eventchn.fd port
let read_port eventchn = Eventchn.read_port eventchn.fd
let write_port eventchn port = Eventchn.write_port eventchn.fd port
