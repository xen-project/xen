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
	handle: Xeneventchn.handle;
	mutable virq_port: Xeneventchn.t option;
}

let init () = { handle = Xeneventchn.init (); virq_port = None; }
let fd eventchn = Xeneventchn.fd eventchn.handle
let bind_dom_exc_virq eventchn = eventchn.virq_port <- Some (Xeneventchn.bind_dom_exc_virq eventchn.handle)
let bind_interdomain eventchn domid port = Xeneventchn.bind_interdomain eventchn.handle domid port
let unbind eventchn port = Xeneventchn.unbind eventchn.handle port
let notify eventchn port = Xeneventchn.notify eventchn.handle port
let pending eventchn = Xeneventchn.pending eventchn.handle
let unmask eventchn port = Xeneventchn.unmask eventchn.handle port
