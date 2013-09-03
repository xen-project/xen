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

open Printf

let debug fmt = Logging.debug "domain" fmt

type t =
{
	id: Xenctrl.domid;
	mfn: nativeint;
	remote_port: int;
	interface: Xenmmap.mmap_interface;
	eventchn: Event.t;
	mutable port: int;
	mutable bad_client: bool;
}

let get_path dom = "/local/domain/" ^ (sprintf "%u" dom.id)
let get_id domain = domain.id
let get_interface d = d.interface
let get_mfn d = d.mfn
let get_remote_port d = d.remote_port

let is_bad_domain domain = domain.bad_client
let mark_as_bad domain = domain.bad_client <- true

let dump d chan =
	fprintf chan "dom,%d,%nd,%d\n" d.id d.mfn d.port

let notify dom = Event.notify dom.eventchn dom.port; ()

let bind_interdomain dom =
	dom.port <- Event.bind_interdomain dom.eventchn dom.id dom.remote_port;
	debug "domain %d bound port %d" dom.id dom.port


let close dom =
	debug "domain %d unbound port %d" dom.id dom.port;
	Event.unbind dom.eventchn dom.port;
	Xenmmap.unmap dom.interface;
	()

let make id mfn remote_port interface eventchn = {
	id = id;
	mfn = mfn;
	remote_port = remote_port;
	interface = interface;
	eventchn = eventchn;
	port = -1;
	bad_client = false
}

let is_dom0 d = d.id = 0
