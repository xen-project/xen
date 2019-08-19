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
let warn  fmt = Logging.warn  "domain" fmt

type t =
{
	id: Xenctrl.domid;
	mfn: nativeint;
	interface: Xenmmap.mmap_interface;
	eventchn: Event.t;
	mutable remote_port: int;
	mutable port: Xeneventchn.t option;
	mutable bad_client: bool;
	mutable io_credit: int; (* the rounds of ring process left to do, default is 0,
	                           usually set to 1 when there is work detected, could
	                           also set to n to give "lazy" clients extra credit *)
	mutable conflict_credit: float; (* Must be positive to perform writes; a commit
	                                   that later causes conflict with another
	                                   domain's transaction costs credit. *)
	mutable caused_conflicts: int64;
}

let is_dom0 d = d.id = 0
let get_path dom = "/local/domain/" ^ (sprintf "%u" dom.id)
let get_id domain = domain.id
let get_interface d = d.interface
let get_mfn d = d.mfn
let get_remote_port d = d.remote_port
let get_port d = d.port

let is_bad_domain domain = domain.bad_client
let mark_as_bad domain = domain.bad_client <- true

let get_io_credit domain = domain.io_credit
let set_io_credit ?(n=1) domain = domain.io_credit <- max 0 n
let incr_io_credit domain = domain.io_credit <- domain.io_credit + 1
let decr_io_credit domain = domain.io_credit <- max 0 (domain.io_credit - 1)

let is_paused_for_conflict dom = dom.conflict_credit <= 0.0

let is_free_to_conflict = is_dom0

let string_of_port = function
| None -> "None"
| Some x -> string_of_int (Xeneventchn.to_int x)

let dump d chan =
	fprintf chan "dom,%d,%nd,%d\n" d.id d.mfn d.remote_port

let notify dom = match dom.port with
| None ->
	warn "domain %d: attempt to notify on unknown port" dom.id
| Some port ->
	Event.notify dom.eventchn port

let bind_interdomain dom =
	begin match dom.port with
	| None -> ()
	| Some port -> Event.unbind dom.eventchn port
	end;
	dom.port <- Some (Event.bind_interdomain dom.eventchn dom.id dom.remote_port);
	debug "bound domain %d remote port %d to local port %s" dom.id dom.remote_port (string_of_port dom.port)


let close dom =
	debug "domain %d unbound port %s" dom.id (string_of_port dom.port);
	begin match dom.port with
	| None -> ()
	| Some port -> Event.unbind dom.eventchn port
	end;
	Xenmmap.unmap dom.interface;
	()

let make id mfn remote_port interface eventchn = {
	id = id;
	mfn = mfn;
	remote_port = remote_port;
	interface = interface;
	eventchn = eventchn;
	port = None;
	bad_client = false;
	io_credit = 0;
	conflict_credit = !Define.conflict_burst_limit;
	caused_conflicts = 0L;
}

let log_and_reset_conflict_stats logfn dom =
	if dom.caused_conflicts > 0L then (
		logfn dom.id dom.caused_conflicts;
		dom.caused_conflicts <- 0L
	)
