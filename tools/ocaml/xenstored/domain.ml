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

(* A bound inter-domain event channel port pair.  The remote port, and the
   local port it is bound to. *)
type port_pair =
  {
    local: Xeneventchn.t;
    remote: int;
  }

(* Sentinal port_pair with both set to EVTCHN_INVALID *)
let invalid_ports =
  {
    local = Xeneventchn.of_int 0;
    remote = 0
  }

let string_of_port_pair p =
  sprintf "(l %d, r %d)" (Xeneventchn.to_int p.local) p.remote

type t =
  {
    id: Xenctrl.domid;
    mfn: nativeint;
    interface: Xenmmap.mmap_interface;
    eventchn: Event.t;
    mutable ports: port_pair;
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
let get_id domain = domain.id
let get_interface d = d.interface
let get_mfn d = d.mfn
let get_remote_port d = d.ports.remote
let get_local_port d = d.ports.local

let is_bad_domain domain = domain.bad_client
let mark_as_bad domain = domain.bad_client <- true

let get_io_credit domain = domain.io_credit
let set_io_credit ?(n=1) domain = domain.io_credit <- max 0 n
let incr_io_credit domain = domain.io_credit <- domain.io_credit + 1
let decr_io_credit domain = domain.io_credit <- max 0 (domain.io_credit - 1)

let is_paused_for_conflict dom = dom.conflict_credit <= 0.0

let is_free_to_conflict = is_dom0

let dump d chan =
  fprintf chan "dom,%d,%nd,%d,%d\n"
    d.id d.mfn d.ports.remote (Xeneventchn.to_int d.ports.local)

let rebind_evtchn d remote_port =
  Event.unbind d.eventchn d.ports.local;
  let local = Event.bind_interdomain d.eventchn d.id remote_port in
  let new_ports = { local; remote = remote_port } in
  debug "domain %d rebind %s => %s"
    d.id (string_of_port_pair d.ports) (string_of_port_pair new_ports);
  d.ports <- new_ports

let notify dom =
  Event.notify dom.eventchn dom.ports.local

let close dom =
  debug "domain %d unbind %s" dom.id (string_of_port_pair dom.ports);
  Event.unbind dom.eventchn dom.ports.local;
  dom.ports <- invalid_ports;
  Xenmmap.unmap dom.interface

(* On clean start, local_port will be None, and we must bind the remote port
   given.  On Live Update, the event channel is already bound, and both the
   local and remote port numbers come from the transfer record. *)
let make ?local_port ~remote_port id mfn interface eventchn =
  let local = match local_port with
    | None -> Event.bind_interdomain eventchn id remote_port
    | Some p -> Xeneventchn.of_int p
  in
  let ports = { local; remote = remote_port } in
  debug "domain %d bind %s" id (string_of_port_pair ports);
  {
    id = id;
    mfn = mfn;
    ports;
    interface = interface;
    eventchn = eventchn;
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
