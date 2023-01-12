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
  domexc: Xeneventchn.t;
}

(* On clean start, both parameters will be None, and we must open the evtchn
   handle and bind the DOM_EXC VIRQ.  On Live Update, the fd is preserved
   across exec(), and the DOM_EXC VIRQ still bound. *)
let init ?fd ?domexc_port () =
  let handle = match fd with
    | None -> Xeneventchn.init ~cloexec:false ()
    | Some fd -> fd |> Utils.FD.of_int |> Xeneventchn.fdopen
  in
  let domexc = match domexc_port with
    | None -> Xeneventchn.bind_dom_exc_virq handle
    | Some p -> Xeneventchn.of_int p
  in
  { handle; domexc }

let fd eventchn = Xeneventchn.fd eventchn.handle
let bind_interdomain eventchn domid port = Xeneventchn.bind_interdomain eventchn.handle domid port
let unbind eventchn port = Xeneventchn.unbind eventchn.handle port
let notify eventchn port = Xeneventchn.notify eventchn.handle port
let pending eventchn = Xeneventchn.pending eventchn.handle
let unmask eventchn port = Xeneventchn.unmask eventchn.handle port

let dump e chan =
  Printf.fprintf chan "evtchn-dev,%d,%d\n"
    (Utils.FD.to_int @@ Xeneventchn.fd e.handle)
    (Xeneventchn.to_int e.domexc)
