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

let debug fmt = Logging.debug "domains" fmt

type domains = {
	eventchn: Event.t;
	table: (Xenctrl.domid, Domain.t) Hashtbl.t;
}

let init eventchn =
	{ eventchn = eventchn; table = Hashtbl.create 10 }
let del doms id = Hashtbl.remove doms.table id
let exist doms id = Hashtbl.mem doms.table id
let find doms id = Hashtbl.find doms.table id
let number doms = Hashtbl.length doms.table
let iter doms fct = Hashtbl.iter (fun _ b -> fct b) doms.table

let cleanup xc doms =
	let notify = ref false in
	let dead_dom = ref [] in

	Hashtbl.iter (fun id _ -> if id <> 0 then
		try
			let info = Xenctrl.domain_getinfo xc id in
			if info.Xenctrl.shutdown || info.Xenctrl.dying then (
				debug "Domain %u died (dying=%b, shutdown %b -- code %d)"
				                    id info.Xenctrl.dying info.Xenctrl.shutdown info.Xenctrl.shutdown_code;
				if info.Xenctrl.dying then
					dead_dom := id :: !dead_dom
				else
					notify := true;
			)
		with Xenctrl.Error _ ->
			debug "Domain %u died -- no domain info" id;
			dead_dom := id :: !dead_dom;
		) doms.table;
	List.iter (fun id ->
		let dom = Hashtbl.find doms.table id in
		Domain.close dom;
		Hashtbl.remove doms.table id;
	) !dead_dom;
	!notify, !dead_dom

let resume doms domid =
	()

let create xc doms domid mfn port =
	let interface = Xenctrl.map_foreign_range xc domid (Xenmmap.getpagesize()) mfn in
	let dom = Domain.make domid mfn port interface doms.eventchn in
	Hashtbl.add doms.table domid dom;
	Domain.bind_interdomain dom;
	dom

let create0 doms =
	let port, interface =
		(
			let port = Utils.read_file_single_integer Define.xenstored_proc_port
			and fd = Unix.openfile Define.xenstored_proc_kva
					       [ Unix.O_RDWR ] 0o600 in
			let interface = Xenmmap.mmap fd Xenmmap.RDWR Xenmmap.SHARED
						  (Xenmmap.getpagesize()) 0 in
			Unix.close fd;
			port, interface
		)
		in
	let dom = Domain.make 0 Nativeint.zero port interface doms.eventchn in
	Hashtbl.add doms.table 0 dom;
	Domain.bind_interdomain dom;
	Domain.notify dom;
	dom
