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

exception End_of_file

open Stdext

let xenstore_payload_max = 4096 (* xen/include/public/io/xs_wire.h *)

type watch = {
	con: t;
	token: string;
	path: string;
	base: string;
	is_relative: bool;
}

and t = {
	xb: Xenbus.Xb.t;
	dom: Domain.t option;
	transactions: (int, Transaction.t) Hashtbl.t;
	mutable next_tid: int;
	watches: (string, watch list) Hashtbl.t;
	mutable nb_watches: int;
	anonid: int;
	mutable stat_nb_ops: int;
	mutable perm: Perms.Connection.t;
}

let mark_as_bad con =
	match con.dom with
	|None -> ()
	| Some domain -> Domain.mark_as_bad domain

let get_path con =
Printf.sprintf "/local/domain/%i/" (match con.dom with None -> 0 | Some d -> Domain.get_id d)

let watch_create ~con ~path ~token = { 
	con = con; 
	token = token; 
	path = path; 
	base = get_path con; 
	is_relative = path.[0] <> '/' && path.[0] <> '@'
}

let get_con w = w.con
 
let number_of_transactions con =
	Hashtbl.length con.transactions

let get_domain con = con.dom

let anon_id_next = ref 1

let get_domstr con =
	match con.dom with
	| None     -> "A" ^ (string_of_int con.anonid)
	| Some dom -> "D" ^ (string_of_int (Domain.get_id dom))

let make_perm dom =
	let domid = 
		match dom with
		| None   -> 0
		| Some d -> Domain.get_id d
	in 
	Perms.Connection.create ~perms:[Perms.READ; Perms.WRITE] domid

let create xbcon dom =
	let id =
		match dom with
		| None -> let old = !anon_id_next in incr anon_id_next; old
		| Some _ -> 0  
		in
	let con = 
	{
	xb = xbcon;
	dom = dom;
	transactions = Hashtbl.create 5;
	next_tid = 1;
	watches = Hashtbl.create 8;
	nb_watches = 0;
	anonid = id;
	stat_nb_ops = 0;
	perm = make_perm dom;
	}
	in 
	Logging.new_connection ~tid:Transaction.none ~con:(get_domstr con);
	con

let get_fd con = Xenbus.Xb.get_fd con.xb
let close con =
	Logging.end_connection ~tid:Transaction.none ~con:(get_domstr con);
	Xenbus.Xb.close con.xb

let get_perm con =
	con.perm

let restrict con domid =
	con.perm <- Perms.Connection.restrict con.perm domid

let set_target con target_domid =
	con.perm <- Perms.Connection.set_target (get_perm con) ~perms:[Perms.READ; Perms.WRITE] target_domid

let is_backend_mmap con = match con.xb.Xenbus.Xb.backend with
	| Xenbus.Xb.Xenmmap _ -> true
	| _ -> false

let send_reply con tid rid ty data =
	if (String.length data) > xenstore_payload_max && (is_backend_mmap con) then
		Xenbus.Xb.queue con.xb (Xenbus.Xb.Packet.create tid rid Xenbus.Xb.Op.Error "E2BIG\000")
	else
		Xenbus.Xb.queue con.xb (Xenbus.Xb.Packet.create tid rid ty data)

let send_error con tid rid err = send_reply con tid rid Xenbus.Xb.Op.Error (err ^ "\000")
let send_ack con tid rid ty = send_reply con tid rid ty "OK\000"

let get_watch_path con path =
	if path.[0] = '@' || path.[0] = '/' then
		path
	else
		let rpath = get_path con in
		rpath ^ path

let get_watches (con: t) path =
	if Hashtbl.mem con.watches path
	then Hashtbl.find con.watches path
	else []

let get_children_watches con path =
	let path = path ^ "/" in
	List.concat (Hashtbl.fold (fun p w l ->
		if String.startswith path p then w :: l else l) con.watches [])

let is_dom0 con =
	Perms.Connection.is_dom0 (get_perm con)

let add_watch con path token =
	if !Quota.activate && !Define.maxwatch > 0 &&
	   not (is_dom0 con) && con.nb_watches > !Define.maxwatch then
		raise Quota.Limit_reached;
	let apath = get_watch_path con path in
	let l = get_watches con apath in
	if List.exists (fun w -> w.token = token) l then
		raise Define.Already_exist;
	let watch = watch_create ~con ~token ~path in
	Hashtbl.replace con.watches apath (watch :: l);
	con.nb_watches <- con.nb_watches + 1;
	apath, watch

let del_watch con path token =
	let apath = get_watch_path con path in
	let ws = Hashtbl.find con.watches apath in
	let w = List.find (fun w -> w.token = token) ws in
	let filtered = Utils.list_remove w ws in
	if List.length filtered > 0 then
		Hashtbl.replace con.watches apath filtered
	else
		Hashtbl.remove con.watches apath;
	con.nb_watches <- con.nb_watches - 1;
	apath, w

let list_watches con =
	let ll = Hashtbl.fold 
		(fun _ watches acc -> List.map (fun watch -> watch.path, watch.token) watches :: acc)
		con.watches [] in
	List.concat ll

let fire_single_watch watch =
	let data = Utils.join_by_null [watch.path; watch.token; ""] in
	send_reply watch.con Transaction.none 0 Xenbus.Xb.Op.Watchevent data

let fire_watch watch path =
	let new_path =
		if watch.is_relative && path.[0] = '/'
		then begin
			let n = String.length watch.base
		 	and m = String.length path in
			String.sub path n (m - n)
		end else
			path
	in
	let data = Utils.join_by_null [ new_path; watch.token; "" ] in
	send_reply watch.con Transaction.none 0 Xenbus.Xb.Op.Watchevent data

let find_next_tid con =
	let ret = con.next_tid in con.next_tid <- con.next_tid + 1; ret

let start_transaction con store =
	if !Define.maxtransaction > 0 && not (is_dom0 con)
	&& Hashtbl.length con.transactions > !Define.maxtransaction then
		raise Quota.Transaction_opened;
	let id = find_next_tid con in
	let ntrans = Transaction.make id store in
	Hashtbl.add con.transactions id ntrans;
	Logging.start_transaction ~tid:id ~con:(get_domstr con);
	id

let end_transaction con tid commit =
	let trans = Hashtbl.find con.transactions tid in
	Hashtbl.remove con.transactions tid;
	Logging.end_transaction ~tid ~con:(get_domstr con);
	if commit then Transaction.commit ~con:(get_domstr con) trans else true

let get_transaction con tid =
	Hashtbl.find con.transactions tid

let do_input con = Xenbus.Xb.input con.xb
let has_input con = Xenbus.Xb.has_in_packet con.xb
let pop_in con = Xenbus.Xb.get_in_packet con.xb
let has_more_input con = Xenbus.Xb.has_more_input con.xb

let has_output con = Xenbus.Xb.has_output con.xb
let has_new_output con = Xenbus.Xb.has_new_output con.xb
let peek_output con = Xenbus.Xb.peek_output con.xb
let do_output con = Xenbus.Xb.output con.xb

let incr_ops con = con.stat_nb_ops <- con.stat_nb_ops + 1

let mark_symbols con =
	Hashtbl.iter (fun _ t -> Store.mark_symbols (Transaction.get_store t)) con.transactions

let stats con =
	Hashtbl.length con.watches, con.stat_nb_ops

let dump con chan =
	match con.dom with
	| Some dom -> 
		let domid = Domain.get_id dom in
		(* dump domain *)
		Domain.dump dom chan;
		(* dump watches *)
		List.iter (fun (path, token) ->
			Printf.fprintf chan "watch,%d,%s,%s\n" domid (Utils.hexify path) (Utils.hexify token)
			) (list_watches con);
	| None -> ()

let debug con =
	let domid = get_domstr con in
	let watches = List.map (fun (path, token) -> Printf.sprintf "watch %s: %s %s\n" domid path token) (list_watches con) in
	String.concat "" watches
