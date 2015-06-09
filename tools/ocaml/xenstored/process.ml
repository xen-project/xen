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

let error fmt = Logging.error "process" fmt
let info fmt = Logging.info "process" fmt

open Printf
open Stdext

exception Transaction_again
exception Transaction_nested
exception Domain_not_match
exception Invalid_Cmd_Args

let allow_debug = ref false

let c_int_of_string s =
	let v = ref 0 in
	let is_digit c = c >= '0' && c <= '9' in
	let len = String.length s in
	let i = ref 0 in
	while !i < len && not (is_digit s.[!i]) do incr i done;
	while !i < len && is_digit s.[!i]
	do
		let x = (Char.code s.[!i]) - (Char.code '0') in
		v := !v * 10 + x;
		incr i
	done;
	!v

(* when we don't want a limit, apply a max limit of 8 arguments.
   no arguments take more than 3 currently, which is pointless to split
   more than needed. *)
let split limit c s =
	let limit = match limit with None -> 8 | Some x -> x in
	String.split ~limit c s

let split_one_path data con =
	let args = split (Some 2) '\000' data in
	match args with
	| path :: "" :: [] -> Store.Path.create path (Connection.get_path con)
	| _                -> raise Invalid_Cmd_Args

let process_watch ops cons =
	let do_op_watch op cons =
		let recurse = match (fst op) with
		| Xenbus.Xb.Op.Write    -> false
		| Xenbus.Xb.Op.Mkdir    -> false
		| Xenbus.Xb.Op.Rm       -> true
		| Xenbus.Xb.Op.Setperms -> false
		| _              -> raise (Failure "huh ?") in
		Connections.fire_watches cons (snd op) recurse in
	List.iter (fun op -> do_op_watch op cons) ops

let create_implicit_path t perm path =
	let dirname = Store.Path.get_parent path in
	if not (Transaction.path_exists t dirname) then (
		let rec check_path p =
			match p with
			| []      -> []
			| h :: l  ->
				if Transaction.path_exists t h then
					check_path l
				else
					p in
		let ret = check_path (List.tl (Store.Path.get_hierarchy dirname)) in
		List.iter (fun s -> Transaction.mkdir ~with_watch:false t perm s) ret
	)

(* packets *)
let do_debug con t domains cons data =
	if not (Connection.is_dom0 con) && not !allow_debug
	then None
	else try match split None '\000' data with
	| "print" :: msg :: _ ->
		Logging.xb_op ~tid:0 ~ty:Xenbus.Xb.Op.Debug ~con:"=======>" msg;
		None
	| "quota" :: domid :: _ ->
		let domid = int_of_string domid in
		let quota = (Store.get_quota t.Transaction.store) in
		Some (Quota.to_string quota domid ^ "\000")
	| "watches" :: _ ->
		let watches = Connections.debug cons in
		Some (watches ^ "\000")
	| "mfn" :: domid :: _ ->
		let domid = int_of_string domid in
		let con = Connections.find_domain cons domid in
		may (fun dom -> Printf.sprintf "%nd\000" (Domain.get_mfn dom)) (Connection.get_domain con)
	| _ -> None
	with _ -> None

let do_directory con t domains cons data =
	let path = split_one_path data con in
	let entries = Transaction.ls t (Connection.get_perm con) path in
	if List.length entries > 0 then
		(Utils.join_by_null entries) ^ "\000"
	else
		""

let do_read con t domains cons data =
	let path = split_one_path data con in
	Transaction.read t (Connection.get_perm con) path

let do_getperms con t domains cons data =
	let path = split_one_path data con in
	let perms = Transaction.getperms t (Connection.get_perm con) path in
	Perms.Node.to_string perms ^ "\000"

let do_watch con t rid domains cons data =
	let (node, token) = 
		match (split None '\000' data) with
		| [node; token; ""]   -> node, token
		| _                   -> raise Invalid_Cmd_Args
		in
	let watch = Connections.add_watch cons con node token in
	Connection.send_ack con (Transaction.get_id t) rid Xenbus.Xb.Op.Watch;
	Connection.fire_single_watch watch

let do_unwatch con t domains cons data =
	let (node, token) =
		match (split None '\000' data) with
		| [node; token; ""]   -> node, token
		| _                   -> raise Invalid_Cmd_Args
		in
	Connections.del_watch cons con node token

let do_transaction_start con t domains cons data =
	if Transaction.get_id t <> Transaction.none then
		raise Transaction_nested;
	let store = Transaction.get_store t in
	string_of_int (Connection.start_transaction con store) ^ "\000"

let do_transaction_end con t domains cons data =
	let commit =
		match (split None '\000' data) with
		| "T" :: _ -> true
		| "F" :: _ -> false
		| x :: _   -> raise (Invalid_argument x)
		| _        -> raise Invalid_Cmd_Args
		in
	let success =
		Connection.end_transaction con (Transaction.get_id t) commit in
	if not success then
		raise Transaction_again;
	if commit then
		process_watch (List.rev (Transaction.get_ops t)) cons

let do_introduce con t domains cons data =
	if not (Connection.is_dom0 con)
	then raise Define.Permission_denied;
	let (domid, mfn, port) =
		match (split None '\000' data) with
		| domid :: mfn :: port :: _ ->
			int_of_string domid, Nativeint.of_string mfn, int_of_string port
		| _                         -> raise Invalid_Cmd_Args;
		in
	let dom =
		if Domains.exist domains domid then
			Domains.find domains domid
		else try
			let ndom = Xenctrl.with_intf (fun xc ->
				Domains.create xc domains domid mfn port) in
			Connections.add_domain cons ndom;
			Connections.fire_spec_watches cons "@introduceDomain";
			ndom
		with _ -> raise Invalid_Cmd_Args
	in
	if (Domain.get_remote_port dom) <> port || (Domain.get_mfn dom) <> mfn then
		raise Domain_not_match

let do_release con t domains cons data =
	if not (Connection.is_dom0 con)
	then raise Define.Permission_denied;
	let domid =
		match (split None '\000' data) with
		| [domid;""] -> int_of_string domid
		| _          -> raise Invalid_Cmd_Args
		in
	let fire_spec_watches = Domains.exist domains domid in
	Domains.del domains domid;
	Connections.del_domain cons domid;
	if fire_spec_watches 
	then Connections.fire_spec_watches cons "@releaseDomain"
	else raise Invalid_Cmd_Args

let do_resume con t domains cons data =
	if not (Connection.is_dom0 con)
	then raise Define.Permission_denied;
	let domid =
		match (split None '\000' data) with
		| domid :: _ -> int_of_string domid
		| _          -> raise Invalid_Cmd_Args
		in
	if Domains.exist domains domid
	then Domains.resume domains domid
	else raise Invalid_Cmd_Args

let do_getdomainpath con t domains cons data =
	let domid =
		match (split None '\000' data) with
		| domid :: "" :: [] -> c_int_of_string domid
		| _                 -> raise Invalid_Cmd_Args
		in
	sprintf "/local/domain/%u\000" domid

let do_write con t domains cons data =
	let path, value =
		match (split (Some 2) '\000' data) with
		| path :: value :: [] -> Store.Path.create path (Connection.get_path con), value
		| _                   -> raise Invalid_Cmd_Args
		in
	create_implicit_path t (Connection.get_perm con) path;
	Transaction.write t (Connection.get_perm con) path value

let do_mkdir con t domains cons data =
	let path = split_one_path data con in
	create_implicit_path t (Connection.get_perm con) path;
	try
		Transaction.mkdir t (Connection.get_perm con) path
	with
		Define.Already_exist -> ()

let do_rm con t domains cons data =
	let path = split_one_path data con in
	try
		Transaction.rm t (Connection.get_perm con) path
	with
		Define.Doesnt_exist -> ()

let do_setperms con t domains cons data =
	let path, perms =
		match (split (Some 2) '\000' data) with
		| path :: perms :: _ ->
			Store.Path.create path (Connection.get_path con),
			(Perms.Node.of_string perms)
		| _                   -> raise Invalid_Cmd_Args
		in
	Transaction.setperms t (Connection.get_perm con) path perms

let do_error con t domains cons data =
	raise Define.Unknown_operation

let do_isintroduced con t domains cons data =
	let domid =
		match (split None '\000' data) with
		| domid :: _ -> int_of_string domid
		| _          -> raise Invalid_Cmd_Args
		in
	if domid = Define.domid_self || Domains.exist domains domid then "T\000" else "F\000"

(* [restrict] is in the patch queue since xen3.2 *)
let do_restrict con t domains cons data =
	if not (Connection.is_dom0 con)
	then raise Define.Permission_denied;
	let domid =
		match (split None '\000' data) with
		| [ domid; "" ] -> c_int_of_string domid
		| _          -> raise Invalid_Cmd_Args
	in
	Connection.restrict con domid

(* only in xen >= 4.2 *)
let do_reset_watches con t domains cons data =
  Connection.del_watches con;
  Connection.del_transactions con

(* only in >= xen3.3                                                                                    *)
(* we ensure backward compatibility with restrict by counting the number of argument of set_target ...  *)
(* This is not very elegant, but it is safe as 'restrict' only restricts permission of dom0 connections *)
let do_set_target con t domains cons data =
	if not (Connection.is_dom0 con)
	then raise Define.Permission_denied;
	match split None '\000' data with
		| [ domid; "" ]               -> do_restrict con t domains con data (* backward compatibility with xen3.2-pq *)
		| [ domid; target_domid; "" ] -> Connections.set_target cons (c_int_of_string domid) (c_int_of_string target_domid)
		| _                           -> raise Invalid_Cmd_Args

(*------------- Generic handling of ty ------------------*)
let reply_ack fct ty con t rid doms cons data =
	fct con t doms cons data;
	Connection.send_ack con (Transaction.get_id t) rid ty;
	if Transaction.get_id t = Transaction.none then
		process_watch (Transaction.get_ops t) cons

let reply_data fct ty con t rid doms cons data =
	let ret = fct con t doms cons data in
	Connection.send_reply con (Transaction.get_id t) rid ty ret

let reply_data_or_ack fct ty con t rid doms cons data =
	match fct con t doms cons data with
		| Some ret -> Connection.send_reply con (Transaction.get_id t) rid ty ret
		| None -> Connection.send_ack con (Transaction.get_id t) rid ty

let reply_none fct ty con t rid doms cons data =
	(* let the function reply *)
	fct con t rid doms cons data

let function_of_type ty =
	match ty with
	| Xenbus.Xb.Op.Debug             -> reply_data_or_ack do_debug
	| Xenbus.Xb.Op.Directory         -> reply_data do_directory
	| Xenbus.Xb.Op.Read              -> reply_data do_read
	| Xenbus.Xb.Op.Getperms          -> reply_data do_getperms
	| Xenbus.Xb.Op.Watch             -> reply_none do_watch
	| Xenbus.Xb.Op.Unwatch           -> reply_ack do_unwatch
	| Xenbus.Xb.Op.Transaction_start -> reply_data do_transaction_start
	| Xenbus.Xb.Op.Transaction_end   -> reply_ack do_transaction_end
	| Xenbus.Xb.Op.Introduce         -> reply_ack do_introduce
	| Xenbus.Xb.Op.Release           -> reply_ack do_release
	| Xenbus.Xb.Op.Getdomainpath     -> reply_data do_getdomainpath
	| Xenbus.Xb.Op.Write             -> reply_ack do_write
	| Xenbus.Xb.Op.Mkdir             -> reply_ack do_mkdir
	| Xenbus.Xb.Op.Rm                -> reply_ack do_rm
	| Xenbus.Xb.Op.Setperms          -> reply_ack do_setperms
	| Xenbus.Xb.Op.Isintroduced      -> reply_data do_isintroduced
	| Xenbus.Xb.Op.Resume            -> reply_ack do_resume
	| Xenbus.Xb.Op.Set_target        -> reply_ack do_set_target
	| Xenbus.Xb.Op.Restrict          -> reply_ack do_restrict
	| Xenbus.Xb.Op.Reset_watches     -> reply_ack do_reset_watches
	| Xenbus.Xb.Op.Invalid           -> reply_ack do_error
	| _                              -> reply_ack do_error

let input_handle_error ~cons ~doms ~fct ~ty ~con ~t ~rid ~data =
	let reply_error e =
		Connection.send_error con (Transaction.get_id t) rid e in
	try
		fct ty con t rid doms cons data
	with
	| Define.Invalid_path          -> reply_error "EINVAL"
	| Define.Already_exist         -> reply_error "EEXIST"
	| Define.Doesnt_exist          -> reply_error "ENOENT"
	| Define.Lookup_Doesnt_exist s -> reply_error "ENOENT"
	| Define.Permission_denied     -> reply_error "EACCES"
	| Not_found                    -> reply_error "ENOENT"
	| Invalid_Cmd_Args             -> reply_error "EINVAL"
	| Invalid_argument i           -> reply_error "EINVAL"
	| Transaction_again            -> reply_error "EAGAIN"
	| Transaction_nested           -> reply_error "EBUSY"
	| Domain_not_match             -> reply_error "EINVAL"
	| Quota.Limit_reached          -> reply_error "EQUOTA"
	| Quota.Data_too_big           -> reply_error "E2BIG"
	| Quota.Transaction_opened     -> reply_error "EQUOTA"
	| (Failure "int_of_string")    -> reply_error "EINVAL"
	| Define.Unknown_operation     -> reply_error "ENOSYS"

(**
 * Nothrow guarantee.
 *)
let process_packet ~store ~cons ~doms ~con ~tid ~rid ~ty ~data =
	try
		let fct = function_of_type ty in
		let t =
			if tid = Transaction.none then
				Transaction.make tid store
			else
				Connection.get_transaction con tid
			in
		input_handle_error ~cons ~doms ~fct ~ty ~con ~t ~rid ~data;
	with exn ->
		error "process packet: %s" (Printexc.to_string exn);
		Connection.send_error con tid rid "EIO"

let write_access_log ~ty ~tid ~con ~data =
	Logging.xb_op ~ty ~tid ~con:(Connection.get_domstr con) data

let write_answer_log ~ty ~tid ~con ~data =
	Logging.xb_answer ~ty ~tid ~con:(Connection.get_domstr con) data

let do_input store cons doms con =
	let newpacket =
		try
			Connection.do_input con
		with Xenbus.Xb.Reconnect ->
			info "%s requests a reconnect" (Connection.get_domstr con);
			Connection.reconnect con;
			info "%s reconnection complete" (Connection.get_domstr con);
			false
		| Failure exp ->
			error "caught exception %s" exp;
			error "got a bad client %s" (sprintf "%-8s" (Connection.get_domstr con));
			Connection.mark_as_bad con;
			false
	in

	if newpacket then (
		let packet = Connection.pop_in con in
		let tid, rid, ty, data = Xenbus.Xb.Packet.unpack packet in
		(* As we don't log IO, do not call an unnecessary sanitize_data 
		   info "[%s] -> [%d] %s \"%s\""
		         (Connection.get_domstr con) tid
		         (Xenbus.Xb.Op.to_string ty) (sanitize_data data); *)
		process_packet ~store ~cons ~doms ~con ~tid ~rid ~ty ~data;
		write_access_log ~ty ~tid ~con ~data;
		Connection.incr_ops con;
	)

let do_output store cons doms con =
	if Connection.has_output con then (
		if Connection.has_new_output con then (
			let packet = Connection.peek_output con in
			let tid, rid, ty, data = Xenbus.Xb.Packet.unpack packet in
			(* As we don't log IO, do not call an unnecessary sanitize_data 
			   info "[%s] <- %s \"%s\""
			         (Connection.get_domstr con)
			         (Xenbus.Xb.Op.to_string ty) (sanitize_data data);*)
			write_answer_log ~ty ~tid ~con ~data;
		);
		try
			ignore (Connection.do_output con)
		with Xenbus.Xb.Reconnect ->
			info "%s requests a reconnect" (Connection.get_domstr con);
			Connection.reconnect con;
			info "%s reconnection complete" (Connection.get_domstr con)
	)

