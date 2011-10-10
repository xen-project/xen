(*
 * Copyright (C) 2006-2007 XenSource Ltd.
 * Copyright (C) 2008      Citrix Ltd.
 * Author Vincent Hanquez <vincent.hanquez@eu.citrix.com>
 * Author Thomas Gazagnaire <thomas.gazagnaire@eu.citrix.com>
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

let debug fmt = Logs.debug "general" fmt

type t = {
	mutable anonymous: Connection.t list;
	domains: (int, Connection.t) Hashtbl.t;
	mutable watches: (string, Connection.watch list) Trie.t;
}

let create () = { anonymous = []; domains = Hashtbl.create 8; watches = Trie.create () }

let add_anonymous cons fd can_write =
	let xbcon = Xenbus.Xb.open_fd fd in
	let con = Connection.create xbcon None in
	cons.anonymous <- con :: cons.anonymous

let add_domain cons dom =
	let xbcon = Xenbus.Xb.open_mmap (Domain.get_interface dom) (fun () -> Domain.notify dom) in
	let con = Connection.create xbcon (Some dom) in
	Hashtbl.add cons.domains (Domain.get_id dom) con

let select cons =
	let inset = List.map (fun c -> Connection.get_fd c) cons.anonymous
	and outset = List.fold_left (fun l c -> if Connection.has_output c
						then Connection.get_fd c :: l
						else l) [] cons.anonymous in
	inset, outset

let find cons fd =
	List.find (fun c -> Connection.get_fd c = fd) cons.anonymous

let find_domain cons id =
	Hashtbl.find cons.domains id

let del_watches_of_con con watches =
	match List.filter (fun w -> Connection.get_con w != con) watches with
	| [] -> None
	| ws -> Some ws 

let del_anonymous cons con =
	try
		cons.anonymous <- Utils.list_remove con cons.anonymous;
		cons.watches <- Trie.map (del_watches_of_con con) cons.watches;
		Connection.close con
	with exn ->
		debug "del anonymous %s" (Printexc.to_string exn)

let del_domain cons id =
	try
		let con = find_domain cons id in
		Hashtbl.remove cons.domains id;
		cons.watches <- Trie.map (del_watches_of_con con) cons.watches;
		Connection.close con
	with exn ->
		debug "del domain %u: %s" id (Printexc.to_string exn)

let iter_domains cons fct =
	Hashtbl.iter (fun k c -> fct c) cons.domains

let iter_anonymous cons fct =
	List.iter (fun c -> fct c) (List.rev cons.anonymous)

let iter cons fct =
	iter_domains cons fct; iter_anonymous cons fct

let has_more_work cons =
	Hashtbl.fold (fun id con acc ->
		if Connection.has_more_input con then
			con :: acc
		else
			acc) cons.domains []

let key_of_str path =
	if path.[0] = '@'
	then [path]
	else "" :: Store.Path.to_string_list (Store.Path.of_string path)

let key_of_path path =
	"" :: Store.Path.to_string_list path

let add_watch cons con path token =
	let apath, watch = Connection.add_watch con path token in
	let key = key_of_str apath in
	let watches =
 		if Trie.mem cons.watches key
 		then Trie.find cons.watches key
 		else []
	in
 	cons.watches <- Trie.set cons.watches key (watch :: watches);
	watch

let del_watch cons con path token =
 	let apath, watch = Connection.del_watch con path token in
 	let key = key_of_str apath in
 	let watches = Utils.list_remove watch (Trie.find cons.watches key) in
 	if watches = [] then
		cons.watches <- Trie.unset cons.watches key
 	else
		cons.watches <- Trie.set cons.watches key watches;
 	watch

(* path is absolute *)
let fire_watches cons path recurse =
	let key = key_of_path path in
	let path = Store.Path.to_string path in
	let fire_watch _ = function
		| None         -> ()
		| Some watches -> List.iter (fun w -> Connection.fire_watch w path) watches
	in
	let fire_rec x = function
		| None         -> ()
		| Some watches -> 
			  List.iter (fun w -> Connection.fire_single_watch w) watches
	in
	Trie.iter_path fire_watch cons.watches key;
	if recurse then
		Trie.iter fire_rec (Trie.sub cons.watches key)

let fire_spec_watches cons specpath =
	iter cons (fun con ->
		List.iter (fun w -> Connection.fire_single_watch w) (Connection.get_watches con specpath))

let set_target cons domain target_domain =
	let con = find_domain cons domain in
	Connection.set_target con target_domain

let number_of_transactions cons =
	let res = ref 0 in
	let aux con = 
		res := Connection.number_of_transactions con + !res
	in
	iter cons aux;
	!res

let stats cons =
	let nb_ops_anon = ref 0 
	and nb_watchs_anon = ref 0
	and nb_ops_dom = ref 0
	and nb_watchs_dom = ref 0 in
	iter_anonymous cons (fun con ->
		let con_watchs, con_ops = Connection.stats con in
		nb_ops_anon := !nb_ops_anon + con_ops;
		nb_watchs_anon := !nb_watchs_anon + con_watchs;
	);
	iter_domains cons (fun con ->
		let con_watchs, con_ops = Connection.stats con in
		nb_ops_dom := !nb_ops_dom + con_ops;
		nb_watchs_dom := !nb_watchs_dom + con_watchs;
	);
	(List.length cons.anonymous, !nb_ops_anon, !nb_watchs_anon,
	 Hashtbl.length cons.domains, !nb_ops_dom, !nb_watchs_dom)
