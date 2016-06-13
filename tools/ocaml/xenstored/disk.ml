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

let enable = ref false
let xs_daemon_database = Paths.xen_run_stored ^ "/db"

let error fmt = Logging.error "disk" fmt

(* unescape utils *)
exception Bad_escape

let is_digit c = match c with '0' .. '9' -> true | _ -> false

let undec c =
	match c with
	| '0' .. '9' -> (Char.code c) - (Char.code '0')
	| _          -> raise (Failure "undecify")

let unhex c =
	let c = Char.lowercase c in
	match c with
	| '0' .. '9' -> (Char.code c) - (Char.code '0')
	| 'a' .. 'f' -> (Char.code c) - (Char.code 'a') + 10
	| _          -> raise (Failure "unhexify")

let string_unescaped s =
	let len = String.length s
	and i = ref 0 in
	let d = Buffer.create len in

	let read_escape () =
		incr i;
		match s.[!i] with
		| 'n'  -> '\n'
		| 'r'  -> '\r'
		| '\\' -> '\\'
		| '\'' -> '\''
		| '"'  -> '"'
		| 't'  -> '\t'
		| 'b'  -> '\b'
		| 'x'  ->
			let v = (unhex s.[!i + 1] * 16) + unhex s.[!i + 2] in
			i := !i + 2;
			Char.chr v
		| c    ->
			if is_digit c then (
				let v = (undec s.[!i]) * 100 +
					(undec s.[!i + 1]) * 10 +
					(undec s.[!i + 2]) in
				i := !i + 2;
				Char.chr v
			) else
				raise Bad_escape
	in

	while !i < len
	do
		let c = match s.[!i] with
		| '\\' -> read_escape ()
		| c    -> c in
		Buffer.add_char d c;
		incr i
	done;
	Buffer.contents d

(* file -> lines_of_file *)
let file_readlines file =
	let channel = open_in file in
	let rec input_line_list channel =
		let line = try input_line channel with End_of_file -> "" in
		if String.length line > 0 then
			line :: input_line_list channel
		else (
			close_in channel;
			[]
		) in
	input_line_list channel

let rec map_string_list_range l s =
	match l with
	| [] -> []
	| (a,b) :: l -> String.sub s a (b - a) :: map_string_list_range l s

let is_digit c =
	try ignore (int_of_char c); true with _ -> false

let rec parse_perm s =
	let len = String.length s in
	if len = 0 then
		[]
	else
		let i = ref 1 in
		while !i < len && is_digit s.[!i] do incr i done;
		let x = String.sub s 0 !i
		and lx = String.sub s !i len in
		x :: parse_perm lx

let read store =
	(* don't let the permission get on our way, full perm ! *)
	let v = Store.get_ops store Perms.Connection.full_rights in

	(* a line is : path{perm} or path{perm} = value *)
	let parse_line s =
		let path, perm, value =
			let len = String.length s in
			let si = if String.contains s '=' then
					String.index s '='
				else
					len - 1 in
			let pi = String.rindex_from s si '{' in
			let epi = String.index_from s pi '}' in

			if String.contains s '=' then
				let ss = map_string_list_range [ (0, pi);
				                                 (pi + 1, epi);
				                                 (si + 2, len); ] s in
				(List.nth ss 0, List.nth ss 1, List.nth ss 2)
			else
				let ss = map_string_list_range [ (0, pi);
				                                 (pi + 1, epi);
				                               ] s in
				(List.nth ss 0, List.nth ss 1, "")
			in
		let path = Store.Path.of_string path in
		v.Store.write path (string_unescaped value);
		v.Store.setperms path (Perms.Node.of_strings (parse_perm perm)) in
	try
		let lines = file_readlines xs_daemon_database in
		List.iter (fun s -> parse_line s) lines
	with exc ->
		error "caught exn %s" (Printexc.to_string exc)

let write store =
	if !enable then
	try
		let tfile = Printf.sprintf "%s#" xs_daemon_database in
		let channel = open_out_gen [ Open_wronly; Open_creat; Open_trunc; ]
		                           0o600 tfile in
		Store.dump store channel;
		flush channel;
		close_out channel;
		Unix.rename tfile xs_daemon_database
	with exc ->
		error "caught exn %s" (Printexc.to_string exc)
