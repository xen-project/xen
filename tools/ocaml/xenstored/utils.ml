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
open Stdext

(* lists utils *)
let filter_out filter l =
	List.filter (fun x -> not (List.mem x filter)) l

let filter_in filter l =
	List.filter (fun x -> List.mem x filter) l

let list_remove element l =
	List.filter (fun e -> e != element) l

let list_tl_multi n l =
	let rec do_tl i x =
		if i = 0 then x else do_tl (i - 1) (List.tl x)
		in
	do_tl n l

(* string utils *)
let get_hierarchy path =
	let l = List.length path in
	let revpath = List.rev path in
	let rec sub i =
		let x = List.rev (list_tl_multi (l - i) revpath) in
		if i = l then [ x ] else x :: sub (i + 1)
		in
	sub 0

let hexify s =
	let hexseq_of_char c = sprintf "%02x" (Char.code c) in
	let hs = Bytes.create (String.length s * 2) in
	for i = 0 to String.length s - 1
	do
		let seq = hexseq_of_char s.[i] in
		Bytes.set hs (i * 2) seq.[0];
		Bytes.set hs (i * 2 + 1) seq.[1];
	done;
	Bytes.to_string hs

let unhexify hs =
	let char_of_hexseq seq0 seq1 = Char.chr (int_of_string (sprintf "0x%c%c" seq0 seq1)) in
	let b = Bytes.create (String.length hs / 2) in
	for i = 0 to Bytes.length b - 1
	do
		Bytes.set b i (char_of_hexseq hs.[i * 2] hs.[i * 2 + 1])
	done;
	Bytes.to_string b

let trim_path path =
	try
		let rindex = String.rindex path '/' in
		String.sub path 0 rindex
	with
		Not_found -> ""

let join_by_null ls = String.concat "\000" ls

(* unix utils *)
let create_unix_socket name =
        Unixext.unlink_safe name;
        Unixext.mkdir_rec (Filename.dirname name) 0o700;
        let sockaddr = Unix.ADDR_UNIX(name) in
        let sock = Unix.socket Unix.PF_UNIX Unix.SOCK_STREAM 0 in
        Unix.bind sock sockaddr;
        Unix.listen sock 1;
        sock

let read_file_single_integer filename =
	let fd = Unix.openfile filename [ Unix.O_RDONLY ] 0o640 in
	let buf = Bytes.make 20 (char_of_int 0) in
	let sz = Unix.read fd buf 0 20 in
	Unix.close fd;
	int_of_string (Bytes.to_string (Bytes.sub buf 0 sz))

let path_complete path connection_path =
	if String.get path 0 <> '/' then
		connection_path ^ path
	else
		path

let path_validate path connection_path =
	if String.length path = 0 || String.length path > 1024 then
		raise Define.Invalid_path
	else
		let cpath = path_complete path connection_path in
		if String.get cpath 0 <> '/' then
			raise Define.Invalid_path
		else
			cpath

