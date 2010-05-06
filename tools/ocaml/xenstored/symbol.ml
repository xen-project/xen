(*
 * Copyright (C) 2006-2007 XenSource Ltd.
 * Copyright (C) 2008      Citrix Ltd.
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

type t = int

type 'a record = { data: 'a; mutable garbage: bool }
let int_string_tbl : (int,string record) Hashtbl.t = Hashtbl.create 1024
let string_int_tbl : (string,int) Hashtbl.t = Hashtbl.create 1024

let created_counter = ref 0
let used_counter = ref 0

let count = ref 0
let rec fresh () =
	if Hashtbl.mem int_string_tbl !count
	then begin
		incr count;
		fresh ()
	end else
		!count

let new_record v = { data=v; garbage=false }

let of_string name =
	if Hashtbl.mem string_int_tbl name
	then begin
		incr used_counter;
		Hashtbl.find string_int_tbl name
	end else begin
		let i = fresh () in
		incr created_counter;
		Hashtbl.add string_int_tbl name i;
		Hashtbl.add int_string_tbl i (new_record name);
		i
	end

let to_string i =
	(Hashtbl.find int_string_tbl i).data

let mark_all_as_unused () =
	Hashtbl.iter (fun _ v -> v.garbage <- true) int_string_tbl

let mark_as_used symb =
	let record1 = Hashtbl.find int_string_tbl symb in
		record1.garbage <- false

let garbage () =
	let records = Hashtbl.fold (fun symb record accu ->
		if record.garbage then (symb, record.data) :: accu else accu
	) int_string_tbl [] in
	let remove (int,string) =
		Hashtbl.remove int_string_tbl int;
		Hashtbl.remove string_int_tbl string
	in
	created_counter := 0;
	used_counter := 0;
	List.iter remove records

let stats () =
	Hashtbl.length string_int_tbl

let created () = !created_counter
let used () = !used_counter
