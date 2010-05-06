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

type ty =
	| Set_bool of bool ref
	| Set_int of int ref
	| Set_string of string ref
	| Set_float of float ref
	| Unit of (unit -> unit)
	| Bool of (bool -> unit)
	| Int of (int -> unit)
	| String of (string -> unit)
	| Float of (float -> unit)

exception Error of (string * string) list

let trim_start lc s =
	let len = String.length s and i = ref 0 in
	while !i < len && (List.mem s.[!i] lc)
	do
		incr i
	done;
	if !i < len then String.sub s !i (len - !i) else ""

let trim_end lc s =
	let i = ref (String.length s - 1) in
	while !i > 0 && (List.mem s.[!i] lc)
	do
		decr i
	done;
	if !i >= 0 then String.sub s 0 (!i + 1) else ""

let rec split ?limit:(limit=(-1)) c s =
	let i = try String.index s c with Not_found -> -1 in
	let nlimit = if limit = -1 || limit = 0 then limit else limit - 1 in
	if i = -1 || nlimit = 0 then
		[ s ]
	else
		let a = String.sub s 0 i
		and b = String.sub s (i + 1) (String.length s - i - 1) in
		a :: (split ~limit: nlimit c b)

let parse_line stream =
	let lc = [ ' '; '\t' ] in
	let trim_spaces s = trim_end lc (trim_start lc s) in
	let to_config s =
		match split ~limit:2 '=' s with
		| k :: v :: [] -> Some (trim_end lc k, trim_start lc v)
		| _            -> None in
	let rec read_filter_line () =
		try
			let line = trim_spaces (input_line stream) in
			if String.length line > 0 && line.[0] <> '#' then
				match to_config line with
				| None   -> read_filter_line ()
				| Some x -> x :: read_filter_line ()
			else
				read_filter_line ()
		with
			End_of_file -> [] in
	read_filter_line ()

let parse filename =
	let stream = open_in filename in
	let cf = parse_line stream in
	close_in stream;
	cf

let validate cf expected other =
	let err = ref [] in
	let append x = err := x :: !err in
	List.iter (fun (k, v) ->
		try
			if not (List.mem_assoc k expected) then
				other k v
			else let ty = List.assoc k expected in
			match ty with
			| Unit f       -> f ()
			| Bool f       -> f (bool_of_string v)
			| String f     -> f v
			| Int f        -> f (int_of_string v)
			| Float f      -> f (float_of_string v)
			| Set_bool r   -> r := (bool_of_string v)
			| Set_string r -> r := v
			| Set_int r    -> r := int_of_string v
			| Set_float r  -> r := (float_of_string v)
		with
		| Not_found                 -> append (k, "unknown key")
		| Failure "int_of_string"   -> append (k, "expect int arg")
		| Failure "bool_of_string"  -> append (k, "expect bool arg")
		| Failure "float_of_string" -> append (k, "expect float arg")
		| exn                       -> append (k, Printexc.to_string exn)
		) cf;
	if !err != [] then raise (Error !err)

(** read a filename, parse and validate, and return the errors if any *)
let read filename expected other =
	let cf = parse filename in
	validate cf expected other
