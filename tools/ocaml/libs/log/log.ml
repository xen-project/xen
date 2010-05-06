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

exception Unknown_level of string

type stream_type = Stderr | Stdout | File of string

type stream_log = {
  ty : stream_type;
  channel : out_channel option ref;
}

type level = Debug | Info | Warn | Error

type output =
	| Stream of stream_log
	| String of string list ref
	| Syslog of string
	| Nil

let int_of_level l =
	match l with Debug -> 0 | Info -> 1 | Warn -> 2 | Error -> 3

let string_of_level l =
	match l with Debug -> "debug" | Info -> "info"
	           | Warn -> "warn" | Error -> "error"

let level_of_string s =
	match s with
	| "debug" -> Debug
	| "info"  -> Info
	| "warn"  -> Warn
	| "error" -> Error
	| _       -> raise (Unknown_level s)

let mkdir_safe dir perm =
        try Unix.mkdir dir perm with _ -> ()

let mkdir_rec dir perm =
	let rec p_mkdir dir =
		let p_name = Filename.dirname dir in
		if p_name = "/" || p_name = "." then
			()
		else (
			p_mkdir p_name;
			mkdir_safe dir perm
		) in
	p_mkdir dir

type t = { output: output; mutable level: level; }

let make output level = { output = output; level = level; }

let make_stream ty channel = 
        Stream {ty=ty; channel=ref channel; }

(** open a syslog logger *)
let opensyslog k level =
	make (Syslog k) level

(** open a stderr logger *)
let openerr level =
	if (Unix.stat "/dev/stderr").Unix.st_kind <> Unix.S_CHR then
		failwith "/dev/stderr is not a valid character device";
	make (make_stream Stderr (Some (open_out "/dev/stderr"))) level
	
let openout level =
	if (Unix.stat "/dev/stdout").Unix.st_kind <> Unix.S_CHR then
		failwith "/dev/stdout is not a valid character device";
        make (make_stream Stdout (Some (open_out "/dev/stdout"))) level


(** open a stream logger - returning the channel. *)
(* This needs to be separated from 'openfile' so we can reopen later *)
let doopenfile filename =
        if Filename.is_relative filename then
	        None
	else (
                try
		  mkdir_rec (Filename.dirname filename) 0o700;
	          Some (open_out_gen [ Open_append; Open_creat ] 0o600 filename)
                with _ -> None
	)

(** open a stream logger - returning the output type *)
let openfile filename level =
        make (make_stream (File filename) (doopenfile filename)) level

(** open a nil logger *)
let opennil () =
	make Nil Error

(** open a string logger *)
let openstring level =
        make (String (ref [""])) level

(** try to reopen a logger *)
let reopen t =
	match t.output with
	| Nil              -> t
	| Syslog k         -> Syslog.close (); opensyslog k t.level
	| Stream s         -> (
	      match (s.ty,!(s.channel)) with 
		| (File filename, Some c) -> close_out c; s.channel := (try doopenfile filename with _ -> None); t 
		| _ -> t)
	| String _         -> t

(** close a logger *)
let close t =
	match t.output with
	| Nil           -> ()
	| Syslog k      -> Syslog.close ();
	| Stream s      -> (
	      match !(s.channel) with 
		| Some c -> close_out c; s.channel := None
		| None -> ())
	| String _      -> ()

(** create a string representating the parameters of the logger *)
let string_of_logger t =
	match t.output with
	| Nil           -> "nil"
	| Syslog k      -> sprintf "syslog:%s" k
	| String _      -> "string"
	| Stream s      -> 
	    begin
	      match s.ty with 
		| File f -> sprintf "file:%s" f
		| Stderr -> "stderr"
		| Stdout -> "stdout"
	    end

(** parse a string to a logger *)
let logger_of_string s : t =
	match s with
	| "nil"    -> opennil ()
	| "stderr" -> openerr Debug
	| "stdout" -> openout Debug
	| "string" -> openstring Debug
	| _        ->
		let split_in_2 s =
			try
				let i = String.index s ':' in
				String.sub s 0 (i),
				String.sub s (i + 1) (String.length s - i - 1)
			with _ ->
				failwith "logger format error: expecting string:string"
			in
		let k, s = split_in_2 s in
		match k with
		| "syslog" -> opensyslog s Debug
		| "file"   -> openfile s Debug
		| _        -> failwith "unknown logger type"

let validate s =
	match s with
	| "nil"    -> ()
	| "stderr" -> ()
	| "stdout" -> ()
	| "string" -> ()
	| _        ->
		let split_in_2 s =
			try
				let i = String.index s ':' in
				String.sub s 0 (i),
				String.sub s (i + 1) (String.length s - i - 1)
			with _ ->
				failwith "logger format error: expecting string:string"
			in
		let k, s = split_in_2 s in
		match k with
		| "syslog" -> ()
		| "file"   -> (
			try
				let st = Unix.stat s in
				if st.Unix.st_kind <> Unix.S_REG then
					failwith "logger file is a directory";
				()
			with Unix.Unix_error (Unix.ENOENT, _, _) -> ()
			)
		| _        -> failwith "unknown logger"

(** change a logger level to level *)
let set t level = t.level <- level

let gettimestring () =
	let time = Unix.gettimeofday () in
	let tm = Unix.localtime time in
        let msec = time -. (floor time) in
	sprintf "%d%.2d%.2d %.2d:%.2d:%.2d.%.3d|" (1900 + tm.Unix.tm_year)
	        (tm.Unix.tm_mon + 1) tm.Unix.tm_mday
	        tm.Unix.tm_hour tm.Unix.tm_min tm.Unix.tm_sec
	        (int_of_float (1000.0 *. msec))

(*let extra_hook = ref (fun x -> x)*)

let output t ?(key="") ?(extra="") priority (message: string) =
  let construct_string withtime =
		(*let key = if key = "" then [] else [ key ] in
		let extra = if extra = "" then [] else [ extra ] in
		let items = 
      (if withtime then [ gettimestring () ] else [])
		  @ [ sprintf "%5s" (string_of_level priority) ] @ extra @ key @ [ message ] in
(*		let items = !extra_hook items in*)
		String.concat " " items*)
    Printf.sprintf "[%s%s|%s] %s" 
      (if withtime then gettimestring () else "") (string_of_level priority) extra message
	in
	(* Keep track of how much we write out to streams, so that we can *)
	(* log-rotate at appropriate times *)
	let write_to_stream stream =
	  let string = (construct_string true) in
	  try
	    fprintf stream "%s\n%!" string
	  with _ -> () (* Trap exception when we fail to write log *)
        in

	if String.length message > 0 then
	match t.output with
	| Syslog k      ->
		let sys_prio = match priority with
		| Debug -> Syslog.Debug
		| Info  -> Syslog.Info
		| Warn  -> Syslog.Warning
		| Error -> Syslog.Err in
		Syslog.log Syslog.Daemon sys_prio ((construct_string false) ^ "\n")
	| Stream s -> (
	      match !(s.channel) with
		| Some c -> write_to_stream c
		| None -> ())
	| Nil           -> ()
	| String s      -> (s := (construct_string true)::!s)

let log t level (fmt: ('a, unit, string, unit) format4): 'a =
	let b = (int_of_level t.level) <= (int_of_level level) in
	(* ksprintf is the preferred name for kprintf, but the former
	 * is not available in OCaml 3.08.3 *)
	Printf.kprintf (if b then output t level else (fun _ -> ())) fmt
	    
let debug t (fmt: ('a , unit, string, unit) format4) = log t Debug fmt
let info t (fmt: ('a , unit, string, unit) format4) = log t Info fmt
let warn t (fmt: ('a , unit, string, unit) format4) = log t Warn fmt
let error t (fmt: ('a , unit, string, unit) format4) = log t Error fmt
