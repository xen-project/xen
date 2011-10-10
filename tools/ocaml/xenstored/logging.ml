(*
 * Copyright (C) 2006-2007 XenSource Ltd.
 * Copyright (C) 2008      Citrix Ltd.
 * Author Thomas Gazagnaire <thomas.gazagnaire@citrix.com>
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

open Stdext
open Printf


(* Logger common *)

type logger =
		{ stop: unit -> unit;
		  restart: unit -> unit;
		  rotate: unit -> unit;
		  write: 'a. ('a, unit, string, unit) format4 -> 'a }

let truncate_line nb_chars line = 
	if String.length line > nb_chars - 1 then
		let len = max (nb_chars - 1) 2 in
		let dst_line = String.create len in
		String.blit line 0 dst_line 0 (len - 2);
		dst_line.[len-2] <- '.'; 
		dst_line.[len-1] <- '.';
		dst_line
	else line

let log_rotate ref_ch log_file log_nb_files =
	let file n = sprintf "%s.%i" log_file n in
	let log_files =
		let rec aux accu n =
			if n >= log_nb_files then accu
			else
				if n = 1 && Sys.file_exists log_file
				then aux [log_file,1] 2
				else
					let file = file (n-1) in
					if Sys.file_exists file then
						aux ((file, n) :: accu) (n+1)
					else accu in
		aux [] 1 in
	List.iter (fun (f, n) -> Unix.rename f (file n)) log_files;
	close_out !ref_ch;
	ref_ch := open_out log_file

let make_logger log_file log_nb_files log_nb_lines log_nb_chars post_rotate =
	let channel = ref (open_out_gen [Open_append; Open_creat] 0o644 log_file) in
	let counter = ref 0 in
	let stop() =
		try flush !channel; close_out !channel
		with _ -> () in
	let restart() =
		stop();
		channel := open_out_gen [Open_append; Open_creat] 0o644 log_file in
	let rotate() =
		log_rotate channel log_file log_nb_files;
		(post_rotate (): unit);
		counter := 0 in
	let output s =
		let s = if log_nb_chars > 0 then truncate_line log_nb_chars s else s in
		let s = s ^ "\n" in
		output_string !channel s;
		flush !channel;
		incr counter;
		if !counter > log_nb_lines then rotate() in
	{ stop=stop; restart=restart; rotate=rotate; write = fun fmt -> Printf.ksprintf output fmt }


(* Xenstored logger *) 

exception Unknown_level of string

type level = Debug | Info | Warn | Error | Null

let int_of_level = function
	| Debug -> 0 | Info -> 1 | Warn -> 2
	| Error -> 3 | Null -> max_int

let string_of_level = function
	| Debug -> "debug" | Info -> "info" | Warn -> "warn"
	| Error -> "error" | Null -> "null"

let level_of_string = function
	| "debug" -> Debug | "info"  -> Info | "warn"  -> Warn
	| "error" -> Error | "null"  -> Null | s  -> raise (Unknown_level s)

let string_of_date () =
	let time = Unix.gettimeofday () in
	let tm = Unix.gmtime time in
	let msec = time -. (floor time) in
	sprintf "%d%.2d%.2dT%.2d:%.2d:%.2d.%.3dZ"
		(1900 + tm.Unix.tm_year) (tm.Unix.tm_mon + 1) tm.Unix.tm_mday
		tm.Unix.tm_hour tm.Unix.tm_min tm.Unix.tm_sec
		(int_of_float (1000.0 *. msec))

let xenstored_log_file = ref "/var/log/xenstored.log"
let xenstored_log_level = ref Null
let xenstored_log_nb_files = ref 10
let xenstored_log_nb_lines = ref 13215
let xenstored_log_nb_chars = ref (-1)
let xenstored_logger = ref (None: logger option)

let init_xenstored_log () =
	if !xenstored_log_level <> Null && !xenstored_log_nb_files > 0 then
		let logger =
			make_logger 
				!xenstored_log_file !xenstored_log_nb_files !xenstored_log_nb_lines
				!xenstored_log_nb_chars ignore in
		xenstored_logger := Some logger

let xenstored_logging level key (fmt: (_,_,_,_) format4) =
	match !xenstored_logger with
	| Some logger when int_of_level level >= int_of_level !xenstored_log_level ->
			let date = string_of_date() in
			let level = string_of_level level in
			logger.write ("[%s|%5s|%s] " ^^ fmt) date level key
	| _ -> Printf.ksprintf ignore fmt

let debug key = xenstored_logging Debug key
let info key = xenstored_logging Info key
let warn key = xenstored_logging Warn key
let error key = xenstored_logging Error key

(* Access logger *)

type access_type =
	| Coalesce
	| Conflict
	| Commit
	| Newconn
	| Endconn
	| XbOp of Xenbus.Xb.Op.operation

let string_of_tid ~con tid =
	if tid = 0
	then sprintf "%-12s" con
	else sprintf "%-12s" (sprintf "%s.%i" con tid)

let string_of_access_type = function
	| Coalesce                -> "coalesce "
	| Conflict                -> "conflict "
	| Commit                  -> "commit   "
	| Newconn                 -> "newconn  "
	| Endconn                 -> "endconn  "

	| XbOp op -> match op with
	| Xenbus.Xb.Op.Debug             -> "debug    "

	| Xenbus.Xb.Op.Directory         -> "directory"
	| Xenbus.Xb.Op.Read              -> "read     "
	| Xenbus.Xb.Op.Getperms          -> "getperms "

	| Xenbus.Xb.Op.Watch             -> "watch    "
	| Xenbus.Xb.Op.Unwatch           -> "unwatch  "

	| Xenbus.Xb.Op.Transaction_start -> "t start  "
	| Xenbus.Xb.Op.Transaction_end   -> "t end    "

	| Xenbus.Xb.Op.Introduce         -> "introduce"
	| Xenbus.Xb.Op.Release           -> "release  "
	| Xenbus.Xb.Op.Getdomainpath     -> "getdomain"
	| Xenbus.Xb.Op.Isintroduced      -> "is introduced"
	| Xenbus.Xb.Op.Resume            -> "resume   "
 
	| Xenbus.Xb.Op.Write             -> "write    "
	| Xenbus.Xb.Op.Mkdir             -> "mkdir    "
	| Xenbus.Xb.Op.Rm                -> "rm       "
	| Xenbus.Xb.Op.Setperms          -> "setperms "
	| Xenbus.Xb.Op.Restrict          -> "restrict "
	| Xenbus.Xb.Op.Set_target        -> "settarget"

	| Xenbus.Xb.Op.Error             -> "error    "
	| Xenbus.Xb.Op.Watchevent        -> "w event  "
	(*
	| x                       -> Xenbus.Xb.Op.to_string x
	*)

let sanitize_data data =
	let data = String.copy data in
	for i = 0 to String.length data - 1
	do
		if data.[i] = '\000' then
			data.[i] <- ' '
	done;
	String.escaped data

let activate_access_log = ref true
let access_log_file = ref "/var/log/xenstored-access.log"
let access_log_nb_files = ref 20
let access_log_nb_lines = ref 13215
let access_log_nb_chars = ref 180
let access_log_read_ops = ref false
let access_log_transaction_ops = ref false
let access_log_special_ops = ref false
let access_logger = ref None

let init_access_log post_rotate =
	if !access_log_nb_files > 0 then
		let logger =
			make_logger
				!access_log_file !access_log_nb_files !access_log_nb_lines
				!access_log_nb_chars post_rotate in
		access_logger := Some logger
 
let access_logging ~con ~tid ?(data="") access_type =
        try
		maybe
			(fun logger ->
				let date = string_of_date() in
				let tid = string_of_tid ~con tid in
				let access_type = string_of_access_type access_type in
				let data = sanitize_data data in
				logger.write "[%s] %s %s %s" date tid access_type data)
			!access_logger
	with _ -> ()

let new_connection = access_logging Newconn
let end_connection = access_logging Endconn
let read_coalesce ~tid ~con data =
	if !access_log_read_ops
	then access_logging Coalesce ~tid ~con ~data:("read "^data)
let write_coalesce data = access_logging Coalesce ~data:("write "^data)
let conflict = access_logging Conflict
let commit = access_logging Commit

let xb_op ~tid ~con ~ty data =
	let print = match ty with
		| Xenbus.Xb.Op.Read | Xenbus.Xb.Op.Directory | Xenbus.Xb.Op.Getperms -> !access_log_read_ops
		| Xenbus.Xb.Op.Transaction_start | Xenbus.Xb.Op.Transaction_end ->
			false (* transactions are managed below *)
		| Xenbus.Xb.Op.Introduce | Xenbus.Xb.Op.Release | Xenbus.Xb.Op.Getdomainpath | Xenbus.Xb.Op.Isintroduced | Xenbus.Xb.Op.Resume ->
			!access_log_special_ops
		| _ -> true in
	if print then access_logging ~tid ~con ~data (XbOp ty)

let start_transaction ~tid ~con = 
	if !access_log_transaction_ops && tid <> 0
	then access_logging ~tid ~con (XbOp Xenbus.Xb.Op.Transaction_start)

let end_transaction ~tid ~con = 
	if !access_log_transaction_ops && tid <> 0
	then access_logging ~tid ~con (XbOp Xenbus.Xb.Op.Transaction_end)

let xb_answer ~tid ~con ~ty data =
	let print = match ty with
		| Xenbus.Xb.Op.Error when String.startswith "ENOENT " data -> !access_log_read_ops
		| Xenbus.Xb.Op.Error -> true
		| Xenbus.Xb.Op.Watchevent -> true
		| _ -> false
	in
	if print then access_logging ~tid ~con ~data (XbOp ty)
