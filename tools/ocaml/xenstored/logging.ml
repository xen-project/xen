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

type log_destination =
	| File of string
	| Syslog of Syslog.facility

let log_destination_of_string s =
	let prefix = "syslog:" in
	let len_prefix = String.length prefix in
	let len = String.length s in
	if String.startswith prefix s
	then Syslog(Syslog.facility_of_string (String.sub s len_prefix (len - len_prefix)))
	else File s

(* The prefix of a log line depends on the log destination *)
let prefix log_destination ?level ?key date = match log_destination with
	| File _ ->
		let level = match level with
			| Some x -> Printf.sprintf "|%5s" x
			| None -> "" in
		let key = match key with
			| Some x -> "|" ^ x
			| None -> "" in
		Printf.sprintf "[%s%s%s] " date level key
	| Syslog _ ->
		let key = match key with
			| Some x -> "[" ^ x ^ "] "
			| None -> "" in
		(* Syslog handles the date and level internally *)
		key

type level = Debug | Info | Warn | Error | Null

type logger =
		{ stop: unit -> unit;
		  restart: unit -> unit;
		  rotate: unit -> unit;
		  write: ?level:level -> string -> unit }

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

let make_file_logger log_file log_nb_files log_nb_lines log_nb_chars post_rotate =
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
	let write ?level s =
		let s = if log_nb_chars > 0 then truncate_line log_nb_chars s else s in
		let s = s ^ "\n" in
		output_string !channel s;
		flush !channel;
		incr counter;
		if !counter > log_nb_lines then rotate() in
	{ stop=stop; restart=restart; rotate=rotate; write=write }

exception Unknown_level of string

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

(* We can defer to syslog for log management *)
let make_syslog_logger facility =
	(* When TZ is unset in the environment, each syslog call will stat the
	   /etc/localtime file at least three times during the process. We'd like to
	   avoid this cost given that we are not a mobile environment and we log
	   almost every xenstore entry update/watch. *)
	let () =
		let tz_is_set =
			try String.length (Unix.getenv "TZ") > 0
			with Not_found -> false in
		if not tz_is_set then Unix.putenv "TZ" "/etc/localtime" in
	let nothing () = () in
	let write ?level s =
		let level = match level with
			| Some Error -> Syslog.Err
			| Some Warn -> Syslog.Warning
			| Some Info -> Syslog.Info
			| Some Debug -> Syslog.Debug
			| Some Null -> Syslog.Debug
			| None -> Syslog.Debug in
		(* Syslog handles the date and level internally *)
		Syslog.log facility level s in
	{ stop = nothing; restart = nothing; rotate = nothing; write=write }

let xenstored_log_destination = ref (File "/var/log/xenstored.log")
let xenstored_log_level = ref Warn
let xenstored_log_nb_files = ref 10
let xenstored_log_nb_lines = ref 13215
let xenstored_log_nb_chars = ref (-1)
let xenstored_logger = ref (None: logger option)

let set_xenstored_log_destination s =
	xenstored_log_destination := log_destination_of_string s

let set_xenstored_logger logger =
	xenstored_logger := Some logger;
	logger.write ~level:Info (Printf.sprintf "Xen Storage Daemon, version %d.%d"
	Define.xenstored_major Define.xenstored_minor)


let init_xenstored_log () = match !xenstored_log_destination with
	| File file ->
		if !xenstored_log_level <> Null && !xenstored_log_nb_files > 0 then
			let logger =
				make_file_logger 
					file !xenstored_log_nb_files !xenstored_log_nb_lines
					!xenstored_log_nb_chars ignore in
			set_xenstored_logger logger
	| Syslog facility ->
		set_xenstored_logger (make_syslog_logger facility)


let xenstored_logging level key (fmt: (_,_,_,_) format4) =
	match !xenstored_logger with
	| Some logger when int_of_level level >= int_of_level !xenstored_log_level ->
			let date = string_of_date() in
			let level' = string_of_level level in
			let prefix = prefix !xenstored_log_destination ~level:level' ~key date in
			Printf.ksprintf (fun s -> logger.write ~level (prefix ^ s)) fmt
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
	| Xenbus.Xb.Op.Invalid           -> "invalid  "
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
let access_log_destination = ref (File "/var/log/xenstored-access.log")
let access_log_nb_files = ref 20
let access_log_nb_lines = ref 13215
let access_log_nb_chars = ref 180
let access_log_read_ops = ref false
let access_log_transaction_ops = ref false
let access_log_special_ops = ref false
let access_logger = ref None

let set_access_log_destination s =
	access_log_destination := log_destination_of_string s

let init_access_log post_rotate = match !access_log_destination with
	| File file ->
		if !access_log_nb_files > 0 then
			let logger =
				make_file_logger
					file !access_log_nb_files !access_log_nb_lines
					!access_log_nb_chars post_rotate in
			access_logger := Some logger
	| Syslog facility ->
		access_logger := Some (make_syslog_logger facility)

let access_logging ~con ~tid ?(data="") ~level access_type =
        try
		maybe
			(fun logger ->
				let date = string_of_date() in
				let tid = string_of_tid ~con tid in
				let access_type = string_of_access_type access_type in
				let data = sanitize_data data in
				let prefix = prefix !access_log_destination date in
				let msg = Printf.sprintf "%s %s %s %s" prefix tid access_type data in
				logger.write ~level msg)
			!access_logger
	with _ -> ()

let new_connection = access_logging ~level:Debug Newconn
let end_connection = access_logging ~level:Debug Endconn
let read_coalesce ~tid ~con data =
	if !access_log_read_ops
        then access_logging Coalesce ~tid ~con ~data:("read "^data) ~level:Debug
let write_coalesce data = access_logging Coalesce ~data:("write "^data) ~level:Debug
let conflict = access_logging Conflict ~level:Debug
let commit = access_logging Commit ~level:Debug

let xb_op ~tid ~con ~ty data =
	let print = match ty with
		| Xenbus.Xb.Op.Read | Xenbus.Xb.Op.Directory | Xenbus.Xb.Op.Getperms -> !access_log_read_ops
		| Xenbus.Xb.Op.Transaction_start | Xenbus.Xb.Op.Transaction_end ->
			false (* transactions are managed below *)
		| Xenbus.Xb.Op.Introduce | Xenbus.Xb.Op.Release | Xenbus.Xb.Op.Getdomainpath | Xenbus.Xb.Op.Isintroduced | Xenbus.Xb.Op.Resume ->
			!access_log_special_ops
		| _ -> true in
	if print then access_logging ~tid ~con ~data (XbOp ty) ~level:Info

let start_transaction ~tid ~con = 
	if !access_log_transaction_ops && tid <> 0
	then access_logging ~tid ~con (XbOp Xenbus.Xb.Op.Transaction_start) ~level:Debug

let end_transaction ~tid ~con = 
	if !access_log_transaction_ops && tid <> 0
	then access_logging ~tid ~con (XbOp Xenbus.Xb.Op.Transaction_end) ~level:Debug

let xb_answer ~tid ~con ~ty data =
	let print, level = match ty with
		| Xenbus.Xb.Op.Error when String.startswith "ENOENT" data -> !access_log_read_ops , Warn
		| Xenbus.Xb.Op.Error -> true , Warn
		| Xenbus.Xb.Op.Watchevent -> true , Info
		| _ -> false, Debug
	in
	if print then access_logging ~tid ~con ~data (XbOp ty) ~level
