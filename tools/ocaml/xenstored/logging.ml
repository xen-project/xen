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

let error fmt = Logs.error "general" fmt
let info fmt = Logs.info "general" fmt
let debug fmt = Logs.debug "general" fmt

let access_log_file = ref "/var/log/xenstored-access.log"
let access_log_nb_files = ref 20
let access_log_nb_lines = ref 13215
let activate_access_log = ref true

(* maximal size of the lines in xenstore-acces.log file *)
let line_size = 180

let log_read_ops = ref false
let log_transaction_ops = ref false
let log_special_ops = ref false

type access_type =
	| Coalesce
	| Conflict
	| Commit
	| Newconn
	| Endconn
	| XbOp of Xenbus.Xb.Op.operation

type access =
	{
		fd: out_channel ref;
		counter: int ref;
		write: tid:int -> con:string -> ?data:string -> access_type -> unit;
	}

let string_of_date () =
	let time = Unix.gettimeofday () in
	let tm = Unix.localtime time in
	let msec = time -. (floor time) in
	sprintf "%d%.2d%.2d %.2d:%.2d:%.2d.%.3d" (1900 + tm.Unix.tm_year)
		(tm.Unix.tm_mon + 1)
		tm.Unix.tm_mday
		tm.Unix.tm_hour
		tm.Unix.tm_min
		tm.Unix.tm_sec
		(int_of_float (1000.0 *. msec))

let fill_with_space n s =
	if String.length s < n
	then 
		let r = String.make n ' ' in
		String.blit s 0  r 0 (String.length s);
		r
	else 
		s

let string_of_tid ~con tid =
	if tid = 0
	then fill_with_space 12 (sprintf "%s" con)
	else fill_with_space 12 (sprintf "%s.%i" con tid)

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

	| x                       -> Xenbus.Xb.Op.to_string x

let file_exists file =
	try
		Unix.close (Unix.openfile file [Unix.O_RDONLY] 0o644);
		true
	with _ ->
		false

let log_rotate fd =
	let file n = sprintf "%s.%i" !access_log_file n in
	let log_files =
		let rec aux accu n =
			if n >= !access_log_nb_files
			then accu
			else if n = 1 && file_exists !access_log_file
			then aux [!access_log_file,1] 2
			else
				let file = file (n-1) in
				if file_exists file
				then aux ((file,n) :: accu) (n+1)
				else accu
		in
		aux [] 1
	in
	let rec rename = function
		| (f,n) :: t when n < !access_log_nb_files -> 
			Unix.rename f (file n);
			rename t
		| _ -> ()
	in
	rename log_files;
	close_out !fd;
	fd := open_out !access_log_file

let sanitize_data data =
	let data = String.copy data in
	for i = 0 to String.length data - 1
	do
		if data.[i] = '\000' then
			data.[i] <- ' '
	done;
	String.escaped data

let make save_to_disk =
	let fd = ref (open_out_gen [Open_append; Open_creat] 0o644 !access_log_file) in
	let counter = ref 0 in
	{
		fd = fd;
		counter = counter;
		write = 
			if not !activate_access_log || !access_log_nb_files = 0
			then begin fun ~tid ~con ?data _ -> () end
			else fun ~tid ~con ?(data="") access_type ->
				let s = Printf.sprintf "[%s] %s %s %s\n" (string_of_date()) (string_of_tid ~con tid) 
					(string_of_access_type access_type) (sanitize_data data) in
				let s =
					if String.length s > line_size
					then begin
						let s = String.sub s 0 line_size in
						s.[line_size-3] <- '.'; 
						s.[line_size-2] <- '.';
						s.[line_size-1] <- '\n';
						s
					end else
						s
				in
				incr counter;
				output_string !fd s;
				flush !fd;
				if !counter > !access_log_nb_lines 
				then begin 
					log_rotate fd;
					save_to_disk ();
					counter := 0;
				end
	}

let access : (access option) ref = ref None
let init aal save_to_disk =
	activate_access_log := aal;
	access := Some (make save_to_disk)

let write_access_log ~con ~tid ?data access_type = 
        try
	  maybe (fun a -> a.write access_type ~con ~tid ?data) !access
	with _ -> ()

let new_connection = write_access_log Newconn
let end_connection = write_access_log Endconn
let read_coalesce ~tid ~con data =
	if !log_read_ops
	then write_access_log Coalesce ~tid ~con ~data:("read "^data)
let write_coalesce data = write_access_log Coalesce ~data:("write "^data)
let conflict = write_access_log Conflict
let commit = write_access_log Commit

let xb_op ~tid ~con ~ty data =
	let print =
	match ty with
		| Xenbus.Xb.Op.Read | Xenbus.Xb.Op.Directory | Xenbus.Xb.Op.Getperms -> !log_read_ops
		| Xenbus.Xb.Op.Transaction_start | Xenbus.Xb.Op.Transaction_end ->
			false (* transactions are managed below *)
		| Xenbus.Xb.Op.Introduce | Xenbus.Xb.Op.Release | Xenbus.Xb.Op.Getdomainpath | Xenbus.Xb.Op.Isintroduced | Xenbus.Xb.Op.Resume ->
			!log_special_ops
		| _ -> true
	in
		if print 
		then write_access_log ~tid ~con ~data (XbOp ty)

let start_transaction ~tid ~con = 
	if !log_transaction_ops && tid <> 0
	then write_access_log ~tid ~con (XbOp Xenbus.Xb.Op.Transaction_start)

let end_transaction ~tid ~con = 
	if !log_transaction_ops && tid <> 0
	then write_access_log ~tid ~con (XbOp Xenbus.Xb.Op.Transaction_end)

let xb_answer ~tid ~con ~ty data =
	let print = match ty with
		| Xenbus.Xb.Op.Error when data="ENOENT " -> !log_read_ops
		| Xenbus.Xb.Op.Error -> !log_special_ops
		| Xenbus.Xb.Op.Watchevent -> true
		| _ -> false
	in
		if print
		then write_access_log ~tid ~con ~data (XbOp ty)
