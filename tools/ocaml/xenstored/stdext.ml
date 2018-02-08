(*
 * Copyright (C) 2006-2007 XenSource Ltd.
 * Copyright (C) 2008-2010 Citrix Ltd.
 * Author Vincent Hanquez <vincent.hanquez@eu.citrix.com>
 * Author Dave Scott <dave.scott@eu.citrix.com>
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

type ('a, 'b) either = Right of 'a | Left of 'b

(** apply the clean_f function after fct function has been called.
 * Even if fct raises an exception, clean_f is applied
 *)
let exnhook = ref None 

let finally fct clean_f =
	let result = try
		fct ();
	with
		exn ->
		  (match !exnhook with None -> () | Some f -> f exn);
		  clean_f (); raise exn in
	clean_f ();
	result

(** if v is not none, apply f on it and return some value else return none. *)
let may f v =
	match v with Some x -> Some (f x) | None -> None

(** default value to d if v is none. *) 
let default d v =
	match v with Some x -> x | None -> d

(** apply f on v if not none *)
let maybe f v =
	match v with None -> () | Some x -> f x

module String = struct include String

let of_char c = String.make 1 c

let rec split ?limit:(limit=(-1)) c s =
	let i = try String.index s c with Not_found -> -1 in
	let nlimit = if limit = -1 || limit = 0 then limit else limit - 1 in
	if i = -1 || nlimit = 0 then
		[ s ]
	else
		let a = String.sub s 0 i
		and b = String.sub s (i + 1) (String.length s - i - 1) in
		a :: (split ~limit: nlimit c b)

let fold_left f accu string =
	let accu = ref accu in
	for i = 0 to length string - 1 do
		accu := f !accu string.[i]
	done;
	!accu

(** True if string 'x' starts with prefix 'prefix' *)
let startswith prefix x =
	let x_l = String.length x and prefix_l = String.length prefix in
	prefix_l <= x_l && String.sub x 0 prefix_l  = prefix
end

module Unixext = struct

(** remove a file, but doesn't raise an exception if the file is already removed *)
let unlink_safe file =
	try Unix.unlink file with (* Unix.Unix_error (Unix.ENOENT, _ , _)*) _ -> ()

(** create a directory but doesn't raise an exception if the directory already exist *)
let mkdir_safe dir perm =
	try Unix.mkdir dir perm with Unix.Unix_error (Unix.EEXIST, _, _) -> ()

(** create a directory, and create parent if doesn't exist *)
let mkdir_rec dir perm =
	let rec p_mkdir dir =
		let p_name = Filename.dirname dir in
		if p_name <> "/" && p_name <> "." 
		then p_mkdir p_name;
		mkdir_safe dir perm in
	p_mkdir dir

(** daemonize a process *)
(* !! Must call this before spawning any threads !! *)
let daemonize () =
	match Unix.fork () with
	| 0 ->
		if Unix.setsid () == -1 then
			failwith "Unix.setsid failed";

		begin match Unix.fork () with
		| 0 ->
			let nullfd = Unix.openfile "/dev/null" [ Unix.O_WRONLY ] 0 in
			begin try
				Unix.close Unix.stdin;
				Unix.dup2 nullfd Unix.stdout;
				Unix.dup2 nullfd Unix.stderr;
			with exn -> Unix.close nullfd; raise exn
			end;
			Unix.close nullfd
		| _ -> exit 0
		end
	| _ -> exit 0

(** write a pidfile file *)
let pidfile_write filename =
	let fd = Unix.openfile filename
	                       [ Unix.O_WRONLY; Unix.O_CREAT; Unix.O_TRUNC; ]
			       0o640 in
	finally
	(fun () ->
		let pid = Unix.getpid () in
		let buf = string_of_int pid ^ "\n" in
		let len = String.length buf in
		if Unix.write fd buf 0 len <> len 
		then failwith "pidfile_write failed";
	)
	(fun () -> Unix.close fd)

end
