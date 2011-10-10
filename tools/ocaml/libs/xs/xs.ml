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

type perms = Xsraw.perms
type con = Xsraw.con
type domid = int

type xsh =
{
	con: con;
	debug: string list -> string;
	directory: string -> string list;
	read: string -> string;
	readv: string -> string list -> string list;
	write: string -> string -> unit;
	writev: string -> (string * string) list -> unit;
	mkdir: string -> unit;
	rm: string -> unit;
	getperms: string -> perms;
	setperms: string -> perms -> unit;
	setpermsv: string -> string list -> perms -> unit;
	introduce: domid -> nativeint -> int -> unit;
	release: domid -> unit;
	resume: domid -> unit;
	getdomainpath: domid -> string;
	watch: string -> string -> unit;
	unwatch: string -> string -> unit;
}

let get_operations con = {
	con = con;
	debug = (fun commands -> Xsraw.debug commands con);
	directory = (fun path -> Xsraw.directory 0 path con);
	read = (fun path -> Xsraw.read 0 path con);
	readv = (fun dir vec -> Xsraw.readv 0 dir vec con);
	write = (fun path value -> Xsraw.write 0 path value con);
	writev = (fun dir vec -> Xsraw.writev 0 dir vec con);
	mkdir = (fun path -> Xsraw.mkdir 0 path con);
	rm = (fun path -> Xsraw.rm 0 path con);
	getperms = (fun path -> Xsraw.getperms 0 path con);
	setperms = (fun path perms -> Xsraw.setperms 0 path perms con);
	setpermsv = (fun dir vec perms -> Xsraw.setpermsv 0 dir vec perms con);
	introduce = (fun id mfn port -> Xsraw.introduce id mfn port con);
	release = (fun id -> Xsraw.release id con);
	resume = (fun id -> Xsraw.resume id con);
	getdomainpath = (fun id -> Xsraw.getdomainpath id con);
	watch = (fun path data -> Xsraw.watch path data con);
	unwatch = (fun path data -> Xsraw.unwatch path data con);
}

let transaction xsh = Xst.transaction xsh.con

let has_watchevents xsh = Xsraw.has_watchevents xsh.con
let get_watchevent xsh = Xsraw.get_watchevent xsh.con

let read_watchevent xsh = Xsraw.read_watchevent xsh.con

let make fd = get_operations (Xsraw.open_fd fd)
let get_fd xsh = Xenbus.Xb.get_fd xsh.con.Xsraw.xb

exception Timeout

(* Should never be thrown, indicates a bug in the read_watchevent_timetout function *)
exception Timeout_with_nonempty_queue

(* Just in case we screw up: poll the callback every couple of seconds rather
   than wait for the whole timeout period *)
let max_blocking_time = 5. (* seconds *)

let read_watchevent_timeout xsh timeout callback =
	let start_time = Unix.gettimeofday () in
	let end_time = start_time +. timeout in

	let left = ref timeout in

	(* Returns true if a watch event in the queue satisfied us *)
	let process_queued_events () = 
		let success = ref false in
		while Xsraw.has_watchevents xsh.con && not(!success)
		do
			success := callback (Xsraw.get_watchevent xsh.con)
		done;
		!success in
	(* Returns true if a watch event read from the socket satisfied us *)
	let process_incoming_event () = 
		let fd = get_fd xsh in
		let r, _, _ = Unix.select [ fd ] [] [] (min max_blocking_time !left) in

		(* If data is available for reading then read it *)
		if r = []
		then false (* timeout, either a max_blocking_time or global *)
		else callback (Xsraw.read_watchevent xsh.con) in

	let success = ref false in
	while !left > 0. && not(!success)
	do
		(* NB the 'callback' might call back into Xs functions
		   and as a side-effect, watches might be queued. Hence
		   we must process the queue on every loop iteration *)

		(* First process all queued watch events *)
		if not(!success)
		then success := process_queued_events ();
		(* Then block for one more watch event *)
		if not(!success)
		then success := process_incoming_event ();
		(* Just in case our callback caused events to be queued
		   and this is our last time round the loop: this prevents
		   us throwing the Timeout_with_nonempty_queue spuriously *)
		if not(!success)
		then success := process_queued_events ();

		(* Update the time left *)
		let current_time = Unix.gettimeofday () in
		left := end_time -. current_time
	done;
	if not(!success) then begin
		(* Sanity check: it should be impossible for any
		   events to be queued here *)
		if Xsraw.has_watchevents xsh.con
		then raise Timeout_with_nonempty_queue
		else raise Timeout
	end


let monitor_paths xsh l time callback =
	let unwatch () =
		List.iter (fun (w,v) -> try xsh.unwatch w v with _ -> ()) l in
	List.iter (fun (w,v) -> xsh.watch w v) l;
	begin try
		read_watchevent_timeout xsh time callback;
	with
		exn -> unwatch (); raise exn;
	end;
	unwatch ()

let daemon_socket = "/var/run/xenstored/socket"

(** Throws this rather than a miscellaneous Unix.connect failed *)
exception Failed_to_connect

let daemon_open () =
	try
		let sockaddr = Unix.ADDR_UNIX(daemon_socket) in
		let sock = Unix.socket Unix.PF_UNIX Unix.SOCK_STREAM 0 in
		Unix.connect sock sockaddr;
		Unix.set_close_on_exec sock;
		make sock
	with _ -> raise Failed_to_connect

let domain_open () =
	let path = "/proc/xen/xenbus" in
	let fd = Unix.openfile path [ Unix.O_RDWR ] 0o550 in
	Unix.set_close_on_exec fd;
	make fd

let close xsh = Xsraw.close xsh.con
