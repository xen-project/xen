(*
 * Copyright (C) 2014 Zheng Li <dev@zheng.li>
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


(* The [read], [write], [except] are fields mapped to the POLLIN/OUT/PRI
   subscription flags used by poll, which have a correspondence to the
   readfds, writefds, exceptfds concept as in select. *)
type event = {
	mutable read: bool;
	mutable write: bool;
	mutable except: bool;
}

external select_on_poll: (Unix.file_descr * event) array -> int -> int = "stub_select_on_poll"

let init_event () = {read = false; write = false; except = false}

let select in_fds out_fds exc_fds timeout =
	let h = Hashtbl.create 57 in
	let add_event event_set fd =
		let e =
			try Hashtbl.find h fd
			with Not_found ->
				let e = init_event () in
				Hashtbl.add h fd e; e in
		event_set e in
	List.iter (add_event (fun x -> x.read <- true)) in_fds;
	List.iter (add_event (fun x -> x.write <- true)) out_fds;
	List.iter (add_event (fun x -> x.except <- true)) exc_fds;
	(* Unix.stdin and init_event are dummy input as stubs, which will
           always be overwritten later on.  *)
	let a = Array.make (Hashtbl.length h) (Unix.stdin, init_event ()) in
	let i = ref (-1) in
	Hashtbl.iter (fun fd event -> incr i; Array.set a !i (fd, event)) h;
	let n = select_on_poll a (int_of_float (timeout *. 1000.)) in
	let r = [], [], [] in
	if n = 0 then r else
		Array.fold_right
			(fun (fd, event) (r, w, x) ->
			 (if event.read then fd :: r else r),
			 (if event.write then fd :: w else w),
			 (if event.except then fd :: x else x))
			a r
