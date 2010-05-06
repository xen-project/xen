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

exception Timeout

(** Throws this rather than a miscellaneous Unix.connect failed *)
exception Failed_to_connect

(** perms contains 3 things:
    - owner domid.
    - other perm: applied to domain that is not owner or in ACL.
    - ACL: list of per-domain permission
  *)
type perms = Xsraw.perms

type domid = int
type con

type xsh = {
	con : con;
	debug: string list -> string;
	directory : string -> string list;
	read : string -> string;
	readv : string -> string list -> string list;
	write : string -> string -> unit;
	writev : string -> (string * string) list -> unit;
	mkdir : string -> unit;
	rm : string -> unit;
	getperms : string -> perms;
	setperms : string -> perms -> unit;
	setpermsv : string -> string list -> perms -> unit;
	introduce : domid -> nativeint -> int -> unit;
	release : domid -> unit;
	resume : domid -> unit;
	getdomainpath : domid -> string;
	watch : string -> string -> unit;
	unwatch : string -> string -> unit;
}

(** get operations provide a vector of xenstore function that apply to one
    connection *)
val get_operations : con -> xsh

(** create a transaction with a vector of function that can be applied
    into the transaction. *)
val transaction : xsh -> (Xst.ops -> 'a) -> 'a

(** watch manipulation on a connection *)
val has_watchevents : xsh -> bool
val get_watchevent : xsh -> string * string
val read_watchevent : xsh -> string * string

(** get_fd return the fd of the connection to be able to select on it.
    NOTE: it works only for socket-based connection *)
val get_fd : xsh -> Unix.file_descr

(** wait for watchevent with a timeout. Until the callback return true,
    every watch during the time specified, will be pass to the callback.
    NOTE: it works only when use with a socket-based connection *)
val read_watchevent_timeout : xsh -> float -> (string * string -> bool) -> unit

(** register a set of watches, then wait for watchevent.
    remove all watches previously set before giving back the hand. *)
val monitor_paths : xsh
                 -> (string * string) list
                 -> float
                 -> (string * string -> bool)
                 -> unit

(** open a socket-based xenstored connection *)
val daemon_open : unit -> xsh

(** open a mmap-based xenstored connection *)
val domain_open : unit -> xsh

(** close any xenstored connection *)
val close : xsh -> unit
