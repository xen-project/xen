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
exception Partial_not_empty
exception Unexpected_packet of string
exception Invalid_path of string
val unexpected_packet : Xenbus.Xb.Op.operation -> Xenbus.Xb.Op.operation -> 'a
type con = { xb : Xenbus.Xb.t; watchevents : (string * string) Queue.t; }
val close : con -> unit
val open_fd : Unix.file_descr -> con
val split_string : ?limit:int -> char -> string -> string list
type perm = PERM_NONE | PERM_READ | PERM_WRITE | PERM_RDWR
type perms = int * perm * (int * perm) list
val string_of_perms : int * perm * (int * perm) list -> string
val perms_of_string : string -> int * perm * (int * perm) list
val pkt_send : con -> unit
val pkt_recv : con -> Xenbus.Xb.Packet.t
val pkt_recv_timeout : con -> float -> bool * Xenbus.Xb.Packet.t option
val queue_watchevent : con -> string -> unit
val has_watchevents : con -> bool
val get_watchevent : con -> string * string
val read_watchevent : con -> string * string
val sync_recv : Xenbus.Xb.Op.operation -> con -> string
val sync : (Xenbus.Xb.t -> 'a) -> con -> string
val ack : string -> unit
val validate_path : string -> unit
val validate_watch_path : string -> unit
val directory : int -> string -> con -> string list
val debug : string list -> con -> string
val read : int -> string -> con -> string
val readv : int -> string -> string list -> con -> string list
val getperms : int -> string -> con -> int * perm * (int * perm) list
val watch : string -> string -> con -> unit
val unwatch : string -> string -> con -> unit
val transaction_start : con -> int
val transaction_end : int -> bool -> con -> bool
val introduce : int -> nativeint -> int -> con -> unit
val release : int -> con -> unit
val resume : int -> con -> unit
val getdomainpath : int -> con -> string
val write : int -> string -> string -> con -> unit
val writev : int -> string -> (string * string) list -> con -> unit
val mkdir : int -> string -> con -> unit
val rm : int -> string -> con -> unit
val setperms : int -> string -> int * perm * (int * perm) list -> con -> unit
val setpermsv :
  int ->
  string -> string list -> int * perm * (int * perm) list -> con -> unit
