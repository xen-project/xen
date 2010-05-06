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

type keylogger = {
  mutable debug : string list;
  mutable info : string list;
  mutable warn : string list;
  mutable error : string list;
  no_default : bool;
}
val __all_loggers : (string, Log.t) Hashtbl.t
val __default_logger : keylogger
val __log_mapping : (string, keylogger) Hashtbl.t
val get_or_open : string -> Log.t
val add : string -> string list -> unit
val get_by_level : keylogger -> Log.level -> string list
val set_by_level : keylogger -> Log.level -> string list -> unit
val set : string -> Log.level -> string list -> unit
val set_default : Log.level -> string list -> unit
val append : string -> Log.level -> string -> unit
val append_default : Log.level -> string -> unit
val reopen : unit -> unit
val reclaim : unit -> unit
val clear : string -> Log.level -> unit
val clear_default : Log.level -> unit
val reset_all : string list -> unit
val log :
  string ->
  Log.level -> ?extra:string -> ('a, unit, string, unit) format4 -> 'a
val debug : string -> ?extra:string -> ('a, unit, string, unit) format4 -> 'a
val info : string -> ?extra:string -> ('a, unit, string, unit) format4 -> 'a
val warn : string -> ?extra:string -> ('a, unit, string, unit) format4 -> 'a
val error : string -> ?extra:string -> ('a, unit, string, unit) format4 -> 'a
