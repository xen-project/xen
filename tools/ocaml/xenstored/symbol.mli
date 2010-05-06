(*
 * Copyright (C) 2006-2007 XenSource Ltd.
 * Copyright (C) 2008      Citrix Ltd.
 * Author Thomas Gazagnaire <thomas.gazagnaire@eu.citrix.com>
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

(** Node names *)

(** Xenstore nodes names are often the same, ie. "local", "domain", "device", ... so it is worth to 
    manipulate them through the use of small identifiers that we call symbols. These symbols can be 
    compared in constant time (as opposite to strings) and should help the ocaml GC. *)

type t
(** The type of symbols. *)

val of_string : string -> t
(** Convert a string into a symbol. *)

val to_string : t -> string
(** Convert a symbol into a string. *)

(** {6 Garbage Collection} *)

(** Symbols need to be regulary garbage collected. The following steps should be followed:
-     mark all the knowns symbols as unused (with [mark_all_as_unused]);
-     mark all the symbols really usefull as used (with [mark_as_used]); and
-     finally, call [garbage] *)

val mark_all_as_unused : unit -> unit
val mark_as_used : t -> unit
val garbage : unit -> unit

(** {6 Statistics } *)

val stats : unit -> int
(** Get the number of used symbols. *)

val created : unit -> int
(** Returns the number of symbols created since the last GC. *)

val used : unit -> int
(** Returns the number of existing symbols used since the last GC *)
