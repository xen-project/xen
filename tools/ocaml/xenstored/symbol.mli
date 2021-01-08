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

val equal: t -> t -> bool
(** Compare two symbols for equality *)

val compare: t -> t -> int
(** Compare two symbols *)

(** {6 Statistics } *)

val stats : unit -> int * int
(** Get the table size and number of entries. *)

