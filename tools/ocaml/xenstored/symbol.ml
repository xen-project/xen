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

module WeakTable = Weak.Make(struct
    type t = string
    let equal (x:string) (y:string) = (x = y)
    let hash = Hashtbl.hash
  end)

type t = string

let tbl = WeakTable.create 1024

let of_string s = WeakTable.merge tbl s
let to_string s = s

let equal a b =
  (* compare using physical equality, both members have to be part of the above weak table *)
  a == b

(* the sort order is reversed here, so that Map.fold constructs a list
   in ascending order *)
let compare a b = String.compare b a

let stats () =
  let len, entries, _, _, _, _ = WeakTable.stats tbl in
  len, entries
