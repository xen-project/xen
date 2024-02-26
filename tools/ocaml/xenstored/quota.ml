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

exception Limit_reached
exception Data_too_big
exception Transaction_opened

let warn fmt = Logging.warn "quota" fmt
let activate = ref true
let maxent = ref (1000)
let maxsize = ref (2048)

module Domid = struct
  type t = Xenctrl.domid
  let compare (a:t) (b:t) = compare a b
end

module DomidMap = Map.Make(Domid)

type t = {
  maxent: int;               (* max entities per domU *)
  maxsize: int;              (* max size of data store in one node *)
  cur: int DomidMap.t; (* current domains quota *)
}

let to_string quota domid =
  try
    Printf.sprintf "dom%i quota: %i/%i" domid (DomidMap.find domid quota.cur) quota.maxent
  with Not_found ->
    Printf.sprintf "dom%i quota: not set" domid

let create () =
  { maxent = !maxent; maxsize = !maxsize; cur = DomidMap.empty; }

let copy quota = { quota with cur = quota.cur }

let del quota id = { quota with cur = DomidMap.remove id quota.cur }

let _check quota id size =
  if size > quota.maxsize then (
    warn "domain %u err create entry: data too big %d" id size;
    raise Data_too_big
  );
  if id > 0 then
    try
      let entry = DomidMap.find id quota.cur in
      if entry >= quota.maxent then (
        warn "domain %u cannot create entry: quota reached" id;
        raise Limit_reached
      )
    with Not_found -> ()

let check quota id size =
  if !activate then
    _check quota id size

let find_or_zero quota_cur id =
  try DomidMap.find id quota_cur with Not_found -> 0

let update_entry quota_cur id diff =
  let nb = diff + find_or_zero quota_cur id in
  if nb = 0 then DomidMap.remove id quota_cur
  else DomidMap.add id nb quota_cur

let del_entry quota id =
  {quota with cur = update_entry quota.cur id (-1)}

let add_entry quota id =
  {quota with cur = update_entry quota.cur id (+1)}

let merge orig_quota mod_quota dest_quota =
  let fold_merge id nb dest =
    match nb - find_or_zero orig_quota.cur id with
    | 0 -> dest (* not modified *)
    | diff -> update_entry dest id diff (* update with [x=x+diff] *)
  in
  {dest_quota with cur = DomidMap.fold fold_merge mod_quota.cur dest_quota.cur}
(* dest_quota = dest_quota + (mod_quota - orig_quota) *)
