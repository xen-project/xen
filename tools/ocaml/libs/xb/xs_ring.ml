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

module Server_feature = struct
	type t =
	| Reconnection
end

module Server_features = Set.Make(struct
	type t = Server_feature.t
	let compare = compare
end)

external read: Xenmmap.mmap_interface -> string -> int -> int = "ml_interface_read"
external write: Xenmmap.mmap_interface -> string -> int -> int = "ml_interface_write"

external _internal_set_server_features: Xenmmap.mmap_interface -> int -> unit = "ml_interface_set_server_features" "noalloc"
external _internal_get_server_features: Xenmmap.mmap_interface -> int = "ml_interface_get_server_features" "noalloc"


let get_server_features mmap =
	(* NB only one feature currently defined above *)
	let x = _internal_get_server_features mmap in
	if x = 0
	then Server_features.empty
	else Server_features.singleton Server_feature.Reconnection

let set_server_features mmap set =
	(* NB only one feature currently defined above *)
	let x = if set = Server_features.empty then 0 else 1 in
	_internal_set_server_features mmap x

external close: Xenmmap.mmap_interface -> unit = "ml_interface_close" "noalloc"
