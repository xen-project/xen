(*
 * Copyright (C) 2006-2007 XenSource Ltd.
 * Copyright (C) 2008      Citrix Ltd.
 * Author Vincent Hanquez <vincent.hanquez@eu.citrix.com>
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

let info fmt = Logging.info "perms" fmt

open Stdext

let activate = ref true

type permty = READ | WRITE | RDWR | NONE

let char_of_permty perm =
	match perm with
	| READ -> 'r'
	| WRITE -> 'w'
	| RDWR -> 'b'
	| NONE -> 'n'

let permty_of_char c =
	match c with
	| 'r' -> READ
	| 'w' -> WRITE
	| 'b' -> RDWR
	| 'n' -> NONE
	| _ -> invalid_arg "unknown permission type"


(* node permissions *)
module Node =
struct

type t =
{
	owner: Xenctrl.domid;
	other: permty;
	acl: (Xenctrl.domid * permty) list;
}

let create owner other acl =
	{ owner = owner; other = other; acl = acl }

let get_other perms = perms.other
let get_acl perms = perms.acl
let get_owner perm = perm.owner

let default0 = create 0 NONE []

let perm_of_string s =
	let ty = permty_of_char s.[0]
	and id = int_of_string (String.sub s 1 (String.length s - 1)) in
	(id, ty)

let of_strings ls =
	let vect = List.map (perm_of_string) ls in
	match vect with
	| [] -> invalid_arg "permvec empty"
	| h :: l -> create (fst h) (snd h) l

(* [s] must end with '\000' *)
let of_string s =
	let ls = String.split '\000' s in
	let ls = if ls = [] then ls else List.rev (List.tl (List.rev ls)) in
	of_strings ls

let string_of_perm perm =
	Printf.sprintf "%c%u" (char_of_permty (snd perm)) (fst perm)

let to_string permvec =
	let l = ((permvec.owner, permvec.other) :: permvec.acl) in
	String.concat "\000" (List.map string_of_perm l)

end


(* permission of connections *)
module Connection =
struct

type elt = Xenctrl.domid * (permty list)
type t =
	{ main: elt;
	  target: elt option; }

let full_rights : t =
	{ main = 0, [READ; WRITE];
	  target = None }

let create ?(perms=[NONE]) domid : t =
	{ main = (domid, perms);
	  target = None }

let set_target (connection:t) ?(perms=[NONE]) domid =
	{ connection with target = Some (domid, perms) }

let get_owners (connection:t) =
	match connection.main, connection.target with
	| c1, Some c2 -> [ fst c1; fst c2 ]
	| c1, None    -> [ fst c1 ]

let is_owner (connection:t) id =
	match connection.target with
	| Some target -> fst connection.main = id || fst target = id
	| None        -> fst connection.main = id

let is_dom0 (connection:t) =
	is_owner connection 0

let restrict (connection:t) domid =
	match connection.target, connection.main with
	| None, (0, perms) -> { connection with main = (domid, perms) }
	| _                -> raise Define.Permission_denied

let elt_to_string (i,p) =
	Printf.sprintf "%i%S" i (String.concat "" (List.map String.of_char (List.map char_of_permty p)))

let to_string connection =
	Printf.sprintf "%s%s" (elt_to_string connection.main) (default "" (may elt_to_string connection.target))
end

(* check if owner of the current connection and of the current node are the same *)
let check_owner (connection:Connection.t) (node:Node.t) =
	if !activate && not (Connection.is_dom0 connection)
	then Connection.is_owner connection (Node.get_owner node)
	else true

(* check if the current connection has the requested perm on the current node *)
let check (connection:Connection.t) request (node:Node.t) =
	let check_acl domainid =
		let perm =
			if List.mem_assoc domainid (Node.get_acl node)
			then List.assoc domainid (Node.get_acl node)
			else Node.get_other node
		in
		match perm, request with
		| NONE, _ ->
			info "Permission denied: Domain %d has no permission" domainid;
			false
		| RDWR, _ -> true
		| READ, READ -> true
		| WRITE, WRITE -> true
		| READ, _ ->
			info "Permission denied: Domain %d has read only access" domainid;
			false
		| WRITE, _ ->
			info "Permission denied: Domain %d has write only access" domainid;
			false
	in
	if !activate
	&& not (Connection.is_dom0 connection)
	&& not (check_owner connection node)
	&& not (List.exists check_acl (Connection.get_owners connection))
	then raise Define.Permission_denied

let equiv perm1 perm2 =
	(Node.to_string perm1) = (Node.to_string perm2)
