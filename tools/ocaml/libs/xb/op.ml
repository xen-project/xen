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

type operation = Debug | Directory | Read | Getperms |
                 Watch | Unwatch | Transaction_start |
                 Transaction_end | Introduce | Release |
                 Getdomainpath | Write | Mkdir | Rm |
                 Setperms | Watchevent | Error | Isintroduced |
                 Resume | Set_target | Restrict | Invalid

let operation_c_mapping =
	[| Debug; Directory; Read; Getperms;
           Watch; Unwatch; Transaction_start;
           Transaction_end; Introduce; Release;
           Getdomainpath; Write; Mkdir; Rm;
           Setperms; Watchevent; Error; Isintroduced;
           Resume; Set_target; Restrict |]
let size = Array.length operation_c_mapping

let array_search el a =
	let len = Array.length a in
	let rec search i =
		if i > len then raise Not_found;
		if a.(i) = el then i else search (i + 1) in
	search 0

let of_cval i =
	if i >= 0 && i < size
	then operation_c_mapping.(i)
	else Invalid

let to_cval op =
	array_search op operation_c_mapping

let to_string ty =
	match ty with
	| Debug			-> "DEBUG"
	| Directory		-> "DIRECTORY"
	| Read			-> "READ"
	| Getperms		-> "GET_PERMS"
	| Watch			-> "WATCH"
	| Unwatch		-> "UNWATCH"
	| Transaction_start	-> "TRANSACTION_START"
	| Transaction_end	-> "TRANSACTION_END"
	| Introduce		-> "INTRODUCE"
	| Release		-> "RELEASE"
	| Getdomainpath		-> "GET_DOMAIN_PATH"
	| Write			-> "WRITE"
	| Mkdir			-> "MKDIR"
	| Rm			-> "RM"
	| Setperms		-> "SET_PERMS"
	| Watchevent		-> "WATCH_EVENT"
	| Error			-> "ERROR"
	| Isintroduced		-> "IS_INTRODUCED"
	| Resume		-> "RESUME"
	| Set_target		-> "SET_TARGET"
	| Restrict		-> "RESTRICT"
	| Invalid		-> "INVALID"
