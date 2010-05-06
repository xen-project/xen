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

type ops =
{
	directory: string -> string list;
	read: string -> string;
	readv: string -> string list -> string list;
	write: string -> string -> unit;
	writev: string -> (string * string) list -> unit;
	mkdir: string -> unit;
	rm: string -> unit;
	getperms: string -> Xsraw.perms;
	setperms: string -> Xsraw.perms -> unit;
	setpermsv: string -> string list -> Xsraw.perms -> unit;
}

let get_operations tid xsh = {
	directory = (fun path -> Xsraw.directory tid path xsh);
	read = (fun path -> Xsraw.read tid path xsh);
	readv = (fun dir vec -> Xsraw.readv tid dir vec xsh);
	write = (fun path value -> Xsraw.write tid path value xsh);
	writev = (fun dir vec -> Xsraw.writev tid dir vec xsh);
	mkdir = (fun path -> Xsraw.mkdir tid path xsh);
	rm = (fun path -> Xsraw.rm tid path xsh);
	getperms = (fun path -> Xsraw.getperms tid path xsh);
	setperms = (fun path perms -> Xsraw.setperms tid path perms xsh);
	setpermsv = (fun dir vec perms -> Xsraw.setpermsv tid dir vec perms xsh);
}

let transaction xsh (f: ops -> 'a) : 'a =
	let commited = ref false and result = ref None in
	while not !commited
	do
		let tid = Xsraw.transaction_start xsh in
		let t = get_operations tid xsh in

		begin try
			result := Some (f t)
		with exn ->
			ignore (Xsraw.transaction_end tid false xsh);
			raise exn
		end;
		commited := Xsraw.transaction_end tid true xsh
	done;
	match !result with
	| None        -> failwith "internal error in transaction"
	| Some result -> result
