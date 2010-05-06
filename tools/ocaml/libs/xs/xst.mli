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
type ops = {
	directory : string -> string list;
	read : string -> string;
	readv : string -> string list -> string list;
	write : string -> string -> unit;
	writev : string -> (string * string) list -> unit;
	mkdir : string -> unit;
	rm : string -> unit;
	getperms : string -> Xsraw.perms;
	setperms : string -> Xsraw.perms -> unit;
	setpermsv : string -> string list -> Xsraw.perms -> unit;
}

val get_operations : int -> Xsraw.con -> ops
val transaction : Xsraw.con -> (ops -> 'a) -> 'a
