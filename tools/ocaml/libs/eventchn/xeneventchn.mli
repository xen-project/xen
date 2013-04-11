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

(** Event channel bindings: see tools/libxc/xenctrl.h *)

type handle
(** An initialised event channel interface. *)

type t
(** A local event channel. *)

val to_int: t -> int

val of_int: int -> t

val init: unit -> handle
(** Return an initialised event channel interface. On error it
    will throw a Failure exception. *)

val fd: handle -> Unix.file_descr
(** Return a file descriptor suitable for Unix.select. When
    the descriptor becomes readable, it is safe to call 'pending'.
    On error it will throw a Failure exception. *)

val notify : handle -> t -> unit
(** Notify the given event channel. On error it will throw a
    Failure exception. *)

val bind_interdomain : handle -> int -> int -> t
(** [bind_interdomain h domid remote_port] returns a local event
    channel connected to domid:remote_port. On error it will
    throw a Failure exception. *)

val bind_dom_exc_virq : handle -> t
(** Binds a local event channel to the VIRQ_DOM_EXC
    (domain exception VIRQ). On error it will throw a Failure
    exception. *)

val unbind : handle -> t -> unit
(** Unbinds the given event channel. On error it will throw a
    Failure exception. *)

val pending : handle -> t
(** Returns the next event channel to become pending. On error it
    will throw a Failure exception. *)

val unmask : handle -> t -> unit
(** Unmasks the given event channel. On error it will throw a
    Failure exception. *)
