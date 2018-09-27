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

(** Event channel bindings: see tools/libxc/include/xenctrl.h *)

type handle
(** An initialised event channel interface. *)

type t
(** A local event channel. *)

type virq_t =
  | Timer        (* #define VIRQ_TIMER      0 *)
  | Debug        (* #define VIRQ_DEBUG      1 *)
  | Console      (* #define VIRQ_CONSOLE    2 *)
  | Dom_exc      (* #define VIRQ_DOM_EXC    3 *)
  | Tbuf         (* #define VIRQ_TBUF       4 *)
  | Reserved_5   (* Do not use this value as it's not defined *)
  | Debugger     (* #define VIRQ_DEBUGGER   6 *)
  | Xenoprof     (* #define VIRQ_XENOPROF   7 *)
  | Con_ring     (* #define VIRQ_CON_RING   8 *)
  | Pcpu_state   (* #define VIRQ_PCPU_STATE 9 *)
  | Mem_event    (* #define VIRQ_MEM_EVENT  10 *)
  | Xc_reserved  (* #define VIRQ_XC_RESERVED 11 *)
  | Enomem       (* #define VIRQ_ENOMEM     12 *)
  | Xenpmu       (* #define VIRQ_XENPMU     13 *)


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

val bind_virq: handle -> virq_t -> t
(** Binds a local event channel to the specific VIRQ type.
    On error it will throw a Failure exception. *)

val unbind : handle -> t -> unit
(** Unbinds the given event channel. On error it will throw a
    Failure exception. *)

val pending : handle -> t
(** Returns the next event channel to become pending. On error it
    will throw a Failure exception. *)

val unmask : handle -> t -> unit
(** Unmasks the given event channel. On error it will throw a
    Failure exception. *)
