(*
 * Copyright (C) 2014 Zheng Li <dev@zheng.li>
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


(** Same interface and semantics as [Unix.select] but with an extra alternative
    implementation based on poll. Switching implementations is done by calling
     the [use_poll] function. *)
val select:
	Unix.file_descr list -> Unix.file_descr list -> Unix.file_descr list -> float
	-> Unix.file_descr list * Unix.file_descr list * Unix.file_descr list

(** [use_poll true] will use poll based select with max fds number limitation
   eliminated; [use_poll false] will use standard [Unix.select] with max fd
   number set to 1024; not calling this function at all equals to use the
   standard [Unix.select] with max fd number setting untouched. *)
val use_poll: bool -> unit
