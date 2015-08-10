(*
 * Copyright (C) 2014 Luis R. Rodriguez <mcgrof@suse.com>
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

(** Calls the C library sd_listen_fds() function for us. Although
 *  the library doesn't accept argument we send one over to help
 *  us do sanity checks on the expected sockets *)
val sd_listen_fds: string -> Unix.file_descr

(** Tells us whether the process is launched by systemd *)
val launched_by_systemd: unit -> bool

(** Tells systemd we're ready *)
external sd_notify_ready: unit -> unit = "ocaml_sd_notify_ready"
