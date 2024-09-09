(* SPDX-License-Identifier: LGPL-2.1-only WITH OCaml-LGPL-linking-exception *)

(** To avoid breaking the plugin interface, this module needs to be
    standalone and can't rely on any other Xen library. Even unrelated
    changes in the interfaces of those modules would change the hash
    of this interface and break the plugin system.
    It can only depend on Stdlib, therefore all of the types (domid,
    domaininfo etc.) are redefined here instead of using alternatives
    defined elsewhere.

    NOTE: The signature of this interface should not be changed (no
    functions or types can be added, modified, or removed). If
    underlying Xenctrl changes require a new interface, a V2 with a
    corresponding plugin should be created.
*)

module type Domain_getinfo_V1 = sig
  exception Error of string

  type domid = int
  type handle

  type domaininfo = {
    domid : domid;
    dying : bool;
    shutdown : bool;
    shutdown_code : int;
  }

  val interface_open : unit -> handle
  val domain_getinfo : handle -> domid -> domaininfo
  val domain_getinfolist : handle -> domaininfo array
end

val register_logging_function : (string -> unit) -> unit
val logging_function : (string -> unit) ref
val register_plugin_v1 : (module Domain_getinfo_V1) -> unit
val get_plugin_v1 : unit -> (module Domain_getinfo_V1)
