(* SPDX-License-Identifier: LGPL-2.1-only WITH OCaml-LGPL-linking-exception *)
(** Minimal interface on top of unstable Xenctrl for Oxenstored's usage *)

module P = Plugin_interface_v1

module M : P.Domain_getinfo_V1 = struct
  exception Error of string

  type domid = int
  type handle

  type domaininfo = {
    domid : domid;
    dying : bool;
    shutdown : bool;
    shutdown_code : int;
  }

  external interface_open : unit -> handle = "stub_xsd_glue_xc_interface_open"

  external domain_getinfo : handle -> domid -> domaininfo
    = "stub_xsd_glue_xc_domain_getinfo"

  external domain_getinfolist : handle -> domaininfo array
    = "stub_xsd_glue_xc_domain_getinfolist"

  let _ = Callback.register_exception "xsg.error_v1" (Error "register_callback")
end

let () =
  Printf.ksprintf !P.logging_function "Registration of %s plugin started\n%!"
    __MODULE__;
  P.register_plugin_v1 (module M : P.Domain_getinfo_V1);
  Printf.ksprintf !P.logging_function "Registration of %s plugin successful\n%!"
    __MODULE__
