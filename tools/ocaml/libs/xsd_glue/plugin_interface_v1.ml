(* SPDX-License-Identifier: LGPL-2.1-only WITH OCaml-LGPL-linking-exception *)

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

let ignore_logging : string -> unit = ignore
let logging_function = ref ignore_logging
let register_logging_function func = logging_function := func
let plugin_implementation_v1 : (module Domain_getinfo_V1) option ref = ref None
let register_plugin_v1 m = plugin_implementation_v1 := Some m

let get_plugin_v1 () : (module Domain_getinfo_V1) =
  match !plugin_implementation_v1 with
  | Some s -> s
  | None -> failwith "No plugin loaded"
