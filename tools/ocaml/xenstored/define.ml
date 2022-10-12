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

let xenstored_major = 1
let xenstored_minor = 0

let xs_daemon_socket = Paths.xen_run_stored ^ "/socket"

let default_config_dir = Paths.xen_config_dir

let maxwatch = ref (100)
let maxtransaction = ref (10)
let maxrequests = ref (1024)   (* maximum requests per transaction *)
let maxoutstanding = ref (1024) (* maximum outstanding requests, i.e. in-flight requests / domain *)
let maxwatchevents = ref (1024)
(*
	maximum outstanding watch events per watch,
	recommended >= maxoutstanding to avoid blocking backend transactions due to
	malicious frontends
 *)

let gc_max_overhead = ref 120 (* 120% see comment in xenstored.ml *)
let conflict_burst_limit = ref 5.0
let conflict_max_history_seconds = ref 0.05
let conflict_rate_limit_is_aggregate = ref true

let domid_self = 0x7FF0

let path_max = ref Xenbus.Partial.xenstore_rel_path_max

exception Not_a_directory of string
exception Not_a_value of string
exception Already_exist
exception Doesnt_exist
exception Lookup_Doesnt_exist of string
exception Invalid_path
exception Permission_denied
exception Unknown_operation
