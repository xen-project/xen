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

type config =
{
	domain_init: bool;
	activate_access_log: bool;
	daemonize: bool;
	reraise_top_level: bool;
	config_file: string option;
	pidfile: string option; (* old xenstored compatibility *)
	tracefile: string option; (* old xenstored compatibility *)
	restart: bool;
	disable_socket: bool;
}

let do_argv =
	let pidfile = ref "" and tracefile = ref "" (* old xenstored compatibility *)
	and domain_init = ref true
	and activate_access_log = ref true
	and daemonize = ref true
	and reraise_top_level = ref false
	and config_file = ref ""
	and restart = ref false
	and disable_socket = ref false in

	let speclist =
		[ ("--no-domain-init", Arg.Unit (fun () -> domain_init := false),
		   "to state that xenstored should not initialise dom0");
		  ("--config-file", Arg.Set_string config_file,
		   "set an alternative location for the configuration file");
		  ("--no-fork", Arg.Unit (fun () -> daemonize := false),
		   "to request that the daemon does not fork");
		  ("--reraise-top-level", Arg.Unit (fun () -> reraise_top_level := true),
		   "reraise exceptions caught at the top level");
		  ("--no-access-log", Arg.Unit (fun () -> activate_access_log := false),
		  "do not create a xenstore-access.log file");
		  ("--pid-file", Arg.Set_string pidfile, ""); (* for compatibility *)
		  ("-T", Arg.Set_string tracefile, ""); (* for compatibility *)
		  ("--restart", Arg.Set restart, "Read database on starting");
		  ("--disable-socket", Arg.Unit (fun () -> disable_socket := true), "Disable socket");
		] in
	let usage_msg = "usage : xenstored [--config-file <filename>] [--no-domain-init] [--help] [--no-fork] [--reraise-top-level] [--restart] [--disable-socket]" in
	Arg.parse speclist (fun s -> ()) usage_msg;
	{
		domain_init = !domain_init;
		activate_access_log = !activate_access_log;
		daemonize = !daemonize;
		reraise_top_level = !reraise_top_level;
		config_file = if !config_file <> "" then Some !config_file else None;
		pidfile = if !pidfile <> "" then Some !pidfile else None;
		tracefile = if !tracefile <> "" then Some !tracefile else None;
		restart = !restart;
		disable_socket = !disable_socket;
	}
