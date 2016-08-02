(*
 * Copyright (C) 2006-2007 XenSource Ltd.
 * Copyright (C) 2008      Citrix Ltd.
 * Author Vincent Hanquez <vincent.hanquez@eu.citrix.com>
 * Author Thomas Gazagnaire <thomas.gazagnaire@eu.citrix.com>
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

open Printf
open Parse_arg
open Stdext

let error fmt = Logging.error "xenstored" fmt
let debug fmt = Logging.debug "xenstored" fmt
let info fmt = Logging.info "xenstored" fmt

(*------------ event klass processors --------------*)
let process_connection_fds store cons domains rset wset =
	let try_fct fct c =
		try
			fct store cons domains c
		with
		| Unix.Unix_error(err, "write", _) ->
			Connections.del_anonymous cons c;
			error "closing socket connection: write error: %s"
			      (Unix.error_message err)
		| Unix.Unix_error(err, "read", _) ->
			Connections.del_anonymous cons c;
			if err <> Unix.ECONNRESET then
			error "closing socket connection: read error: %s"
			      (Unix.error_message err)
		| Xenbus.Xb.End_of_file ->
			Connections.del_anonymous cons c;
			debug "closing socket connection"
		in
	let process_fdset_with fds fct =
		List.iter
			(fun fd ->
			 try try_fct fct (Connections.find cons fd)
			 with Not_found -> ()
			) fds in
	process_fdset_with rset Process.do_input;
	process_fdset_with wset Process.do_output

let process_domains store cons domains =
	let do_io_domain domain =
		if not (Domain.is_bad_domain domain) then
			let io_credit = Domain.get_io_credit domain in
			if io_credit > 0 then (
				let con = Connections.find_domain cons (Domain.get_id domain) in
				Process.do_input store cons domains con;
				Process.do_output store cons domains con;
				Domain.decr_io_credit domain;
			) in
	Domains.iter domains do_io_domain

let sigusr1_handler store =
	try
		let channel = open_out_gen [ Open_wronly; Open_creat; Open_trunc; ]
		                           0o600 (Paths.xen_run_stored ^ "/db.debug") in
		finally (fun () -> Store.dump store channel)
			(fun () -> close_out channel)
	with _ ->
		()

let sighup_handler _ =
	maybe (fun logger -> logger.Logging.restart()) !Logging.xenstored_logger;
	maybe (fun logger -> logger.Logging.restart()) !Logging.access_logger

let config_filename cf =
	match cf.config_file with
	| Some name -> name
	| None      -> Define.default_config_dir ^ "/oxenstored.conf"

let default_pidfile = Paths.xen_run_dir ^ "/xenstored.pid"

let ring_scan_interval = ref 20

let parse_config filename =
	let pidfile = ref default_pidfile in
	let options = [
		("merge-activate", Config.Set_bool Transaction.do_coalesce);
		("perms-activate", Config.Set_bool Perms.activate);
		("quota-activate", Config.Set_bool Quota.activate);
		("quota-maxwatch", Config.Set_int Define.maxwatch);
		("quota-transaction", Config.Set_int Define.maxtransaction);
		("quota-maxentity", Config.Set_int Quota.maxent);
		("quota-maxsize", Config.Set_int Quota.maxsize);
		("quota-maxrequests", Config.Set_int Define.maxrequests);
		("test-eagain", Config.Set_bool Transaction.test_eagain);
		("persistent", Config.Set_bool Disk.enable);
		("xenstored-log-file", Config.String Logging.set_xenstored_log_destination);
		("xenstored-log-level", Config.String
			(fun s -> Logging.xenstored_log_level := Logging.level_of_string s));
		("xenstored-log-nb-files", Config.Set_int Logging.xenstored_log_nb_files);
		("xenstored-log-nb-lines", Config.Set_int Logging.xenstored_log_nb_lines);
		("xenstored-log-nb-chars", Config.Set_int Logging.xenstored_log_nb_chars);
		("access-log-file", Config.String Logging.set_access_log_destination);
		("access-log-nb-files", Config.Set_int Logging.access_log_nb_files);
		("access-log-nb-lines", Config.Set_int Logging.access_log_nb_lines);
		("access-log-nb-chars", Config.Set_int Logging.access_log_nb_chars);
		("access-log-read-ops", Config.Set_bool Logging.access_log_read_ops);
		("access-log-transactions-ops", Config.Set_bool Logging.access_log_transaction_ops);
		("access-log-special-ops", Config.Set_bool Logging.access_log_special_ops);
		("allow-debug", Config.Set_bool Process.allow_debug);
		("ring-scan-interval", Config.Set_int ring_scan_interval);
		("pid-file", Config.Set_string pidfile); ] in
	begin try Config.read filename options (fun _ _ -> raise Not_found)
	with
	| Config.Error err -> List.iter (fun (k, e) ->
		match e with
		| "unknown key" -> eprintf "config: unknown key %s\n" k
		| _             -> eprintf "config: %s: %s\n" k e
		) err;
	| Sys_error m -> eprintf "error: config: %s\n" m;
	end;
	!pidfile

module DB = struct

exception Bad_format of string

let dump_format_header = "$xenstored-dump-format"

let from_channel_f chan domain_f watch_f store_f =
	let unhexify s = Utils.unhexify s in
	let getpath s = Store.Path.of_string (Utils.unhexify s) in
	let header = input_line chan in
	if header <> dump_format_header then
		raise (Bad_format "header");
	let quit = ref false in
	while not !quit
	do
		try
			let line = input_line chan in
			let l = String.split ',' line in
			try
				match l with
				| "dom" :: domid :: mfn :: port :: []->
					domain_f (int_of_string domid)
					         (Nativeint.of_string mfn)
					         (int_of_string port)
				| "watch" :: domid :: path :: token :: [] ->
					watch_f (int_of_string domid)
					        (unhexify path) (unhexify token)
				| "store" :: path :: perms :: value :: [] ->
					store_f (getpath path)
					        (Perms.Node.of_string (unhexify perms ^ "\000"))
					        (unhexify value)
				| _ ->
					info "restoring: ignoring unknown line: %s" line
			with exn ->
				info "restoring: ignoring unknown line: %s (exception: %s)"
				     line (Printexc.to_string exn);
				()
		with End_of_file ->
			quit := true
	done;
	()

let from_channel store cons doms chan =
	(* don't let the permission get on our way, full perm ! *)
	let op = Store.get_ops store Perms.Connection.full_rights in
	let xc = Xenctrl.interface_open () in

	let domain_f domid mfn port =
		let ndom =
			if domid > 0 then
				Domains.create xc doms domid mfn port
			else
				Domains.create0 doms
			in
		Connections.add_domain cons ndom;
		in
	let watch_f domid path token = 
		let con = Connections.find_domain cons domid in
		ignore (Connections.add_watch cons con path token)
		in
	let store_f path perms value =
		op.Store.write path value;
		op.Store.setperms path perms
		in
	finally (fun () -> from_channel_f chan domain_f watch_f store_f)
	        (fun () -> Xenctrl.interface_close xc)

let from_file store cons doms file =
	let channel = open_in file in
	finally (fun () -> from_channel store doms cons channel)
	        (fun () -> close_in channel)

let to_channel store cons chan =
	let hexify s = Utils.hexify s in

	fprintf chan "%s\n" dump_format_header;

	(* dump connections related to domains; domid, mfn, eventchn port, watches *)
	Connections.iter_domains cons (fun con -> Connection.dump con chan);

	(* dump the store *)
	Store.dump_fct store (fun path node ->
		let name, perms, value = Store.Node.unpack node in
		let fullpath = (Store.Path.to_string path) ^ "/" ^ name in
		let permstr = Perms.Node.to_string perms in
		fprintf chan "store,%s,%s,%s\n" (hexify fullpath) (hexify permstr) (hexify value)
	);
	flush chan;
	()


let to_file store cons file =
	let channel = open_out_gen [ Open_wronly; Open_creat; Open_trunc; ] 0o600 file in
	finally (fun () -> to_channel store cons channel)
	        (fun () -> close_out channel)
end

let _ =
	let cf = do_argv in
	let pidfile =
		if Sys.file_exists (config_filename cf) then
			parse_config (config_filename cf)
		else
			default_pidfile
		in

	(try 
		Unixext.mkdir_rec (Filename.dirname pidfile) 0o755
	with _ ->
		()
	);

	let rw_sock, ro_sock =
		if cf.disable_socket then
			None, None
		else
			Some (Unix.handle_unix_error Utils.create_unix_socket Define.xs_daemon_socket),
			Some (Unix.handle_unix_error Utils.create_unix_socket Define.xs_daemon_socket_ro)
		in
	
	if cf.daemonize then
		Unixext.daemonize ()
	else
		printf "Xen Storage Daemon, version %d.%d\n%!" 
			Define.xenstored_major Define.xenstored_minor;

	(try Unixext.pidfile_write pidfile with _ -> ());

	(* for compatilibity with old xenstored *)
	begin match cf.pidfile with
	| Some pidfile -> Unixext.pidfile_write pidfile
	| None         -> () end;

	let store = Store.create () in
	let eventchn = Event.init () in
	let domains = Domains.init eventchn in
	let cons = Connections.create () in

	let quit = ref false in

	if cf.restart then (
		DB.from_file store domains cons (Paths.xen_run_stored ^ "/db");
		Event.bind_dom_exc_virq eventchn
	) else (
		if !Disk.enable then (
			info "reading store from disk";
			Disk.read store
		);

		let localpath = Store.Path.of_string "/local" in
		if not (Store.path_exists store localpath) then
			Store.mkdir store (Perms.Connection.create 0) localpath;

		if cf.domain_init then (
			Connections.add_domain cons (Domains.create0 domains);
			Event.bind_dom_exc_virq eventchn
		);
	);

	Select.use_poll (not cf.use_select);

	Sys.set_signal Sys.sighup (Sys.Signal_handle sighup_handler);
	Sys.set_signal Sys.sigterm (Sys.Signal_handle (fun i -> quit := true));
	Sys.set_signal Sys.sigusr1 (Sys.Signal_handle (fun i -> sigusr1_handler store));
	Sys.set_signal Sys.sigpipe Sys.Signal_ignore;

	Logging.init_xenstored_log();
	if cf.activate_access_log then begin
		let post_rotate () = DB.to_file store cons (Paths.xen_run_stored ^ "/db") in
		Logging.init_access_log post_rotate
	end;

	let spec_fds =
		(match rw_sock with None -> [] | Some x -> [ x ]) @
		(match ro_sock with None -> [] | Some x -> [ x ]) @
		(if cf.domain_init then [ Event.fd eventchn ] else [])
		in

	let xc = Xenctrl.interface_open () in

	let process_special_fds rset =
		let accept_connection can_write fd =
			let (cfd, addr) = Unix.accept fd in
			debug "new connection through socket";
			Connections.add_anonymous cons cfd can_write
		and handle_eventchn fd =
			let port = Event.pending eventchn in
			debug "pending port %d" (Xeneventchn.to_int port);
			finally (fun () ->
				if Some port = eventchn.Event.virq_port then (
					let (notify, deaddom) = Domains.cleanup xc domains in
					List.iter (Connections.del_domain cons) deaddom;
					if deaddom <> [] || notify then
						Connections.fire_spec_watches cons "@releaseDomain"
				)
				else
					let c = Connections.find_domain_by_port cons port in
					match Connection.get_domain c with
					| Some dom -> Domain.incr_io_credit dom | None -> ()
				) (fun () -> Event.unmask eventchn port)
		and do_if_set fd set fct =
			if List.mem fd set then
				fct fd in

		maybe (fun fd -> do_if_set fd rset (accept_connection true)) rw_sock;
		maybe (fun fd -> do_if_set fd rset (accept_connection false)) ro_sock;
		do_if_set (Event.fd eventchn) rset (handle_eventchn)
	in

	let ring_scan_checker dom =
		(* no need to scan domains already marked as for processing *)
		if not (Domain.get_io_credit dom > 0) then
			let con = Connections.find_domain cons (Domain.get_id dom) in
			if not (Connection.has_more_work con) then (
				Process.do_output store cons domains con;
				Process.do_input store cons domains con;
				if Connection.has_more_work con then
					(* Previously thought as no work, but detect some after scan (as
					   processing a new message involves multiple steps.) It's very
					   likely to be a "lazy" client, bump its credit. It could be false
					   positive though (due to time window), but it's no harm to give a
					   domain extra credit. *)
					let n = 32 + 2 * (Domains.number domains) in
					info "found lazy domain %d, credit %d" (Domain.get_id dom) n;
					Domain.set_io_credit ~n dom
			) in

	let last_stat_time = ref 0. in
	let last_scan_time = ref 0. in

	let periodic_ops now =
		(* we garbage collect the string->int dictionary after a sizeable amount of operations,
		 * there's no need to be really fast even if we got loose
		 * objects since names are often reuse.
		 *)
		if Symbol.created () > 1000 || Symbol.used () > 20000
		then begin
			Symbol.mark_all_as_unused ();
			Store.mark_symbols store;
			Connections.iter cons Connection.mark_symbols;
			Symbol.garbage ()
		end;

		(* scan all the xs rings as a safenet for ill-behaved clients *)
		if !ring_scan_interval >= 0 && now > (!last_scan_time +. float !ring_scan_interval) then
			(last_scan_time := now; Domains.iter domains ring_scan_checker);

		(* make sure we don't print general stats faster than 2 min *)
		if now > (!last_stat_time +. 120.) then (
			last_stat_time := now;

			let gc = Gc.stat () in
			let (lanon, lanon_ops, lanon_watchs,
			     ldom, ldom_ops, ldom_watchs) = Connections.stats cons in
			let store_nodes, store_abort, store_coalesce = Store.stats store in
			let symtbl_len = Symbol.stats () in

			info "store stat: nodes(%d) t-abort(%d) t-coalesce(%d)"
			     store_nodes store_abort store_coalesce;
			info "sytbl stat: %d" symtbl_len;
			info "  con stat: anonymous(%d, %d o, %d w) domains(%d, %d o, %d w)"
			     lanon lanon_ops lanon_watchs ldom ldom_ops ldom_watchs;
			info "  mem stat: minor(%.0f) promoted(%.0f) major(%.0f) heap(%d w, %d c) live(%d w, %d b) free(%d w, %d b)"
			     gc.Gc.minor_words gc.Gc.promoted_words gc.Gc.major_words
			     gc.Gc.heap_words gc.Gc.heap_chunks
			     gc.Gc.live_words gc.Gc.live_blocks
			     gc.Gc.free_words gc.Gc.free_blocks
		)
		in

		let period_ops_interval = 15. in
		let period_start = ref 0. in

	let main_loop () =

		let mw = Connections.has_more_work cons in
		List.iter
			(fun c ->
			 match Connection.get_domain c with
			 | None -> () | Some d -> Domain.incr_io_credit d)
			mw;
		let timeout =
			if List.length mw > 0 then 0. else period_ops_interval in
		let inset, outset = Connections.select cons in
		let rset, wset, _ =
		try
			Select.select (spec_fds @ inset) outset [] timeout
		with Unix.Unix_error(Unix.EINTR, _, _) ->
			[], [], [] in
		let sfds, cfds =
			List.partition (fun fd -> List.mem fd spec_fds) rset in
		if List.length sfds > 0 then
			process_special_fds sfds;
		if List.length cfds > 0 || List.length wset > 0 then
			process_connection_fds store cons domains cfds wset;
		if timeout <> 0. then (
			let now = Unix.gettimeofday () in
			if now > !period_start +. period_ops_interval then
				(period_start := now; periodic_ops now)
		);
		process_domains store cons domains
		in

	Systemd.sd_notify_ready ();
	while not !quit
	do
		try
			main_loop ()
		with exc ->
			error "caught exception %s" (Printexc.to_string exc);
			if cf.reraise_top_level then
				raise exc
	done;
	info "stopping xenstored";
	DB.to_file store cons (Paths.xen_run_stored ^ "/db");
	()
