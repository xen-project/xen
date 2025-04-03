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
let warn fmt = Logging.warn "xenstored" fmt
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
    if Domain.is_bad_domain domain
    || Domain.get_io_credit domain <= 0
    || Domain.is_paused_for_conflict domain
    then () (* nothing to do *)
    else (
      let con = Connections.find_domain cons (Domain.get_id domain) in
      Process.do_input store cons domains con;
      Process.do_output store cons domains con;
      Domain.decr_io_credit domain
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

let parse_config ?(strict=false) filename =
  let pidfile = ref default_pidfile in
  let options = [
    ("merge-activate", Config.Set_bool Transaction.do_coalesce);
    ("conflict-burst-limit", Config.Set_float Define.conflict_burst_limit);
    ("conflict-max-history-seconds", Config.Set_float Define.conflict_max_history_seconds);
    ("conflict-rate-limit-is-aggregate", Config.Set_bool Define.conflict_rate_limit_is_aggregate);
    ("perms-activate", Config.Set_bool Perms.activate);
    ("perms-watch-activate", Config.Set_bool Perms.watch_activate);
    ("quota-activate", Config.Set_bool Quota.activate);
    ("quota-maxwatch", Config.Set_int Define.maxwatch);
    ("quota-transaction", Config.Set_int Define.maxtransaction);
    ("quota-maxentity", Config.Set_int Quota.maxent);
    ("quota-maxsize", Config.Set_int Quota.maxsize);
    ("quota-maxrequests", Config.Set_int Define.maxrequests);
    ("quota-maxoutstanding", Config.Set_int Define.maxoutstanding);
    ("quota-maxwatchevents", Config.Set_int Define.maxwatchevents);
    ("quota-path-max", Config.Set_int Define.path_max);
    ("gc-max-overhead", Config.Set_int Define.gc_max_overhead);
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
    ("pid-file", Config.Set_string pidfile);
    ("xenstored-kva", Config.Set_string Domains.xenstored_kva);
    ("xenstored-port", Config.Set_string Domains.xenstored_port); ] in
  begin try Config.read filename options (fun _ _ -> raise Not_found)
    with
    | Config.Error err as e -> List.iter (fun (k, e) ->
        match e with
        | "unknown key" -> eprintf "config: unknown key %s\n" k
        | _             -> eprintf "config: %s: %s\n" k e
      ) err;
      if strict then raise e
    | Sys_error m -> eprintf "error: config: %s\n" m;
  end;
  !pidfile

module DB = struct

  exception Bad_format of string

  let dump_format_header = "$xenstored-dump-format"

  let from_channel_f chan global_f evtchn_f socket_f domain_f watch_f store_f =
    let unhexify s = Utils.unhexify s in
    let getpath s =
      let u = Utils.unhexify s in
      debug "Path: %s" u;
      Store.Path.of_string u in
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
          | "global" :: rw :: _ ->
            (* there might be more parameters here,
               					   e.g. a RO socket from a previous version: ignore it *)
            global_f ~rw
          | "evtchn-dev" :: fd :: domexc_port :: [] ->
            evtchn_f ~fd:(int_of_string fd)
              ~domexc_port:(int_of_string domexc_port)
          | "socket" :: fd :: [] ->
            socket_f ~fd:(int_of_string fd)
          | "dom" :: domid :: mfn :: remote_port :: rest ->
            let local_port = match rest with
              | [] -> None (* backward compat: old version didn't have it *)
              | local_port :: _ -> Some (int_of_string local_port) in
            domain_f ?local_port
              ~remote_port:(int_of_string remote_port)
              (int_of_string domid)
              (Nativeint.of_string mfn)
          | "watch" :: domid :: path :: token :: [] ->
            watch_f (int_of_string domid)
              (unhexify path) (unhexify token)
          | "store" :: path :: perms :: value :: [] ->
            store_f (getpath path)
              (Perms.Node.of_string (unhexify perms ^ "\000"))
              (unhexify value)
          | _ ->
            warn "restoring: ignoring unknown line: %s" line
        with exn ->
          warn "restoring: ignoring unknown line: %s (exception: %s)"
            line (Printexc.to_string exn);
          ()
      with End_of_file ->
        quit := true
    done;
    info "Completed loading xenstore dump"

  let from_channel store cons domains_init chan =
    (* don't let the permission get on our way, full perm ! *)
    let op = Store.get_ops store Perms.Connection.full_rights in
    let rwro = ref (None) in
    let doms = ref (None) in

    let require_doms () =
      match !doms with
      | None ->
        warn "No event channel file descriptor available in dump!";
        let domains = domains_init @@ Event.init () in
        doms := Some domains;
        domains
      | Some d -> d
    in
    let global_f ~rw =
      let get_listen_sock sockfd =
        let fd = sockfd |> int_of_string |> Utils.FD.of_int in
        Unix.listen fd 1;
        Some fd
      in
      rwro := get_listen_sock rw
    in
    let evtchn_f ~fd ~domexc_port =
      let evtchn = Event.init ~fd ~domexc_port () in
      doms := Some(domains_init evtchn)
    in
    let socket_f ~fd =
      let ufd = Utils.FD.of_int fd in
      let is_valid = try (Unix.fstat ufd).Unix.st_kind = Unix.S_SOCK with _ -> false in
      if is_valid then
        Connections.add_anonymous cons ufd
      else
        warn "Ignoring invalid socket FD %d" fd
    in
    let domain_f ?local_port ~remote_port domid mfn =
      let doms = require_doms () in
      let ndom =
        if domid > 0 then
          Domains.create ?local_port ~remote_port doms domid mfn
        else
          Domains.create0 ?local_port doms
      in
      Connections.add_domain cons ndom;
    in
    let get_con id =
      if id < 0 then Connections.find cons (Utils.FD.of_int (-id))
      else Connections.find_domain cons id
    in
    let watch_f id path token =
      ignore (Connections.add_watch cons (get_con id) path token)
    in
    let store_f path perms value =
      op.Store.write path value;
      op.Store.setperms path perms
    in
    from_channel_f chan global_f evtchn_f socket_f domain_f watch_f store_f;
    !rwro, require_doms ()

  let from_file store cons doms file =
    info "Loading xenstore dump from %s" file;
    let channel = open_in file in
    finally (fun () -> from_channel store doms cons channel)
      (fun () -> close_in channel)

  let to_channel store cons (rw, evtchn) chan =
    let hexify s = Utils.hexify s in

    fprintf chan "%s\n" dump_format_header;
    let fdopt = function None -> -1 | Some fd ->
      (* systemd and utils.ml sets it close on exec *)
      Unix.clear_close_on_exec fd;
      Utils.FD.to_int fd in
    fprintf chan "global,%d\n" (fdopt rw);

    (* dump evtchn device info *)
    Event.dump evtchn chan;

    (* dump connections related to domains: domid, mfn, eventchn port/ sockets, and watches *)
    Connections.iter cons (fun con -> Connection.dump con chan);

    (* dump the store *)
    Store.dump_fct store (fun path node ->
        let name, perms, value = Store.Node.unpack node in
        let fullpath = Store.Path.to_string (Store.Path.of_path_and_name path name) in
        let permstr = Perms.Node.to_string perms in
        fprintf chan "store,%s,%s,%s\n" (hexify fullpath) (hexify permstr) (hexify value)
      );
    flush chan;
    ()


  let to_file store cons fds file =
    let channel = open_out_gen [ Open_wronly; Open_creat; Open_trunc; ] 0o600 file in
    finally (fun () -> to_channel store cons fds channel)
      (fun () -> close_out channel)
end

(*
	By default OCaml's GC only returns memory to the OS when it exceeds a
	configurable 'max overhead' setting.
	The default is 500%, that is 5/6th of the OCaml heap needs to be free
	and only 1/6th live for a compaction to be triggerred that would
	release memory back to the OS.
	If the limit is not hit then the OCaml process can reuse that memory
	for its own purposes, but other processes won't be able to use it.

	There is also a 'space overhead' setting that controls how much work
	each major GC slice does, and by default aims at having no more than
	80% or 120% (depending on version) garbage values compared to live
	values.
	This doesn't have as much relevance to memory returned to the OS as
	long as space_overhead <= max_overhead, because compaction is only
	triggerred at the end of major GC cycles.

	The defaults are too large once the program starts using ~100MiB of
	memory, at which point ~500MiB would be unavailable to other processes
	(which would be fine if this was the main process in this VM, but it is
	not).

	Max overhead can also be set to 0, however this is for testing purposes
	only (setting it lower than 'space overhead' wouldn't help because the
	major GC wouldn't run fast enough, and compaction does have a
	performance cost: we can only compact contiguous regions, so memory has
	to be moved around).

	Max overhead controls how often the heap is compacted, which is useful
	if there are burst of activity followed by long periods of idle state,
	or if a domain quits, etc. Compaction returns memory to the OS.

	wasted = live * space_overhead / 100

	For globally overriding the GC settings one can use OCAMLRUNPARAM,
	however we provide a config file override to be consistent with other
	oxenstored settings.

	One might want to dynamically adjust the overhead setting based on used
	memory, i.e. to use a fixed upper bound in bytes, not percentage. However
	measurements show that such adjustments increase GC overhead massively,
	while still not guaranteeing that memory is returned any more quickly
	than with a percentage based setting.

	The allocation policy could also be tweaked, e.g. first fit would reduce
	fragmentation and thus memory usage, but the documentation warns that it
	can be sensibly slower, and indeed one of our own testcases can trigger
	such a corner case where it is multiple times slower, so it is best to keep
	the default allocation policy (next-fit/best-fit depending on version).

	There are other tweaks that can be attempted in the future, e.g. setting
	'ulimit -v' to 75% of RAM, however getting the kernel to actually return
	NULL from allocations is difficult even with that setting, and without a
	NULL the emergency GC won't be triggerred.
	Perhaps cgroup limits could help, but for now tweak the safest only.
*)

let tweak_gc () =
  Gc.set { (Gc.get ()) with Gc.max_overhead = !Define.gc_max_overhead }


let () =
  Printexc.set_uncaught_exception_handler Logging.fallback_exception_handler;
  let cf = do_argv in
  if cf.config_test then begin
    let path = config_filename cf in
    let _pidfile:string = parse_config ~strict:true path in
    Printf.printf "Configuration valid at %s\n%!" path;
    exit 0
  end;
  let pidfile =
    if Sys.file_exists (config_filename cf) then
      parse_config (config_filename cf)
    else
      default_pidfile
  in

  tweak_gc ();

  (try
     Unixext.mkdir_rec (Filename.dirname pidfile) 0o755
   with _ ->
     ()
  );

  let rw_sock =
    if cf.disable_socket || cf.live_reload then
      None
    else
      Some (Unix.handle_unix_error Utils.create_unix_socket Define.xs_daemon_socket)
  in

  if cf.daemonize && not cf.live_reload then
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
  let next_frequent_ops = ref 0. in
  let advance_next_frequent_ops () =
    next_frequent_ops := (Unix.gettimeofday () +. !Define.conflict_max_history_seconds)
  in
  let delay_next_frequent_ops_by duration =
    next_frequent_ops := !next_frequent_ops +. duration
  in
  let domains_init eventchn = Domains.init eventchn advance_next_frequent_ops in

  let cons = Connections.create () in

  let quit = ref false in

  Logging.init_xenstored_log();
  List.iter (fun path ->
      Store.write store Perms.Connection.full_rights path "") Store.Path.specials;

  let rw_sock, domains =
    if cf.restart && Sys.file_exists Disk.xs_daemon_database then (
      let rw, domains = DB.from_file store domains_init cons Disk.xs_daemon_database in
      info "Live reload: database loaded";
      Process.LiveUpdate.completed ();
      rw, domains
    ) else (
      info "No live reload: regular startup";
      let domains = domains_init @@ Event.init () in
      if !Disk.enable then (
        info "reading store from disk";
        Disk.read store
      );

      let localpath = Store.Path.of_string "/local" in
      if not (Store.path_exists store localpath) then
        Store.mkdir store (Perms.Connection.create 0) localpath;

      if cf.domain_init then (
        Connections.add_domain cons (Domains.create0 domains);
      );
      rw_sock, domains
    ) in

  (* For things that need to be done periodically but more often
     	 * than the periodic_ops function *)
  let frequent_ops () =
    if Unix.gettimeofday () > !next_frequent_ops then (
      History.trim ();
      Domains.incr_conflict_credit domains;
      advance_next_frequent_ops ()
    ) in

  (* required for xenstore-control to detect availability of live-update *)
  let tool_path = Store.Path.of_string "/tool" in
  if not (Store.path_exists store tool_path) then
    Store.mkdir store Perms.Connection.full_rights tool_path;
  Store.write store Perms.Connection.full_rights
    (Store.Path.of_string "/tool/xenstored") Sys.executable_name;

  Sys.set_signal Sys.sighup (Sys.Signal_handle sighup_handler);
  Sys.set_signal Sys.sigterm (Sys.Signal_handle (fun _ ->
      info "Received SIGTERM";
      quit := true));
  Sys.set_signal Sys.sigusr1 (Sys.Signal_handle (fun _ -> sigusr1_handler store));
  Sys.set_signal Sys.sigpipe Sys.Signal_ignore;

  let eventchn = Domains.eventchn domains in

  if cf.activate_access_log then begin
    let post_rotate () = DB.to_file store cons (None, eventchn) Disk.xs_daemon_database in
    Logging.init_access_log post_rotate
  end;

  let spec_fds =
    (match rw_sock with None -> [] | Some x -> [ x ]) @
    (if cf.domain_init then [ Event.fd eventchn ] else [])
  in

  let process_special_fds rset =
    let accept_connection fd =
      let (cfd, _addr) = Unix.accept fd in
      debug "new connection through socket";
      Connections.add_anonymous cons cfd
    and handle_eventchn _fd =
      let port = Event.pending eventchn in
      debug "pending port %d" (Xeneventchn.to_int port);
      finally (fun () ->
          if port = eventchn.Event.domexc then (
            let (notify, deaddom) = Domains.cleanup domains in
            List.iter (Store.reset_permissions store) deaddom;
            List.iter (Connections.del_domain cons) deaddom;
            if deaddom <> [] || notify then
              Connections.fire_spec_watches
                (Store.get_root store)
                cons Store.Path.release_domain
          )
          else
            let c = Connections.find_domain_by_port cons port in
            match Connection.get_domain c with
            | Some dom -> Domain.incr_io_credit dom | None -> ()
        ) (fun () -> Event.unmask eventchn port)
    and do_if_set fd set fct =
      if List.mem fd set then
        fct fd in

    maybe (fun fd -> do_if_set fd rset accept_connection) rw_sock;
    do_if_set (Event.fd eventchn) rset (handle_eventchn)
  in

  let ring_scan_checker dom =
    (* no need to scan domains already marked as for processing *)
    if not (Domain.get_io_credit dom > 0) then (
      debug "Looking up domid %d" (Domain.get_id dom);
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
      )
    ) in

  let last_stat_time = ref 0. in
  let last_scan_time = ref 0. in

  let periodic_ops now =
    debug "periodic_ops starting";

    (* scan all the xs rings as a safenet for ill-behaved clients *)
    if !ring_scan_interval >= 0 && now > (!last_scan_time +. float !ring_scan_interval) then
      (last_scan_time := now; Domains.iter domains ring_scan_checker);

    (* make sure we don't print general stats faster than 2 min *)
    if now > (!last_stat_time +. 120.) then (
      info "Transaction conflict statistics for last %F seconds:" (now -. !last_stat_time);
      last_stat_time := now;
      Domains.iter domains (Domain.log_and_reset_conflict_stats (info "Dom%d caused %Ld conflicts"));
      info "%Ld failed transactions; of these no culprit was found for %Ld" !Transaction.failed_commits !Transaction.failed_commits_no_culprit;
      Transaction.reset_conflict_stats ();

      let gc = Gc.stat () in
      let (lanon, lanon_ops, lanon_watchs,
           ldom, ldom_ops, ldom_watchs) = Connections.stats cons in
      let store_nodes, store_abort, store_coalesce = Store.stats store in
      let symtbl_len, symtbl_entries = Symbol.stats () in

      info "store stat: nodes(%d) t-abort(%d) t-coalesce(%d)"
        store_nodes store_abort store_coalesce;
      info "sytbl stat: length(%d) entries(%d)" symtbl_len symtbl_entries;
      info "  con stat: anonymous(%d, %d o, %d w) domains(%d, %d o, %d w)"
        lanon lanon_ops lanon_watchs ldom ldom_ops ldom_watchs;
      info "  mem stat: minor(%.0f) promoted(%.0f) major(%.0f) heap(%d w, %d c) live(%d w, %d b) free(%d w, %d b)"
        gc.Gc.minor_words gc.Gc.promoted_words gc.Gc.major_words
        gc.Gc.heap_words gc.Gc.heap_chunks
        gc.Gc.live_words gc.Gc.live_blocks
        gc.Gc.free_words gc.Gc.free_blocks
    );
    let elapsed = Unix.gettimeofday () -. now in
    debug "periodic_ops took %F seconds." elapsed;
    if !quit then (
      match Connections.prevents_quit cons with
      | [] -> ()
      | domains -> List.iter (fun con -> warn "%s prevents live update"
                                 (Connection.get_domstr con)) domains
    );
    delay_next_frequent_ops_by elapsed
  in

  let period_ops_interval = 15. in
  let period_start = ref 0. in

  let main_loop () =
    let is_peaceful c =
      match Connection.get_domain c with
      | None -> true (* Treat socket-connections as exempt, and free to conflict. *)
      | Some dom -> not (Domain.is_paused_for_conflict dom)
    in
    frequent_ops ();
    let mw = Connections.has_more_work cons in
    let peaceful_mw = List.filter is_peaceful mw in
    List.iter
      (fun c ->
         match Connection.get_domain c with
         | None -> () | Some d -> Domain.incr_io_credit d)
      peaceful_mw;
    let start_time = Unix.gettimeofday () in
    let timeout =
      let until_next_activity =
        if Domains.all_at_max_credit domains
        then period_ops_interval
        else min (max 0. (!next_frequent_ops -. start_time)) period_ops_interval in
      if peaceful_mw <> [] then 0. else until_next_activity
    in
    let inset, outset = Connections.select ~only_if:is_peaceful cons in
    let rset, wset, _ =
      try
        Poll.poll_select (spec_fds @ inset) outset [] timeout
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
  let live_update = ref false in
  while not (!quit && Connections.prevents_quit cons = [])
  do
    try
      main_loop ();
      live_update := Process.LiveUpdate.should_run cons;
      if !live_update || !quit then begin
        (* don't initiate live update if saving state fails *)
        DB.to_file store cons (rw_sock, eventchn) Disk.xs_daemon_database;
        quit := true;
      end
    with exc ->
      let bt = Printexc.get_backtrace () in
      error "caught exception %s: %s" (Printexc.to_string exc) bt;
      if cf.reraise_top_level then
        raise exc
  done;
  info "stopping xenstored";
  (* unlink pidfile so that launch-xenstore works again *)
  Unixext.unlink_safe pidfile;
  (match cf.pidfile with Some pidfile -> Unixext.unlink_safe pidfile | None -> ());

  if !live_update then begin
    Logging.live_update ();
    Process.LiveUpdate.launch_exn !Process.LiveUpdate.state
  end
