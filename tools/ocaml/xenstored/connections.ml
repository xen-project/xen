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

let debug fmt = Logging.debug "connections" fmt

type t = {
  anonymous: (Unix.file_descr, Connection.t) Hashtbl.t;
  domains: (int, Connection.t) Hashtbl.t;
  ports: (Xeneventchn.t, Connection.t) Hashtbl.t;
  mutable watches: Connection.watch list Trie.t;
  mutable has_pending_watchevents: Connection.Watch.Set.t
}

let create () = {
  anonymous = Hashtbl.create 37;
  domains = Hashtbl.create 37;
  ports = Hashtbl.create 37;
  watches = Trie.create ();
  has_pending_watchevents = Connection.Watch.Set.empty;
}

let get_capacity () =
  (* not multiplied by maxwatch on purpose: 2nd queue in watch itself! *)
  { Xenbus.Xb.maxoutstanding = !Define.maxoutstanding; maxwatchevents = !Define.maxwatchevents }

let add_anonymous cons fd =
  let capacity = get_capacity () in
  let xbcon = Xenbus.Xb.open_fd fd ~capacity in
  let con = Connection.create xbcon None in
  Hashtbl.add cons.anonymous (Xenbus.Xb.get_fd xbcon) con

let add_domain cons dom =
  let capacity = get_capacity () in
  let xbcon = Xenbus.Xb.open_mmap ~capacity (Domain.get_interface dom) (fun () -> Domain.notify dom) in
  let con = Connection.create xbcon (Some dom) in
  Hashtbl.add cons.domains (Domain.get_id dom) con;
  Hashtbl.add cons.ports (Domain.get_local_port dom) con

let select ?(only_if = (fun _ -> true)) cons =
  Hashtbl.fold (fun _ con (ins, outs) ->
      if (only_if con) then (
        let fd = Connection.get_fd con in
        let in_fds = if Connection.can_input con then fd :: ins else ins in
        let out_fds = if Connection.has_output con then fd :: outs else outs in
        in_fds, out_fds
      ) else (ins, outs)
    )
    cons.anonymous ([], [])

let find cons =
  Hashtbl.find cons.anonymous

let find_domain cons =
  Hashtbl.find cons.domains

let find_domain_by_port cons port =
  Hashtbl.find cons.ports port

let del_watches_of_con con watches =
  match List.filter (fun w -> Connection.get_con w != con) watches with
  | [] -> None
  | ws -> Some ws

let del_watches cons con =
  Connection.del_watches con;
  cons.watches <- Trie.map (del_watches_of_con con) cons.watches;
  cons.has_pending_watchevents <-
    cons.has_pending_watchevents |> Connection.Watch.Set.filter @@ fun w ->
    Connection.get_con w != con

let del_anonymous cons con =
  try
    Hashtbl.remove cons.anonymous (Connection.get_fd con);
    del_watches cons con;
    Connection.close con
  with exn ->
    debug "del anonymous %s" (Printexc.to_string exn)

let del_domain cons id =
  try
    let con = find_domain cons id in
    Hashtbl.remove cons.domains id;
    (match Connection.get_domain con with
     | Some d -> Hashtbl.remove cons.ports (Domain.get_local_port d)
     | None -> ());
    del_watches cons con;
    Connection.close con
  with exn ->
    debug "del domain %u: %s" id (Printexc.to_string exn)

let iter_domains cons fct =
  Hashtbl.iter (fun _ c -> fct c) cons.domains

let iter_anonymous cons fct =
  Hashtbl.iter (fun _ c -> fct c) cons.anonymous

let iter cons fct =
  iter_domains cons fct; iter_anonymous cons fct

let has_more_work cons =
  Hashtbl.fold
    (fun _id con acc ->
       if Connection.has_more_work con then con :: acc else acc)
    cons.domains []

let key_of_str path =
  if path.[0] = '@'
  then [path]
  else "" :: Store.Path.to_string_list (Store.Path.of_string path)

let key_of_path path =
  "" :: Store.Path.to_string_list path

let add_watch cons con path token =
  let apath = Connection.get_watch_path con path in
  (* fail on invalid paths early by calling key_of_str before adding watch *)
  let key = key_of_str apath in
  let watch = Connection.add_watch con (path, apath) token in
  let watches =
    if Trie.mem cons.watches key
    then Trie.find cons.watches key
    else []
  in
  cons.watches <- Trie.set cons.watches key (watch :: watches);
  watch

let del_watch cons con path token =
  let apath, watch = Connection.del_watch con path token in
  let key = key_of_str apath in
  let watches = Utils.list_remove watch (Trie.find cons.watches key) in
  if watches = [] then
    cons.watches <- Trie.unset cons.watches key
  else
    cons.watches <- Trie.set cons.watches key watches;
  watch

(* path is absolute *)
let fire_watches ?oldroot source root cons path recurse =
  let key = key_of_path path in
  let path = Store.Path.to_string path in
  let roots = oldroot, root in
  let fire_watch _ = function
    | None         -> ()
    | Some watches -> List.iter (fun w -> Connection.fire_watch source roots w path) watches
  in
  let fire_rec _x = function
    | None         -> ()
    | Some watches ->
      List.iter (Connection.fire_single_watch source roots) watches
  in
  Trie.iter_path fire_watch cons.watches key;
  if recurse then
    Trie.iter fire_rec (Trie.sub cons.watches key)

let send_watchevents cons con =
  cons.has_pending_watchevents <-
    cons.has_pending_watchevents |> Connection.Watch.Set.filter Connection.Watch.flush_events;
  Connection.source_flush_watchevents con

let fire_spec_watches root cons specpath =
  let source = find_domain cons 0 in
  iter cons (fun con ->
      List.iter (Connection.fire_single_watch source (None, root)) (Connection.get_watches con specpath))

let set_target cons domain target_domain =
  let con = find_domain cons domain in
  Connection.set_target con target_domain

let number_of_transactions cons =
  let res = ref 0 in
  let aux con =
    res := Connection.number_of_transactions con + !res
  in
  iter cons aux;
  !res

let stats cons =
  let nb_ops_anon = ref 0
  and nb_watchs_anon = ref 0
  and nb_ops_dom = ref 0
  and nb_watchs_dom = ref 0 in
  iter_anonymous cons (fun con ->
      let con_watchs, con_ops = Connection.stats con in
      nb_ops_anon := !nb_ops_anon + con_ops;
      nb_watchs_anon := !nb_watchs_anon + con_watchs;
    );
  iter_domains cons (fun con ->
      let con_watchs, con_ops = Connection.stats con in
      nb_ops_dom := !nb_ops_dom + con_ops;
      nb_watchs_dom := !nb_watchs_dom + con_watchs;
    );
  (Hashtbl.length cons.anonymous, !nb_ops_anon, !nb_watchs_anon,
   Hashtbl.length cons.domains, !nb_ops_dom, !nb_watchs_dom)

let debug cons =
  let anonymous = Hashtbl.fold (fun _ con accu -> Connection.debug con :: accu) cons.anonymous [] in
  let domains = Hashtbl.fold (fun _ con accu -> Connection.debug con :: accu) cons.domains [] in
  String.concat "" (domains @ anonymous)

let debug_watchevents cons con =
  (* == (physical equality)
     	   has to be used here because w.con.xb.backend might contain a [unit->unit] value causing regular
     	   comparison to fail due to having a 'functional value' which cannot be compared.
     	 *)
  let s = cons.has_pending_watchevents |> Connection.Watch.Set.filter (fun w -> w.con == con) in
  let pending = s |> Connection.Watch.Set.elements
                |> List.map (fun w -> Connection.Watch.pending_watchevents w) |> List.fold_left (+) 0 in
  Printf.sprintf "Watches with pending events: %d, pending events total: %d" (Connection.Watch.Set.cardinal s) pending

let filter ~f cons =
  let fold _ v acc = if f v then v :: acc else acc in
  []
  |> Hashtbl.fold fold cons.anonymous
  |> Hashtbl.fold fold cons.domains

let prevents_quit cons = filter ~f:Connection.prevents_live_update cons
