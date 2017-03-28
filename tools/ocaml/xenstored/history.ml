(*
 * Copyright (c) 2017 Citrix Systems Ltd.
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

type history_record = {
	con: Connection.t;   (* connection that made a change *)
	tid: int;            (* transaction id of the change (may be Transaction.none) *)
	before: Store.t;     (* the store before the change *)
	after: Store.t;      (* the store after the change *)
	finish_count: int64; (* the commit-count at which the transaction finished *)
}

let history : history_record list ref = ref []

(* Called from periodic_ops to ensure we don't discard symbols that are still needed. *)
(* There is scope for optimisation here, since in consecutive commits one commit's `after`
 * is the same thing as the next commit's `before`, but not all commits in history are
 * consecutive. *)
let mark_symbols () =
	(* There are gaps where dom0's commits are missing. Otherwise we could assume that
	 * each element's `before` is the same thing as the next element's `after`
	 * since the next element is the previous commit *)
	List.iter (fun hist_rec ->
			Store.mark_symbols hist_rec.before;
			Store.mark_symbols hist_rec.after;
		)
		!history

(* Keep only enough commit-history to protect the running transactions that we are still tracking *)
(* There is scope for optimisation here, replacing List.filter with something more efficient,
 * probably on a different list-like structure. *)
let trim ?txn () =
	Transaction.trim_short_running_transactions txn;
	history := match Transaction.oldest_short_running_transaction () with
	| None -> [] (* We have no open transaction, so no history is needed *)
	| Some (_, txn) -> (
		(* keep records with finish_count recent enough to be relevant *)
		List.filter (fun r -> r.finish_count > txn.Transaction.start_count) !history
	)

let end_transaction txn con tid commit =
	let success = Connection.end_transaction con tid commit in
	trim ~txn ();
	success

let push (x: history_record) =
	let dom = x.con.Connection.dom in
	match dom with
	| None -> () (* treat socket connections as always free to conflict *)
	| Some d -> if not (Domain.is_free_to_conflict d) then history := x :: !history

(* Find the connections from records since commit-count [since] for which [f record] returns [true] *)
let filter_connections ~ignore ~since ~f =
	(* The "mem" call is an optimisation, to avoid calling f if we have picked con already. *)
	(* Using a hash table rather than a list is to optimise the "mem" call. *)
	List.fold_left (fun acc hist_rec ->
		if hist_rec.finish_count > since
		&& not (hist_rec.con == ignore)
		&& not (Hashtbl.mem acc hist_rec.con)
		&& f hist_rec
		then Hashtbl.replace acc hist_rec.con ();
		acc
	) (Hashtbl.create 1023) !history
