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

let push (x: history_record) =
	let dom = x.con.Connection.dom in
	match dom with
	| None -> () (* treat socket connections as always free to conflict *)
	| Some d -> if not (Domain.is_free_to_conflict d) then history := x :: !history
