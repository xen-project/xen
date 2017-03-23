type request = {
	tid: int;
	rid: int;
	ty: Xenbus.Xb.Op.operation;
	data: string;
}

type response =
	| Ack of (unit -> unit)  (* function is the action to execute after sending the ack *)
	| Reply of string
	| Error of string

let response_equal a b =
	match (a, b) with
	| (Ack _, Ack _) -> true (* just consider the response, not the post-response action *)
	| (x, y) -> x = y
