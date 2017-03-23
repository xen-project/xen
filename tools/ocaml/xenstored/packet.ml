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
