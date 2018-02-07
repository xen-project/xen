type pkt = {
  tid : int;
  rid : int;
  ty : Op.operation;
  len : int;
  buf : Buffer.t;
}
external header_size : unit -> int = "stub_header_size"
external header_of_string_internal : string -> int * int * int * int
  = "stub_header_of_string"
val xenstore_payload_max : int
val of_string : string -> pkt
val append : pkt -> string -> int -> unit
val to_complete : pkt -> int
