module Op :
  sig
    type operation =
      Op.operation =
        Debug
      | Directory
      | Read
      | Getperms
      | Watch
      | Unwatch
      | Transaction_start
      | Transaction_end
      | Introduce
      | Release
      | Getdomainpath
      | Write
      | Mkdir
      | Rm
      | Setperms
      | Watchevent
      | Error
      | Isintroduced
      | Resume
      | Set_target
      | Restrict
      | Invalid
    val operation_c_mapping : operation array
    val size : int
    val array_search : 'a -> 'a array -> int
    val of_cval : int -> operation
    val to_cval : operation -> int
    val to_string : operation -> string
  end
module Packet :
  sig
    type t =
      Packet.t = {
      tid : int;
      rid : int;
      ty : Op.operation;
      data : string;
    }
    exception Error of string
    exception DataError of string
    external string_of_header : int -> int -> int -> int -> string
      = "stub_string_of_header"
    val create : int -> int -> Op.operation -> string -> t
    val of_partialpkt : Partial.pkt -> t
    val to_string : t -> string
    val unpack : t -> int * int * Op.operation * string
    val get_tid : t -> int
    val get_ty : t -> Op.operation
    val get_data : t -> string
    val get_rid : t -> int
  end
exception End_of_file
exception Eagain
exception Noent
exception Invalid
exception Reconnect
type backend_mmap = {
  mmap : Xenmmap.mmap_interface;
  eventchn_notify : unit -> unit;
  mutable work_again : bool;
}
type backend_fd = { fd : Unix.file_descr; }
type backend = Fd of backend_fd | Xenmmap of backend_mmap
type partial_buf = HaveHdr of Partial.pkt | NoHdr of int * string
type t = {
  backend : backend;
  pkt_in : Packet.t Queue.t;
  pkt_out : Packet.t Queue.t;
  mutable partial_in : partial_buf;
  mutable partial_out : string;
}
val init_partial_in : unit -> partial_buf
val reconnect : t -> unit
val queue : t -> Packet.t -> unit
val read_fd : backend_fd -> 'a -> string -> int -> int
val read_mmap : backend_mmap -> 'a -> string -> int -> int
val read : t -> string -> int -> int
val write_fd : backend_fd -> 'a -> string -> int -> int
val write_mmap : backend_mmap -> 'a -> string -> int -> int
val write : t -> string -> int -> int
val output : t -> bool
val input : t -> bool
val newcon : backend -> t
val open_fd : Unix.file_descr -> t
val open_mmap : Xenmmap.mmap_interface -> (unit -> unit) -> t
val close : t -> unit
val is_fd : t -> bool
val is_mmap : t -> bool
val output_len : t -> int
val has_new_output : t -> bool
val has_old_output : t -> bool
val has_output : t -> bool
val peek_output : t -> Packet.t
val input_len : t -> int
val has_in_packet : t -> bool
val get_in_packet : t -> Packet.t
val has_more_input : t -> bool
val is_selectable : t -> bool
val get_fd : t -> Unix.file_descr
