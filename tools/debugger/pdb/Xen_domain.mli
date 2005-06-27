
type context_t

val default_context : context_t
val new_context : int -> int -> int32 -> context_t 

val set_domain : context_t -> int -> unit
val get_domain : context_t -> int
val set_evtchn : context_t -> int -> unit
val get_evtchn : context_t -> int
val set_ring   : context_t -> int32 -> unit
val get_ring   : context_t -> int32

val string_of_context : context_t -> string

val process_response : int32 -> unit

