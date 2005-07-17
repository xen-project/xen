(** Process.mli
 *
 *  process context interface
 *
 *  @author copyright (c) 2005 alex ho
 *  @see <www.cl.cam.ac.uk/netos/pdb> pervasive debugger
 *  @version 1
 *)

open Int32
open Intel

type context_t

val default_context : context_t
val new_context : int -> int -> context_t

val set_domain : context_t -> int -> unit
val get_domain : context_t -> int
val set_process : context_t -> int -> unit
val get_process : context_t -> int

val string_of_context : context_t -> string

val attach_debugger : context_t -> Xen_domain.context_t -> unit
val detach_debugger : context_t -> unit
val pause : context_t -> unit


val read_registers : context_t -> unit
val write_register : context_t -> register -> int32 -> unit
val read_memory : context_t -> int32 -> int -> int list
val write_memory : context_t -> int32 -> int list -> unit
	
val continue : context_t -> unit
val step : context_t -> unit

val insert_memory_breakpoint : context_t -> int32 -> int -> unit
val remove_memory_breakpoint : context_t -> int32 -> int -> unit
