(** Process.mli
 *
 *  process context interface
 *
 *  @author copyright (c) 2005 alex ho
 *  @see <www.cl.cam.ac.uk/netos/pdb> pervasive debugger
 *  @version 1
 *)

type context_t

val default_context : context_t
val new_context : int -> int -> context_t

val set_domain : context_t -> int -> unit
val get_domain : context_t -> int
val set_process : context_t -> int -> unit
val get_process : context_t -> int

val string_of_context : context_t -> string
