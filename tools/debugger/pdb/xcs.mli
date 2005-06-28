(** xcs.mli
 *
 *  xen control switch interface
 *
 *  @author copyright (c) 2005 alex ho
 *  @see <www.cl.cam.ac.uk/netos/pdb> pervasive debugger
 *  @version 1
 *)


val setup : unit -> Unix.file_descr
val read : Unix.file_descr -> Unix.file_descr * int * int * int32
val teardown : Unix.file_descr -> unit
