(** evtchn.mli
 *
 *  event channel interface
 *
 *  @author copyright (c) 2005 alex ho
 *  @see <www.cl.cam.ac.uk/netos/pdb> pervasive debugger
 *  @version 1
 *)


val setup : unit -> Unix.file_descr
val read : Unix.file_descr -> int
val teardown : Unix.file_descr -> unit
val unmask : Unix.file_descr -> int -> unit
