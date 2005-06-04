(** evtchn.ml
 *
 *  event channel interface
 *
 *  @author copyright (c) 2005 alex ho
 *  @see <www.cl.cam.ac.uk/netos/pdb> pervasive debugger
 *  @version 1
 *)

let dev_name = "/dev/xen/evtchn"                          (* EVTCHN_DEV_NAME *)
let dev_major = 10                                       (* EVTCHN_DEV_MAJOR *)
let dev_minor = 201                                      (* EVTCHN_DEV_MINOR *)

let virq_pdb = 6                                      (* as defined VIRQ_PDB *)

external bind_virq : int -> int = "evtchn_bind_virq"
external bind : Unix.file_descr -> int -> unit = "evtchn_bind"
external unbind : Unix.file_descr -> int -> unit = "evtchn_unbind"
external ec_open : string -> int -> int -> Unix.file_descr = "evtchn_open"
external read : Unix.file_descr -> int = "evtchn_read"
external ec_close : Unix.file_descr -> unit = "evtchn_close"
external unmask : Unix.file_descr -> int -> unit = "evtchn_unmask"

let setup () =
  let port = bind_virq virq_pdb in
  let fd = ec_open dev_name dev_major dev_minor in
  bind fd port;
  fd

let teardown fd =
  unbind fd virq_pdb;
  ec_close fd
