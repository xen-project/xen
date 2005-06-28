(** Xen_domain.ml
 *
 *  domain assist for debugging processes
 *
 *  @author copyright (c) 2005 alex ho
 *  @see <www.cl.cam.ac.uk/netos/pdb> pervasive debugger
 *  @version 1
 *)

type context_t =
{
  mutable domain : int;
  mutable evtchn : int;
  mutable pdb_front_ring : int32
}

let default_context = { domain = 0; evtchn = 0; pdb_front_ring = 0l }

let new_context dom evtchn ring = 
  {domain = dom; evtchn = evtchn; pdb_front_ring = ring}

let set_domain ctx value =
  ctx.domain <- value

let set_evtchn ctx value =
  ctx.evtchn <- value

let set_ring ctx value =
  ctx.pdb_front_ring <- value

let get_domain ctx =
  ctx.domain

let get_evtchn ctx =
  ctx.evtchn

let get_ring ctx =
  ctx.pdb_front_ring

let string_of_context ctx =
      Printf.sprintf "{xen domain assist} domain: %d" ctx.domain 

external process_response : int32 -> unit = "process_handle_response"
