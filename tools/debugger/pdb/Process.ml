(** Process.ml
 *
 *  process context implementation
 *
 *  @author copyright (c) 2005 alex ho
 *  @see <www.cl.cam.ac.uk/netos/pdb> pervasive debugger
 *  @version 1
 *)

open Int32
open Intel

type context_t =
{
  mutable domain  : int;
  mutable process : int;
  mutable evtchn  : int;
  mutable ring    : int32;
}

let default_context = { domain = 0; process = 0; evtchn = 0; ring = 0l }

let new_context dom proc = { domain = dom; process = proc; 
                             evtchn = 0; ring = 0l }

let string_of_context ctx =
  Printf.sprintf "{process} domain: %d, process: %d"
                 ctx.domain  ctx.process

let set_domain ctx value =
  ctx.domain <- value;
  print_endline (Printf.sprintf "ctx.domain <- %d" ctx.domain)

let set_process ctx value =
  ctx.process <- value;
  print_endline (Printf.sprintf "ctx.process <- %d" ctx.process)

let get_domain ctx =
  ctx.domain

let get_process ctx =
  ctx.process

external _attach_debugger : context_t -> unit = "proc_attach_debugger"
external detach_debugger : context_t -> unit = "proc_detach_debugger"
external pause_target : context_t -> unit = "proc_pause_target"

(* save the event channel and ring for the domain for future use *)
let attach_debugger proc_ctx dom_ctx =
  print_endline (Printf.sprintf "%d %lx"
    (Xen_domain.get_evtchn dom_ctx)
    (Xen_domain.get_ring dom_ctx));
  proc_ctx.evtchn <- Xen_domain.get_evtchn dom_ctx;
  proc_ctx.ring   <- Xen_domain.get_ring   dom_ctx;
  _attach_debugger proc_ctx

external read_registers : context_t -> unit = "proc_read_registers"
external write_register : context_t -> register -> int32 -> unit =
  "proc_write_register"
external read_memory : context_t -> int32 -> int -> unit = 
  "proc_read_memory"
external write_memory : context_t -> int32 -> int list -> unit = 
  "proc_write_memory"

external continue : context_t -> unit = "proc_continue_target"
external step : context_t -> unit = "proc_step_target"

external insert_memory_breakpoint : context_t -> int32 -> int -> unit = 
  "proc_insert_memory_breakpoint"
external remove_memory_breakpoint : context_t -> int32 -> int -> unit = 
  "proc_remove_memory_breakpoint"

let pause ctx =
  pause_target ctx
