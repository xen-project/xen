(** Domain.ml
 *
 *  domain context implementation
 *
 *  @author copyright (c) 2005 alex ho
 *  @see <www.cl.cam.ac.uk/netos/pdb> pervasive debugger
 *  @version 1
 *)

open Int32
open Intel

type context_t =
{
  mutable domain : int;
  mutable execution_domain : int
}

let default_context = { domain = 0; execution_domain = 0 }

let new_context dom exec_dom = {domain = dom; execution_domain = exec_dom}

let set_domain ctx value =
  ctx.domain <- value;
  print_endline (Printf.sprintf "ctx.domain <- %d" ctx.domain)

let set_execution_domain ctx value =
  ctx.execution_domain <- value;
  print_endline (Printf.sprintf "ctx.execution_domain <- %d"
		 ctx.execution_domain)

let get_domain ctx =
  ctx.domain

let get_execution_domain ctx =
  ctx.execution_domain

let string_of_context ctx =
      Printf.sprintf "{domain} domain: %d, execution_domain: %d"
                      ctx.domain  ctx.execution_domain

external read_registers : context_t -> registers = "read_registers"
external write_register : context_t -> register -> int32 -> unit =
  "write_register"
external read_memory : context_t -> int32 -> int -> int list = 
  "read_memory"
external write_memory : context_t -> int32 -> int list -> unit = 
  "write_memory"
	
external continue : context_t -> unit = "continue_target"
external step : context_t -> unit = "step_target"

external insert_memory_breakpoint : context_t -> int32 -> int -> unit = 
  "insert_memory_breakpoint"
external remove_memory_breakpoint : context_t -> int32 -> int -> unit = 
  "remove_memory_breakpoint"

external attach_debugger : int -> int -> unit = "attach_debugger"
external detach_debugger : int -> int -> unit = "detach_debugger"
external pause_target : int -> unit = "pause_target"

let pause ctx =
  pause_target ctx.domain
