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
  mutable domain : int;
  mutable process : int;
}

let default_context = { domain = 0; process = 0 }

let new_context dom proc = { domain = dom; process = proc }

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
