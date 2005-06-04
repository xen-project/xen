(** PDB.ml
 *
 *  Dispatch debugger commands to the appropriate context
 *
 *  @author copyright (c) 2005 alex ho
 *  @see <www.cl.cam.ac.uk/netos/pdb> pervasive debugger
 *  @version 1
 *)

exception Unimplemented of string
exception Unknown_context of string
exception Unknown_domain

type context_t =
  | Void
  | Event_channel
  | Domain of Domain.context_t
  | Process of Process.context_t

let string_of_context ctx =
  match ctx with
  | Void -> "{void}"
  | Event_channel -> "{event channel}"
  | Domain d  -> Domain.string_of_context d
  | Process p -> Process.string_of_context p



let read_registers ctx =
  match ctx with
  | Domain d  -> Domain.read_registers d 
  | _ -> Intel.null_registers

let write_register ctx register value =
  match ctx with
  | Domain d  -> Domain.write_register d register value
  | _ -> raise (Unimplemented "write register")


let read_memory ctx addr len =
  match ctx with
  | Domain d  -> Domain.read_memory d addr len
  | _ -> raise (Unimplemented "read memory")

let write_memory ctx addr values =
  match ctx with
  | Domain d  -> Domain.write_memory d addr values
  | _ -> raise (Unimplemented "write memory")


let continue ctx =
  match ctx with
  | Domain d  -> Domain.continue d
  | _ -> raise (Unimplemented "continue")

let step ctx =
  match ctx with
  | Domain d  -> Domain.step d
  | _ -> raise (Unimplemented "step")


let insert_memory_breakpoint ctx addr len =
  match ctx with
  | Domain d  -> Domain.insert_memory_breakpoint d addr len
  | _ -> raise (Unimplemented "insert memory breakpoint")

let remove_memory_breakpoint ctx addr len =
  match ctx with
  | Domain d  -> Domain.remove_memory_breakpoint d addr len
  | _ -> raise (Unimplemented "remove memory breakpoint")


let pause ctx =
  match ctx with
  | Domain d  -> Domain.pause d
  | _ -> raise (Unimplemented "pause target")


let attach_debugger ctx =
  match ctx with
  | Domain d  -> Domain.attach_debugger (Domain.get_domain d) 
	                                (Domain.get_execution_domain d)
  | _ -> raise (Unimplemented "attach debugger")

let detach_debugger ctx =
  match ctx with
  | Domain d  -> Domain.detach_debugger (Domain.get_domain d) 
	                                (Domain.get_execution_domain d)
  | _ -> raise (Unimplemented "detach debugger")

external open_debugger : unit -> unit = "open_context"
external close_debugger : unit -> unit = "close_context"

(* this is just the domains right now... expand to other contexts later *)
external debugger_status : unit -> unit = "debugger_status"


(***********************************************************)


let hash = Hashtbl.create 10

let debug_contexts () =
  print_endline "context list:";
  let print_context key ctx = 
    match ctx with
    | Void -> print_endline (Printf.sprintf "  [%s] {void}" 
			       (Util.get_connection_info key))
    | Event_channel -> print_endline (Printf.sprintf "  [%s] {event_channel}" 
			       (Util.get_connection_info key))
    | Process p -> print_endline (Printf.sprintf "  [%s] %s" 
				    (Util.get_connection_info key)
				    (Process.string_of_context p))
    | Domain d -> print_endline (Printf.sprintf "  [%s] %s" 
				   (Util.get_connection_info key)
				   (Domain.string_of_context d))
  in
  Hashtbl.iter print_context hash

(** add_context : add a new context to the hash table.
 *  if there is an existing context for the same key then it 
 *  is first removed implictly by the hash table replace function.
 *)
let add_context (key:Unix.file_descr) context params =
  match context with
  | "void" -> Hashtbl.replace hash key Void
  | "event channel" -> Hashtbl.replace hash key Event_channel
  | "domain" -> 
      begin
	match params with
	| dom::exec_dom::_ ->
            let d = Domain(Domain.new_context dom exec_dom) in
	    attach_debugger d;
            Hashtbl.replace hash key d
	| _ -> failwith "bogus parameters to domain context"
      end
  | "process" -> 
      begin
	match params with
	| dom::pid::_ ->
	    let p = Process.new_context dom pid in
	    Hashtbl.replace hash key (Process(p))
	| _ -> failwith "bogus parameters to process context"
      end
  | _ -> raise (Unknown_context context)

let add_default_context sock =
  add_context sock "void" []

let find_context key =
  try
    Hashtbl.find hash key
  with
    Not_found ->
      print_endline "error: (find_context) PDB context not found";
      raise Not_found

let delete_context key =
  Hashtbl.remove hash key

(** find_domain : Locate the context(s) matching a particular domain 
 *  and execution_domain pair.
 *)

let find_domain dom exec_dom =
    let find key ctx list =
      match ctx with
      |	Domain d ->
	  if (((Domain.get_domain d) = dom) &&
	      ((Domain.get_execution_domain d) = exec_dom))
	  then
	    key :: list
	  else
	    list
      | _ -> list
    in
    let sock_list = Hashtbl.fold find hash [] in
    match sock_list with
    | hd::tl -> hd
    | [] -> raise Unknown_domain
