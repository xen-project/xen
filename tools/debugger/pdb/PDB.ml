(** PDB.ml
 *
 *  Dispatch debugger commands to the appropriate context
 *
 *  @author copyright (c) 2005 alex ho
 *  @see <www.cl.cam.ac.uk/netos/pdb> pervasive debugger
 *  @version 1
 *)

open Util

exception Unimplemented of string
exception Unknown_context of string
exception Unknown_domain
exception Unknown_process

type context_t =
  | Void
  | Xen_virq
  | Xen_xcs
  | Xen_domain of Xen_domain.context_t
  | Domain of Domain.context_t
  | Process of Process.context_t

let string_of_context ctx =
  match ctx with
  | Void -> "{void}"
  | Xen_virq  -> "{Xen virq evtchn}"
  | Xen_xcs   -> "{Xen xcs socket}"
  | Xen_domain d -> Xen_domain.string_of_context d
  | Domain d  -> Domain.string_of_context d
  | Process p -> Process.string_of_context p


let hash = Hashtbl.create 10


(***************************************************************************)

let find_context key =
  try
    Hashtbl.find hash key
  with
    Not_found ->
      print_endline "error: (find_context) PDB context not found";
      raise Not_found

let delete_context key =
  Hashtbl.remove hash key


(**
   find_process : Locate the socket associated with the context(s)
   matching a particular (domain, process id) pair.  if there are multiple
   contexts (there shouldn't be), then return the first one.
 *)

let find_process dom pid =
    let find key ctx list =
      match ctx with
      |	Process p ->
	  if (((Process.get_domain p) = dom) &&
	      ((Process.get_process p) = pid))
	  then
	    key :: list
	  else
	    list
      | _ -> list
    in
    let sock_list = Hashtbl.fold find hash [] in
    match sock_list with
    | hd::tl -> hd
    | [] -> raise Unknown_process


(**
   find_domain : Locate the socket associated with the context(s)
   matching a particular (domain, vcpu) pair.  if there are multiple
   contexts (there shouldn't be), then return the first one.
 *)

let find_domain dom vcpu =
    let find key ctx list =
      match ctx with
      |	Domain d ->
	  if (((Domain.get_domain d) = dom) &&
	      ((Domain.get_vcpu d) = vcpu))
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

(**
   find_xen_domain_context : fetch the socket associated with the
   xen_domain context for a domain.  if there are multiple contexts
   (there shouldn't be), then return the first one.
 *)

let find_xen_domain_context domain =
  let find key ctx list =
    match ctx with
      | Xen_domain d ->
	  if ((Xen_domain.get_domain d) = domain)
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

let attach_debugger ctx =
  match ctx with
  | Domain d  -> Domain.attach_debugger (Domain.get_domain d) 
	                                (Domain.get_vcpu d)
  | Process p ->
      begin
	let xdom_sock = find_xen_domain_context (Process.get_domain p) in
	let xdom_ctx = find_context xdom_sock in
	begin
	  match xdom_ctx with
	    | Xen_domain d ->
		Process.attach_debugger p d
	    | _ -> failwith ("context has wrong xen domain type")
	end;
	raise No_reply
      end
  | _ -> raise (Unimplemented "attach debugger")

let detach_debugger ctx =
  match ctx with
  | Domain d  -> Domain.detach_debugger (Domain.get_domain d) 
	                                (Domain.get_vcpu d)
  | Process p  -> Process.detach_debugger p
  | _ -> raise (Unimplemented "detach debugger")


let debug_contexts () =
  print_endline "context list:";
  let print_context key ctx = 
    match ctx with
    | Void -> print_endline (Printf.sprintf "  [%s] {void}" 
			       (Util.get_connection_info key))
    | Xen_virq  -> print_endline (Printf.sprintf "  [%s] {xen virq evtchn}" 
	                          (Util.get_connection_info key))
    | Xen_xcs   -> print_endline (Printf.sprintf "  [%s] {xen xcs socket}" 
			          (Util.get_connection_info key))
    | Xen_domain d -> print_endline (Printf.sprintf "  [%s] %s" 
			          (Util.get_connection_info key) 
                                  (Xen_domain.string_of_context d))
    | Domain d  -> print_endline (Printf.sprintf "  [%s] %s" 
				  (Util.get_connection_info key)
				  (Domain.string_of_context d))
    | Process p -> print_endline (Printf.sprintf "  [%s] %s" 
				  (Util.get_connection_info key)
				  (Process.string_of_context p))
  in
  Hashtbl.iter print_context hash

(** add_context : add a new context to the hash table.
 *  if there is an existing context for the same key then it 
 *  is first removed implictly by the hash table replace function.
 *)
let add_context (key:Unix.file_descr) context params =
  match context with
  | "void"     -> Hashtbl.replace hash key Void
  | "xen virq" -> Hashtbl.replace hash key Xen_virq
  | "xen xcs"  -> Hashtbl.replace hash key Xen_xcs
  | "domain" -> 
      begin
	match params with
	| dom::vcpu::_ ->
            let d = Domain(Domain.new_context dom vcpu) in
	    attach_debugger d;
            Hashtbl.replace hash key d
	| _ -> failwith "bogus parameters to domain context"
      end
  | "process" -> 
      begin
	match params with
	| dom::pid::_ ->
	    let p = Process(Process.new_context dom pid) in
	    Hashtbl.replace hash key p;
	    attach_debugger p
	| _ -> failwith "bogus parameters to process context"
      end
  | "xen domain"
  | _ -> raise (Unknown_context context)

(* 
 * this is really bogus.  add_xen_domain_context should really
 * be a case within add_context.  however, we need to pass in
 * a pointer that can only be represented as an int32.
 * this would require a different type for params... :(
 * 31 bit integers suck.
 *)
let add_xen_domain_context (key:Unix.file_descr) dom evtchn sring =
  let d = Xen_domain.new_context dom evtchn sring in
  Hashtbl.replace hash key (Xen_domain(d))


let add_default_context sock =
  add_context sock "void" []

(***************************************************************************)

(***************************************************************************)

let read_registers ctx =
  match ctx with
  | Void -> Intel.null_registers                    (* default for startup *)
  | Domain d  -> Domain.read_registers d 
  | Process p ->
      begin
	Process.read_registers p;
	raise No_reply
      end
  | _ -> raise (Unimplemented "read registers")

let write_register ctx register value =
  match ctx with
  | Domain d  -> Domain.write_register d register value
  | Process p ->
      begin
	Process.write_register p register value;
	raise No_reply
      end
  | _ -> raise (Unimplemented "write register")


let read_memory ctx addr len =
  match ctx with
  | Domain d  -> Domain.read_memory d addr len
  | Process p -> Process.read_memory p addr len
  | _ -> raise (Unimplemented "read memory")

let write_memory ctx addr values =
  match ctx with
  | Domain d  -> Domain.write_memory d addr values
  | Process p -> Process.write_memory p addr values
  | _ -> raise (Unimplemented "write memory")


let continue ctx =
  match ctx with
  | Domain d  -> Domain.continue d
  | Process p  -> Process.continue p
  | _ -> raise (Unimplemented "continue")

let step ctx =
  match ctx with
  | Domain d  -> Domain.step d
  | Process p  -> Process.step p
  | _ -> raise (Unimplemented "step")


let insert_memory_breakpoint ctx addr len =
  match ctx with
  | Domain d  -> Domain.insert_memory_breakpoint d addr len
  | Process p  -> Process.insert_memory_breakpoint p addr len
  | _ -> raise (Unimplemented "insert memory breakpoint")

let remove_memory_breakpoint ctx addr len =
  match ctx with
  | Domain d  -> Domain.remove_memory_breakpoint d addr len
  | Process p  -> Process.remove_memory_breakpoint p addr len
  | _ -> raise (Unimplemented "remove memory breakpoint")


let pause ctx =
  match ctx with
  | Domain d  -> Domain.pause d
  | Process p  -> Process.pause p
  | _ -> raise (Unimplemented "pause target")


external open_debugger : unit -> unit = "open_context"
external close_debugger : unit -> unit = "close_context"

(* this is just the domains right now... expand to other contexts later *)
external debugger_status : unit -> unit = "debugger_status"

