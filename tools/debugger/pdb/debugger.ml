(** debugger.ml
 *
 *  main debug functionality
 *
 *  @author copyright (c) 2005 alex ho
 *  @see <www.cl.cam.ac.uk/netos/pdb> pervasive debugger
 *  @version 1
 *)

open Intel
open PDB
open Util
open Str

(** a few debugger commands such as step 's' and continue 'c' do 
 *  not immediately return a response to the debugger.  in these 
 *  cases we raise No_reply instead. 
 *)
exception No_reply

let initialize_debugger () =
  ()

let exit_debugger () =
  ()


(**
   Detach Command
   Note: response is ignored by gdb.  We leave the context in the
   hash.  It will be cleaned up with the socket is closed.
 *)
let gdb_detach ctx =
  PDB.detach_debugger ctx;
  raise No_reply

(**
   Kill Command
   Note: response is ignored by gdb.  We leave the context in the
   hash.  It will be cleaned up with the socket is closed.
 *)
let gdb_kill () =
  ""



(**
   Continue Command.
   resume the target
 *)
let gdb_continue ctx =
  PDB.continue ctx;
  raise No_reply

(**
   Step Command.
   single step the target
 *)
let gdb_step ctx =
  PDB.step ctx;
  raise No_reply


(**
   Read Registers Command.
   returns 16 4-byte registers in a particular defined by gdb.
 *)
let gdb_read_registers ctx =
  let regs = PDB.read_registers ctx in
  let str = 
    (Printf.sprintf "%08lx" (Util.flip_int32 regs.eax)) ^
    (Printf.sprintf "%08lx" (Util.flip_int32 regs.ecx)) ^
    (Printf.sprintf "%08lx" (Util.flip_int32 regs.edx)) ^
    (Printf.sprintf "%08lx" (Util.flip_int32 regs.ebx)) ^
    (Printf.sprintf "%08lx" (Util.flip_int32 regs.esp)) ^
    (Printf.sprintf "%08lx" (Util.flip_int32 regs.ebp)) ^
    (Printf.sprintf "%08lx" (Util.flip_int32 regs.esi)) ^
    (Printf.sprintf "%08lx" (Util.flip_int32 regs.edi)) ^
    (Printf.sprintf "%08lx" (Util.flip_int32 regs.eip)) ^
    (Printf.sprintf "%08lx" (Util.flip_int32 regs.eflags)) ^
    (Printf.sprintf "%08lx" (Util.flip_int32 regs.cs)) ^
    (Printf.sprintf "%08lx" (Util.flip_int32 regs.ss)) ^
    (Printf.sprintf "%08lx" (Util.flip_int32 regs.ds)) ^
    (Printf.sprintf "%08lx" (Util.flip_int32 regs.es)) ^
    (Printf.sprintf "%08lx" (Util.flip_int32 regs.fs)) ^
    (Printf.sprintf "%08lx" (Util.flip_int32 regs.gs)) in
  str
      
(**
   Set Thread Command
 *)
let gdb_set_thread command =
  "OK"


(**
   Read Memory Packets
 *)
let gdb_read_memory ctx command =
  let int_list_to_string i str =
    (Printf.sprintf "%02x" i) ^ str
  in
  let read_mem addr len =
    try
      let mem = PDB.read_memory ctx addr len  in
      List.fold_right int_list_to_string mem ""
    with
      Failure s -> "E02"
  in
  Scanf.sscanf command "m%lx,%d" read_mem



(**
   Write Memory Packets
 *)
let gdb_write_memory ctx command =
  let write_mem addr len =
    print_endline (Printf.sprintf "  gdb_write_memory %lx %x\n" addr len);
    print_endline (Printf.sprintf "  [[ unimplemented ]]\n")
  in
  Scanf.sscanf command "M%lx,%d" write_mem;
  "OK"



(**
   Write Register Packets
 *)
let gdb_write_register ctx command =
  let write_reg reg goofy_val =
    let new_val = Util.flip_int32 goofy_val in
    match reg with
    |  0 -> PDB.write_register ctx EAX new_val
    |  1 -> PDB.write_register ctx ECX new_val
    |  2 -> PDB.write_register ctx EDX new_val
    |  3 -> PDB.write_register ctx EBX new_val
    |  4 -> PDB.write_register ctx ESP new_val
    |  5 -> PDB.write_register ctx EBP new_val
    |  6 -> PDB.write_register ctx ESI new_val
    |  7 -> PDB.write_register ctx EDI new_val
    |  8 -> PDB.write_register ctx EIP new_val
    |  9 -> PDB.write_register ctx EFLAGS new_val
    | 10 -> PDB.write_register ctx CS new_val
    | 11 -> PDB.write_register ctx SS new_val
    | 12 -> PDB.write_register ctx DS new_val
    | 13 -> PDB.write_register ctx ES new_val
    | 14 -> PDB.write_register ctx FS new_val
    | 15 -> PDB.write_register ctx GS new_val
    | _  -> print_endline (Printf.sprintf "write unknown register [%d]" reg)
  in
  Scanf.sscanf command "P%x=%lx" write_reg;
  "OK"


(**
   General Query Packets
 *)
let gdb_query command =
  match command with
  | "qC" -> ""
  | "qOffsets" -> ""
  | "qSymbol::" -> ""
  | _ -> 
      print_endline (Printf.sprintf "unknown gdb query packet [%s]" command);
      "E01"


(**
   Write Memory Binary Packets
 *)
let gdb_write_memory_binary ctx command =
  let write_mem addr len =
    let pos = Str.search_forward (Str.regexp ":") command 0 in
    let txt = Str.string_after command (pos + 1) in
    PDB.write_memory ctx addr (int_list_of_string txt len)
  in
  Scanf.sscanf command "X%lx,%d" write_mem;
  "OK"



(**
   Last Signal Command
 *)
let gdb_last_signal =
  "S00"




(**
   Process PDB extensions to the GDB serial protocol.
   Changes the mutable context state.
 *)
let pdb_extensions command sock =
  let process_extension key value =
    (* since this command can change the context, we need to grab it each time *)
    let ctx = PDB.find_context sock in
    match key with
    | "status" ->
	print_endline (string_of_context ctx);
	PDB.debug_contexts ();
	debugger_status ()
    | "context" ->
        PDB.add_context sock (List.hd value) 
                             (int_list_of_string_list (List.tl value))
    | _ -> failwith (Printf.sprintf "unknown pdb extension command [%s:%s]" 
		                    key (List.hd value))
  in
  try
    Util.little_parser process_extension 
                       (String.sub command 1 ((String.length command) - 1));
    "OK"
  with
  | Unknown_context s -> 
      print_endline (Printf.sprintf "unknown context [%s]" s);
      "E01"
  | Failure s -> "E01"


(**
   Insert Breakpoint or Watchpoint Packet
 *)
let gdb_insert_bwcpoint ctx command =
  let insert cmd addr length =
    try
      match cmd with
      | 0 -> PDB.insert_memory_breakpoint ctx addr length; "OK"
      | _ -> ""
    with
      Failure s -> "E03"
  in
  Scanf.sscanf command "Z%d,%lx,%d" insert

(**
   Remove Breakpoint or Watchpoint Packet
 *)
let gdb_remove_bwcpoint ctx command =
  let insert cmd addr length =
    try
      match cmd with
      | 0 -> PDB.remove_memory_breakpoint ctx addr length; "OK"
      | _ -> ""
    with
      Failure s -> "E04"
  in
  Scanf.sscanf command "z%d,%lx,%d" insert

(**
   Do Work!

   @param command  char list
 *)

let process_command command sock =
  let ctx = PDB.find_context sock in
  try
    match command.[0] with
    | 'c' -> gdb_continue ctx
    | 'D' -> gdb_detach ctx
    | 'g' -> gdb_read_registers ctx
    | 'H' -> gdb_set_thread command
    | 'k' -> gdb_kill ()
    | 'm' -> gdb_read_memory ctx command
    | 'M' -> gdb_write_memory ctx command
    | 'P' -> gdb_write_register ctx command
    | 'q' -> gdb_query command
    | 's' -> gdb_step ctx
    | 'x' -> pdb_extensions command sock
    | 'X' -> gdb_write_memory_binary ctx command
    | '?' -> gdb_last_signal
    | 'z' -> gdb_remove_bwcpoint ctx command
    | 'Z' -> gdb_insert_bwcpoint ctx command
    | _ -> 
	print_endline (Printf.sprintf "unknown gdb command [%s]" command);
	""
  with
    Unimplemented s ->
      print_endline (Printf.sprintf "loser. unimplemented command [%s][%s]" 
		                    command s);
      ""


(**
   process_evtchn  

   This is called each time a virq_pdb is sent from xen to dom 0.
   It is sent by Xen when a domain hits a breakpoint. 

   Think of this as the continuation function for a "c" or "s" command.
*)

external query_domain_stop : unit -> (int * int) list = "query_domain_stop"
(* returns a list of paused domains : () -> (domain, vcpu) list *)

let process_evtchn fd =
  let channel = Evtchn.read fd in
  let find_pair (dom, vcpu) =
    print_endline (Printf.sprintf "checking %d.%d" dom vcpu);
    try
      let sock = PDB.find_domain dom vcpu in
      true
    with
      Unknown_domain -> false
  in
  let dom_list = query_domain_stop () in
  let (dom, vcpu) = List.find find_pair dom_list in
  let vec = 3 in
  let sock = PDB.find_domain dom vcpu in
  print_endline (Printf.sprintf "handle bkpt d:%d ed:%d v:%d  %s" 
		   dom vcpu vec (Util.get_connection_info sock));
  Util.send_reply sock "S05";
  Evtchn.unmask fd channel                                (* allow next virq *)
  
