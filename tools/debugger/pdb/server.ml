(** server.ml
 *
 *  PDB server main loop
 *
 *  @author copyright (c) 2005 alex ho
 *  @see <www.cl.cam.ac.uk/netos/pdb> pervasive debugger
 *  @version 1
 *)

open Unix
open Buffer


(**
 * connection_t: The state for each connection.
 * buffer & length contains bytes that have been read from the sock
 * but not yet parsed / processed.
 *)
type connection_t =
{ 
          fd : file_descr;
  mutable buffer : string;
  mutable length : int;
}


(**
 * validate_checksum:  Compute and compare the checksum of a string
 * against the provided checksum using the gdb serial protocol algorithm.
 *
 *)
let validate_checksum command checksum =
  let c0 = ref 0 in
  for loop = 0 to (String.length command - 1) do
    c0 := !c0 + int_of_char(command.[loop]);
  done;
  if (String.length checksum) = 2 
  then
    let c1 = Util.int_of_hexchar(checksum.[1]) +
	     Util.int_of_hexchar(checksum.[0]) * 16 in
    (!c0 mod 256) = (c1 mod 256)
  else
    false
  

(**
 * process_input: Oh, joy!  Someone sent us a message.  Let's open the
 * envelope and see what they have to say.
 *
 * This function is a paradigm of inefficiency; it performs as many 
 * string copies as possible.
 *)
let process_input conn sock = 
  let max_buffer_size = 1024 in
  let in_string = String.create max_buffer_size in

  let length = read sock in_string 0 max_buffer_size in
  conn.buffer <- conn.buffer ^ (String.sub in_string 0 length);
  conn.length <- conn.length + length;
  let re = Str.regexp "[^\\$]*\\$\\([^#]*\\)#\\(..\\)" in

  (* interrupt the target if there was a ctrl-c *)
  begin
    try
      let break = String.index conn.buffer '\003' + 1 in
      print_endline (Printf.sprintf "{{%s}}" (String.escaped conn.buffer));

      (* discard everything seen before the ctrl-c *)
      conn.buffer <- String.sub conn.buffer break (conn.length - break);
      conn.length <- conn.length - break;

      (* pause the target *)
      PDB.pause (PDB.find_context sock);

      (* send a code back to the debugger *)
      Util.send_reply sock "S05"

    with
      Not_found -> ()
  end;

  (* with gdb this is unlikely to loop since you ack each packet *)
  while ( Str.string_match re conn.buffer 0 ) do
    let command = Str.matched_group 1 conn.buffer in
    let checksum = Str.matched_group 2 conn.buffer in
    let match_end = Str.group_end 2 in

    begin
      match validate_checksum command checksum with
      | true -> 
	  begin
	    Util.write_character sock '+';
	    try
	      let reply = Debugger.process_command command sock in
	      print_endline (Printf.sprintf "[%s] %s -> \"%s\"" 
			       (Util.get_connection_info sock)
			       (String.escaped command) 
			       (String.escaped reply));
	      Util.send_reply sock reply
	    with
	      Debugger.No_reply ->
		print_endline (Printf.sprintf "[%s] %s -> null" 
				 (Util.get_connection_info sock)
				 (String.escaped command))
	  end
      | false ->
	  Util.write_character sock '-';
    end;

    conn.buffer <- String.sub conn.buffer match_end (conn.length - match_end);
    conn.length <- conn.length - match_end;
  done;
  if length = 0 then raise End_of_file



(** main_server_loop.
 *
 *  connection_hash is a hash (duh!) with one connection_t for each
 *  open connection.
 * 
 *  in_list is a list of active sockets.  it also contains a number
 *  of magic entries: 
 *  - server_sock   for accepting new client connections (e.g. gdb)
 *  - xen_virq_sock for Xen virq asynchronous notifications (via evtchn).
 *                  This is used by context = domain
 *  - xcs_sock      for xcs messages when a new backend domain registers
 *                  This is used by context = process
 *)
let main_server_loop sockaddr =
  let connection_hash = Hashtbl.create 10
  in
  let process_socket svr_sock sockets sock =
    let (new_list, closed_list) = sockets in
    if sock == svr_sock
    then
      begin
	let (new_sock, caller) = accept sock in
	print_endline (Printf.sprintf "[%s] new connection from %s"
			              (Util.get_connection_info sock)
			              (Util.get_connection_info new_sock));
	Hashtbl.add connection_hash new_sock 
	            {fd=new_sock; buffer=""; length = 0};
	PDB.add_default_context new_sock;
	(new_sock :: new_list, closed_list)
      end
    else
      begin
	try
	  match PDB.find_context sock with
	  | PDB.Xen_virq ->
	      print_endline (Printf.sprintf "[%s] Xen virq"
			                    (Util.get_connection_info sock));
	      Debugger.process_xen_virq sock;
	      (new_list, closed_list)
	  | PDB.Xen_xcs ->
	      print_endline (Printf.sprintf "[%s] Xen xcs"
			                    (Util.get_connection_info sock));
	      let new_xen_domain = Debugger.process_xen_xcs sock in
	      (new_xen_domain :: new_list, closed_list)
	  | PDB.Xen_domain d ->
	      print_endline (Printf.sprintf "[%s] Xen domain"
			                    (Util.get_connection_info sock));
	      Debugger.process_xen_domain sock;
	      (new_list, closed_list)
	  | _ ->
	      let conn = Hashtbl.find connection_hash sock in
	      process_input conn sock;
	      (new_list, closed_list)
	with
	| Not_found -> 
	    print_endline "error: (main_svr_loop) context not found";
	    PDB.debug_contexts ();
	    raise Not_found
	| End_of_file -> 
	    print_endline (Printf.sprintf "[%s] close connection from %s"
  			                   (Util.get_connection_info sock)
			                   (Util.get_connection_info sock));
	    PDB.delete_context sock;
	    Hashtbl.remove connection_hash sock;
	    close sock;
	    (new_list, sock :: closed_list)
      end
  in

  let rec helper in_list server_sock =

    (*    
     List.iter (fun x->Printf.printf " {%s}\n" 
                                    (Util.get_connection_info x)) in_list;   
     Printf.printf "\n";
    *)

    let (rd_list, _, _) = select in_list [] [] (-1.0) in 
    let (new_list, closed_list) = List.fold_left (process_socket server_sock)
	                                         ([],[]) rd_list  in
    let merge_list = Util.list_remove (new_list @ in_list) closed_list  in
    helper merge_list server_sock
  in

  try
    let server_sock = socket (domain_of_sockaddr sockaddr) SOCK_STREAM 0 in
    setsockopt server_sock SO_REUSEADDR true;
    bind server_sock sockaddr;
    listen server_sock 2;

    PDB.open_debugger ();
    let xen_virq_sock = Evtchn.setup () in
    PDB.add_context xen_virq_sock "xen virq" [];

    let xcs_sock = Xcs.setup () in
    PDB.add_context xcs_sock "xen xcs" [];
    helper [server_sock; xen_virq_sock; xcs_sock] server_sock
  with
  | Sys.Break ->
      print_endline "break: cleaning up";
      PDB.close_debugger ();
      Hashtbl.iter (fun sock conn -> close sock) connection_hash
(*  | Unix_error(e,err,param) -> 
      Printf.printf "unix error: [%s][%s][%s]\n" (error_message e) err param*)
  | Sys_error s -> Printf.printf "sys error: [%s]\n" s
  | Failure s -> Printf.printf "failure: [%s]\n" s
  | End_of_file -> Printf.printf "end of file\n"


let get_port () =
  if (Array.length Sys.argv) = 2 
  then
    int_of_string Sys.argv.(1)
  else
    begin
      print_endline (Printf.sprintf "error: %s <port>" Sys.argv.(0));
      exit 1
    end


let main =
  let address = inet_addr_any in
  let port = get_port () in
  main_server_loop (ADDR_INET(address, port))

