(** xcs.ml
 *
 *  xen control switch interface
 *
 *  @author copyright (c) 2005 alex ho
 *  @see <www.cl.cam.ac.uk/netos/pdb> pervasive debugger
 *  @version 1
 *)

open Int32

let xcs_path = "/var/lib/xen/xcs_socket"                    (* XCS_SUN_PATH *)
let xcs_type = 11                                             (* CMSG_DEBUG *)


type xcs_message =
    {
              domain  : int;
              status  : int;
              ring    : int32;
      mutable evtchn  : int;
    }

external connect : string -> int -> Unix.file_descr = "xcs_connect"
external disconnect : Unix.file_descr -> unit = "xcs_disconnect"
external read_message : Unix.file_descr -> xcs_message = "xcs_read_message"
external write_message : Unix.file_descr -> xcs_message -> unit = 
                                                            "xcs_write_message"
external initialize_ring : int -> int32 -> int32 = "xcs_initialize_ring"

(*
 * initialize xcs stuff
 *)
let setup () =
  connect xcs_path xcs_type


(*
 * adios
 *)
let teardown fd =
  disconnect fd


(*
 * message from a domain backend
 *)
let read socket =
  let xcs = read_message socket in
  begin
    match xcs.status with
      | 1 ->                                    (* PDB_CONNECTION_STATUS_UP *)
	  begin
	    print_endline (Printf.sprintf "  new backend domain available (%d)"
	                   xcs.domain);
	    let ring = initialize_ring xcs.domain xcs.ring in

	    let (local_evtchn, remote_evtchn) = 
	      Evtchn.bind_interdomain xcs.domain in

	    xcs.evtchn <- remote_evtchn;
	    write_message socket xcs;

	    let evtchn_fd = Evtchn._setup () in
	    Evtchn._bind evtchn_fd local_evtchn;

	    (evtchn_fd, local_evtchn, xcs.domain, ring)
	  end
      | 2 ->                                  (* PDB_CONNECTION_STATUS_DOWN *)
	  begin
	    (* TODO:
	       unmap the ring
	       unbind event channel  xen_evtchn_unbind
	       find the evtchn_fd for this domain and close it
	       finally, need to failwith something
	    *)
	    print_endline (Printf.sprintf "  close connection from domain %d"
	                   xcs.domain);
	    (socket, 0, 0, 0l)
	  end
      | _ ->
	  failwith "xcs read: unknown xcs status"
  end
    

