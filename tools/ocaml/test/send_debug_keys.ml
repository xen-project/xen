open Arg
open Printf
open Xenlight

let send_keys ctx s =
  printf "Sending debug key %s\n" s;
  Xenlight.Host.send_debug_keys ctx s;
  ()
  
let _ =
  let logger = Xtl.create_stdio_logger () in
  let ctx = Xenlight.ctx_alloc logger in
  Arg.parse [
  ] (fun s -> send_keys ctx s) "usage: send_debug_keys <keys>"

