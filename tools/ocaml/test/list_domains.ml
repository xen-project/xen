open Arg
open Printf
open Xenlight

let bool_as_char b c = if b then c else '-'

let print_dominfo dominfo =
  let id = dominfo.Xenlight.Dominfo.domid
  and running = bool_as_char dominfo.Xenlight.Dominfo.running 'r'
  and blocked = bool_as_char dominfo.Xenlight.Dominfo.blocked 'b'
  and paused = bool_as_char dominfo.Xenlight.Dominfo.paused 'p'
  and shutdown = bool_as_char dominfo.Xenlight.Dominfo.shutdown 's'
  and dying = bool_as_char dominfo.Xenlight.Dominfo.dying 'd'
  and memory = dominfo.Xenlight.Dominfo.current_memkb
  in
  printf "Dom %d: %c%c%c%c%c %LdKB\n" id running blocked paused shutdown dying memory

let _ =
  let logger = Xtl.create_stdio_logger (*~level:Xentoollog.Debug*) () in
  let ctx = Xenlight.ctx_alloc logger in
  try
    let domains = Xenlight.Dominfo.list ctx in
    List.iter (fun d -> print_dominfo d) domains
  with Xenlight.Error(err, fn) -> begin
    printf "Caught Exception: %s: %s\n" (Xenlight.string_of_error err) fn;
  end


