open Printf

let _ =
	Xenlight.register_exceptions ();
	let logger = Xtl.create_stdio_logger ~level:Xentoollog.Debug () in
	let ctx = Xenlight.ctx_alloc logger in

	let open Xenlight.Host in
	let reader = xen_console_read_start ctx 0 in
	(try
		while true do
			let line = xen_console_read_line ctx reader in
			print_string line
		done
	with End_of_file -> ());
	let _ = xen_console_read_finish ctx reader in
	()

