open Arg
open Printf
open Xentoollog

let stdio_vmessage min_level level errno ctx msg =
	let level_str = level_to_string level
	and errno_str = match errno with None -> "" | Some s -> sprintf ": errno=%d" s
	and ctx_str = match ctx with None -> "" | Some s -> sprintf ": %s" s in
	if compare min_level level <= 0 then begin
		printf "%s%s%s: %s\n" level_str ctx_str errno_str msg;
		flush stdout;
	end

let stdio_progress ctx what percent dne total =
	let nl = if dne = total then "\n" else "" in
	printf "\rProgress %s %d%% (%Ld/%Ld)%s" what percent dne total nl;
	flush stdout

let create_stdio_logger ?(level=Info) () =
	let cbs = {
		vmessage = stdio_vmessage level;
		progress = stdio_progress; } in
	create "Xentoollog.stdio_logger" cbs

let do_test level =
  let lgr = create_stdio_logger ~level:level () in
  begin
    test lgr;
  end

let () =
  let debug_level = ref Info in
  let speclist = [
    ("-v", Arg.Unit (fun () -> debug_level := Debug), "Verbose");
    ("-q", Arg.Unit (fun () -> debug_level := Critical), "Quiet");
  ] in
  let usage_msg = "usage: xtl [OPTIONS]" in
  Arg.parse speclist (fun s -> ()) usage_msg;

  do_test !debug_level
