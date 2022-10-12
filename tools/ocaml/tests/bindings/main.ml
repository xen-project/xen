open Printf

let xch = Xenctrl.interface_open ()

let test_xenversion () =
  let ver = Xenctrl.version xch in
  printf "Xen version: %d.%d%s\n" ver.major ver.minor ver.extra


let () =
  printf "Test Ocaml Bindings\n%!";

  test_xenversion ();

  printf "Starting GC.compact()\n%!";
  Gc.compact ();
  printf "GC done\n";

  ()
