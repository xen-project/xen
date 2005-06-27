(** Util.ml
 *
 *  various utility functions
 *
 *  @author copyright (c) 2005 alex ho
 *  @see <www.cl.cam.ac.uk/netos/pdb> pervasive debugger
 *  @version 1
 *)

let int_of_hexchar h = 
  let i = int_of_char h in
  match h with
  | '0' .. '9' -> i - (int_of_char '0')
  | 'a' .. 'f' -> i - (int_of_char 'a') + 10
  | 'A' .. 'F' -> i - (int_of_char 'A') + 10
  | _ -> raise (Invalid_argument "unknown hex character")

let hexchar_of_int i = 
  let hexchars = [| '0'; '1'; '2'; '3'; '4'; '5'; '6'; '7';
		    '8'; '9'; 'a'; 'b'; 'c'; 'd'; 'e'; 'f' |]
  in
  hexchars.(i)


(** flip the bytes of a four byte int 
 *)

let flip_int num =
  let a = num mod 256
  and b = (num / 256) mod 256
  and c = (num / (256 * 256)) mod 256
  and d = (num / (256 * 256 * 256)) in
  (a * 256 * 256 * 256) + (b * 256 * 256) + (c * 256) + d

    
let flip_int32 num =
  let a = Int32.logand num 0xffl
  and b = Int32.logand (Int32.shift_right_logical num 8)  0xffl
  and c = Int32.logand (Int32.shift_right_logical num 16) 0xffl
  and d =              (Int32.shift_right_logical num 24)       in
  (Int32.logor
     (Int32.logor (Int32.shift_left a 24) (Int32.shift_left b 16))
     (Int32.logor (Int32.shift_left c 8)  d))


let int_list_of_string_list list =
  List.map (fun x -> int_of_string x) list
    
let int_list_of_string str len =
  let array_of_string s =
    let int_array = Array.make len 0 in
    for loop = 0 to len - 1 do
      int_array.(loop) <- (Char.code s.[loop]);
    done;
    int_array
  in
  Array.to_list (array_of_string str)


(* remove leading and trailing whitespace from a string *)

let chomp str =
  let head = Str.regexp "^[ \t\r\n]+" in
  let tail = Str.regexp "[ \t\r\n]+$" in
  let str = Str.global_replace head "" str in
  Str.global_replace tail "" str

(* Stupid little parser for    "<key>=<value>[,<key>=<value>]*"
   It first chops the entire command at each ',', so no ',' in key or value!
   Mucked to return a list of words for "value"
 *)

let list_of_string str =
  let delim c = Str.regexp ("[ \t]*" ^ c ^ "[ \t]*") in
  let str_list = Str.split (delim " ") str in
  List.map (fun x -> chomp(x)) str_list

let little_parser fn str =
  let delim c = Str.regexp ("[ \t]*" ^ c ^ "[ \t]*") in
  let str_list = Str.split (delim ",") str in
  let pair s =
    match Str.split (delim "=") s with
    | [key;value] -> fn (chomp key) (list_of_string value)
    | [key] -> fn (chomp key) []
    | _ -> failwith (Printf.sprintf "error: (little_parser) parse error [%s]" str)
  in
  List.iter pair str_list

(* boolean list membership test *)
let not_list_member the_list element =
  try 
    List.find (fun x -> x = element) the_list;
    false
  with
    Not_found -> true

(* a very inefficient way to remove the elements of one list from another *)
let list_remove the_list remove_list =
  List.filter (not_list_member remove_list) the_list

(* get a description of a file descriptor *)
let get_connection_info fd =
  let get_local_info fd =
    let sockname = Unix.getsockname fd in
    match sockname with
    | Unix.ADDR_UNIX(s) -> "unix"
    | Unix.ADDR_INET(a,p) -> ((Unix.string_of_inet_addr a) ^ ":" ^
			      (string_of_int p))
  and get_remote_info fd =
    let sockname = Unix.getpeername fd in 
    match sockname with
    | Unix.ADDR_UNIX(s) -> s
    | Unix.ADDR_INET(a,p) -> ((Unix.string_of_inet_addr a) ^ ":" ^
			      (string_of_int p))
  in
  try
    get_remote_info fd
  with
  | Unix.Unix_error (Unix.ENOTSOCK, s1, s2) -> 
      let s = Unix.fstat fd in
      Printf.sprintf "dev: %d, inode: %d" s.Unix.st_dev s.Unix.st_ino
  | Unix.Unix_error (Unix.EBADF, s1, s2) -> 
      let s = Unix.fstat fd in
      Printf.sprintf "dev: %d, inode: %d" s.Unix.st_dev s.Unix.st_ino
  | _ -> get_local_info fd


(* really write a string *)
let really_write fd str =
  let strlen = String.length str in
  let sent = ref 0 in
  while (!sent < strlen) do
    sent := !sent + (Unix.write fd str !sent (strlen - !sent))
  done

let write_character fd ch =
  let str = String.create 1 in
  str.[0] <- ch;
  really_write fd str



let send_reply fd reply =
  let checksum = ref 0 in
  write_character fd '$';
  for loop = 0 to (String.length reply) - 1 do
    write_character fd reply.[loop];
    checksum := !checksum + int_of_char reply.[loop]
  done;
  write_character fd '#';
  write_character fd (hexchar_of_int ((!checksum mod 256) / 16));
  write_character fd (hexchar_of_int ((!checksum mod 256) mod 16))
  (*
   * BUG NEED TO LISTEN FOR REPLY +/- AND POSSIBLY RE-TRANSMIT
   *)

