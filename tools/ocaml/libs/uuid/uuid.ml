(*
 * Copyright (C) 2006-2007 XenSource Ltd.
 * Copyright (C) 2008      Citrix Ltd.
 * Author Vincent Hanquez <vincent.hanquez@eu.citrix.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *)

(** Type-safe UUIDs. *)

(** Internally, a UUID is simply a string. *)
type 'a t = string

type cookie = string

let of_string s = s
let to_string s = s

(* deprecated: we don't need to duplicate the uuid prefix/suffix *)
let uuid_of_string = of_string
let string_of_uuid = to_string

let string_of_cookie s = s

let cookie_of_string s = s

(** FIXME: using /dev/random is too slow but using /dev/urandom is too
    deterministic. *)
let dev_random = "/dev/urandom"

let read_random n = 
  let ic = open_in_bin dev_random in
  try
    let result = Array.init n (fun _ -> input_byte ic) in
    close_in ic;
    result
  with e ->
    close_in ic;
    raise e

let uuid_of_int_array uuid =
  Printf.sprintf "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x"
    uuid.(0) uuid.(1) uuid.(2) uuid.(3) uuid.(4) uuid.(5)
    uuid.(6) uuid.(7) uuid.(8) uuid.(9) uuid.(10) uuid.(11)
    uuid.(12) uuid.(13) uuid.(14) uuid.(15)

(** Return a new random UUID *)
let make_uuid() = uuid_of_int_array (read_random 16)

(** Return a new random, big UUID (hopefully big and random enough to be
    unguessable) *)
let make_cookie() =
  let bytes = Array.to_list (read_random 64) in
  String.concat "" (List.map (Printf.sprintf "%1x") bytes)
(*
  let hexencode x = 
    let nibble x =
      char_of_int (if x < 10 
		   then int_of_char '0' + x
		   else int_of_char 'a' + (x - 10)) in
    let result = String.make (String.length x * 2) ' ' in
    for i = 0 to String.length x - 1 do
      let byte = int_of_char x.[i] in
      result.[i * 2 + 0] <- nibble((byte lsr 4) land 15);
      result.[i * 2 + 1] <- nibble((byte lsr 0) land 15);
    done;
    result in
  let n = 64 in
  hexencode (String.concat "" (List.map (fun x -> String.make 1 (char_of_int x)) (Array.to_list (read_n_random_bytes n))))
*)

let int_array_of_uuid s =
  try
    let l = ref [] in
    Scanf.sscanf s "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x"
      (fun a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 a10 a11 a12 a13 a14 a15 ->
      l := [ a0; a1; a2; a3; a4; a5; a6; a7; a8; a9;
             a10; a11; a12; a13; a14; a15; ]);
    Array.of_list !l
  with _ -> invalid_arg "Uuid.int_array_of_uuid"
