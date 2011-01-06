(*
 * Copyright (C) 2006-2010 Citrix Systems Inc.
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

(* Internally, a UUID is simply a string. *)
type 'a t = string

type cookie = string

let of_string s = s
let to_string s = s

let null = ""

(* deprecated: we don't need to duplicate the uuid prefix/suffix *)
let uuid_of_string = of_string
let string_of_uuid = to_string

let string_of_cookie s = s

let cookie_of_string s = s

let dev_random = "/dev/random"
let dev_urandom = "/dev/urandom"

let rnd_array n =
	let fstbyte i = 0xff land i in
	let sndbyte i = fstbyte (i lsr 8) in
	let thdbyte i = sndbyte (i lsr 8) in
	let rec rnd_list n acc = match n with
		| 0 -> acc
		| 1 ->
			let b = fstbyte (Random.bits ()) in
			b :: acc
		| 2 ->
			let r = Random.bits () in
			let b1 = fstbyte r in
			let b2 = sndbyte r in
			b1 :: b2 :: acc
		| n -> 
			let r = Random.bits () in
			let b1 = fstbyte r in
			let b2 = sndbyte r in
			let b3 = thdbyte r in
			rnd_list (n - 3) (b1 :: b2 :: b3 :: acc)
	in
	Array.of_list (rnd_list n [])

let read_array dev n = 
  let ic = open_in_bin dev in
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

let make_uuid_prng () = uuid_of_int_array (rnd_array 16)
let make_uuid_urnd () = uuid_of_int_array (read_array dev_urandom 16)
let make_uuid_rnd () = uuid_of_int_array (read_array dev_random 16)
let make_uuid = make_uuid_urnd

let make_cookie() =
  let bytes = Array.to_list (read_array dev_urandom 64) in
  String.concat "" (List.map (Printf.sprintf "%1x") bytes)

let int_array_of_uuid s =
  try
    let l = ref [] in
    Scanf.sscanf s "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x"
      (fun a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 a10 a11 a12 a13 a14 a15 ->
      l := [ a0; a1; a2; a3; a4; a5; a6; a7; a8; a9;
             a10; a11; a12; a13; a14; a15; ]);
    Array.of_list !l
  with _ -> invalid_arg "Uuid.int_array_of_uuid"

let is_uuid str =
	try
		Scanf.sscanf str
			"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x"
			(fun _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ -> true)
	with _ -> false
