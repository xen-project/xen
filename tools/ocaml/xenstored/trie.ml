(*
 * Copyright (C) 2008-2009 Citrix Ltd.
 * Author Thomas Gazagnaire <thomas.gazagnaire@eu.citrix.com>
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

module Node =
struct
	type ('a,'b) t =  {
		key: 'a;
		value: 'b option;
		children: ('a,'b) t list;
	}

	let create key value = {
		key = key;
		value = Some value;
		children = [];
	}

	let empty key = {
		key = key;
		value = None;
		children = []
	}

	let get_key node = node.key
	let get_value node = 
		match node.value with
		| None       -> raise Not_found
		| Some value -> value

	let get_children node = node.children

	let set_value node value =
		{ node with value = Some value }
	let set_children node children =
		{ node with children = children }

	let add_child node child = 
		{ node with children = child :: node.children }
end

type ('a,'b) t = ('a,'b) Node.t list

let mem_node nodes key =
	List.exists (fun n -> n.Node.key = key) nodes

let find_node nodes key =
	List.find (fun n -> n.Node.key = key) nodes

let replace_node nodes key node =
	let rec aux = function
		| []                            -> []
		| h :: tl when h.Node.key = key -> node :: tl
		| h :: tl                       -> h :: aux tl
	in
	aux nodes
			
let remove_node nodes key =
	let rec aux = function
		| []                            -> raise Not_found
		| h :: tl when h.Node.key = key -> tl
		| h :: tl                       -> h :: aux tl
	in
	aux nodes

let create () = []

let rec iter f tree = 
	let rec aux node =
		f node.Node.key node.Node.value; 
		iter f node.Node.children
	in
	List.iter aux tree

let rec map f tree =
	let rec aux node =
		let value = 
			match node.Node.value with
			| None       -> None
			| Some value -> f value
		in
		{ node with Node.value = value; Node.children = map f node.Node.children }
	in
	List.filter (fun n -> n.Node.value <> None || n.Node.children <> []) (List.map aux tree)

let rec fold f tree acc =
	let rec aux accu node =
		fold f node.Node.children (f node.Node.key node.Node.value accu)
	in
	List.fold_left aux acc tree 

(* return a sub-trie *)
let rec sub_node tree = function
	| []   -> raise Not_found
	| h::t -> 
		  if mem_node tree h
		  then begin
			  let node = find_node tree h in
			  if t = []
			  then node
			  else sub_node node.Node.children t
		  end else
			  raise Not_found

let sub tree path = 
	try (sub_node tree path).Node.children
	with Not_found -> []

let find tree path = 
	Node.get_value (sub_node tree path)

(* return false if the node doesn't exists or if it is not associated to any value *)
let rec mem tree = function
	| []   -> false
	| h::t -> 
		  mem_node tree h
		  && (let node = find_node tree h in 
			  if t = []
			  then node.Node.value <> None
			  else mem node.Node.children t)

(* Iterate over the longest valid prefix *)
let rec iter_path f tree = function
	| []   -> ()
	| h::l -> 
		  if mem_node tree h
		  then begin
			  let node = find_node tree h in
			  f node.Node.key node.Node.value;
			  iter_path f node.Node.children l
		  end

let rec set_node node path value =
	if path = [] 
	then Node.set_value node value
	else begin
		let children = set node.Node.children path value in
		Node.set_children node children
	end

and set tree path value =
	match path with
		| []   -> raise Not_found
		| h::t -> 
			  if mem_node tree h
			  then begin
				  let node = find_node tree h in
				  replace_node tree h (set_node node t value)
			  end else begin
				  let node = Node.empty h in
				  set_node node t value :: tree
			  end

let rec unset tree = function
	| []   -> tree
	| h::t -> 
		  if mem_node tree h
		  then begin
			  let node = find_node tree h in
			  let children = unset node.Node.children t in
			  let new_node =
				  if t = []
				  then Node.set_children (Node.empty h) children
				  else Node.set_children node children
			  in
			  if children = [] && new_node.Node.value = None
			  then remove_node tree h
			  else replace_node tree h new_node
		  end else
			  raise Not_found

