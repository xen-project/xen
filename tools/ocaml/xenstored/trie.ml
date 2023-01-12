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

open Stdext

module StringMap = Map.Make(String)

module Node =
struct
  type 'a t =  {
    key: string;
    value: 'a option;
    children: 'a t StringMap.t;
  }

  let _create key value = {
    key = key;
    value = Some value;
    children = StringMap.empty;
  }

  let empty key = {
    key = key;
    value = None;
    children = StringMap.empty;
  }

  let _get_key node = node.key
  let get_value node =
    match node.value with
    | None       -> raise Not_found
    | Some value -> value

  let _get_children node = node.children

  let set_value node value =
    { node with value = Some value }
  let set_children node children =
    { node with children = children }

  let _add_child node child =
    { node with children = StringMap.add child.key child node.children }
end

type 'a t = 'a Node.t StringMap.t

let mem_node nodes key =
  StringMap.mem key nodes

let find_node nodes key =
  StringMap.find key nodes

let replace_node nodes key node =
  StringMap.update key (function None -> None | Some _ -> Some node) nodes

let remove_node nodes key =
  StringMap.update key (function None -> raise Not_found | Some _ -> None) nodes

let create () = StringMap.empty

let rec iter f tree =
  let aux key node =
    f key node.Node.value;
    iter f node.Node.children
  in
  StringMap.iter aux tree

let rec map f tree =
  let aux node =
    let value =
      match node.Node.value with
      | None       -> None
      | Some value -> f value
    in
    { node with Node.value = value; Node.children = map f node.Node.children }
  in
  tree |> StringMap.map aux
  |> StringMap.filter (fun _ n -> n.Node.value <> None || not (StringMap.is_empty n.Node.children))

let rec fold f tree acc =
  let aux key node accu =
    fold f node.Node.children (f key node.Node.value accu)
  in
  StringMap.fold aux tree acc

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
  with Not_found -> StringMap.empty

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
      StringMap.add node.Node.key (set_node node t value) tree
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
      if StringMap.is_empty children && new_node.Node.value = None
      then remove_node tree h
      else replace_node tree h new_node
    end else
      raise Not_found

