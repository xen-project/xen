(*
 * Copyright (C) 2009-2010 Citrix Ltd.
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

exception Error of string

type create_info =
{
	hvm : bool;
	hap : bool;
	oos : bool;
	ssidref : int32;
	name : string;
	uuid : int array;
	xsdata : (string * string) list;
	platformdata : (string * string) list;
	poolid : int32;
	poolname : string;
}

type build_pv_info =
{
	slack_memkb : int64;
	cmdline : string;
	ramdisk : string;
	features : string;
}

type build_hvm_info =
{
	pae : bool;
	apic : bool;
	acpi : bool;
	nx : bool;
	viridian : bool;
	timeoffset : string;
	timer_mode : int;
	hpet : int;
	vpt_align : int;
}

type build_spec = BuildHVM of build_hvm_info | BuildPV of build_pv_info

type build_info =
{
	max_vcpus : int;
	cur_vcpus : int;
	max_memkb : int64;
	target_memkb : int64;
	video_memkb : int64;
	shadow_memkb : int64;
	kernel : string;
	priv: build_spec;
}

type build_state =
{
	store_port : int;
	store_mfn : int64;
	console_port : int;
	console_mfn : int64;
}

type domid = int

type disk_phystype =
	| PHYSTYPE_QCOW
	| PHYSTYPE_QCOW2
	| PHYSTYPE_VHD
	| PHYSTYPE_AIO
	| PHYSTYPE_FILE
	| PHYSTYPE_PHY

type disk_info =
{
	backend_domid : domid;
	physpath : string;
	phystype : disk_phystype;
	virtpath : string;
	unpluggable : bool;
	readwrite : bool;
	is_cdrom : bool;
}

type nic_type =
	| NICTYPE_IOEMU
	| NICTYPE_VIF

type nic_info =
{
	backend_domid : domid;
	devid : int;
	mtu : int;
	model : string;
	mac : int array;
	bridge : string;
	ifname : string;
	script : string;
	nictype : nic_type;
}

type console_type =
	| CONSOLETYPE_XENCONSOLED
	| CONSOLETYPE_IOEMU

type console_info =
{
	backend_domid : domid;
	devid : int;
	consoletype : console_type;
}

type vkb_info =
{
	backend_domid : domid;
	devid : int;
}

type vfb_info =
{
	backend_domid : domid;
	devid : int;
	vnc : bool;
	vnclisten : string;
	vncpasswd : string;
	vncdisplay : int;
	vncunused : bool;
	keymap : string;
	sdl : bool;
	opengl : bool;
	display : string;
	xauthority : string;
}

type pci_info =
{
	v : int; (* domain * bus * dev * func multiplexed *)
	domain : int;
	vdevfn : int;
	msitranslate : bool;
	power_mgmt : bool;
}

type physinfo =
{
	threads_per_core: int;
	cores_per_socket: int;
	max_cpu_id: int;
	nr_cpus: int;
	cpu_khz: int;
	total_pages: int64;
	free_pages: int64;
	scrub_pages: int64;
	nr_nodes: int;
	hwcap: int32 array;
	physcap: int32;
}

type sched_credit =
{
	weight: int;
	cap: int;
}

external domain_make : create_info -> domid = "stub_xl_domain_make"
external domain_build : build_info -> domid -> build_state = "stub_xl_domain_build"

external disk_add : disk_info -> domid -> unit = "stub_xl_disk_add"
external disk_remove : disk_info -> domid -> unit = "stub_xl_disk_remove"

external nic_add : nic_info -> domid -> unit = "stub_xl_nic_add"
external nic_remove : disk_info -> domid -> unit = "stub_xl_nic_remove"

external console_add : console_info -> build_state -> domid -> unit = "stub_xl_console_add"

external vkb_add : vkb_info -> domid -> unit = "stub_xl_vkb_add"
external vkb_clean_shutdown : domid -> unit = "stub_vkb_clean_shutdown"
external vkb_hard_shutdown : domid -> unit = "stub_vkb_hard_shutdown"

external vfb_add : vfb_info -> domid -> unit = "stub_xl_vfb_add"
external vfb_clean_shutdown : domid -> unit = "stub_vfb_clean_shutdown"
external vfb_hard_shutdown : domid -> unit = "stub_vfb_hard_shutdown"

external pci_add : pci_info -> domid -> unit = "stub_xl_pci_add"
external pci_remove : pci_info -> domid -> unit = "stub_xl_pci_remove"
external pci_shutdown : domid -> unit = "stub_xl_pci_shutdown"

type button =
	| Button_Power
	| Button_Sleep

external button_press : domid -> button -> unit = "stub_xl_button_press"
external physinfo : unit -> physinfo = "stub_xl_physinfo"

external domain_sched_credit_get : domid -> sched_credit = "stub_xl_sched_credit_domain_get"
external domain_sched_credit_set : domid -> sched_credit -> unit = "stub_xl_sched_credit_domain_set"

external send_trigger : domid -> string -> int -> unit = "stub_xl_send_trigger"
external send_sysrq : domid -> char -> unit = "stub_xl_send_sysrq"
external send_debug_keys : domid -> string -> unit = "stub_xl_send_debug_keys"
