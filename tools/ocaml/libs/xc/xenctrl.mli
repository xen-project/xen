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

type domid = int
type vcpuinfo = {
  online : bool;
  blocked : bool;
  running : bool;
  cputime : int64;
  cpumap : int32;
}

type xen_arm_arch_domainconfig = {
  gic_version: int;
  nr_spis: int;
  clock_frequency: int32;
}

type x86_arch_emulation_flags =
  | X86_EMU_LAPIC
  | X86_EMU_HPET
  | X86_EMU_PM
  | X86_EMU_RTC
  | X86_EMU_IOAPIC
  | X86_EMU_PIC
  | X86_EMU_VGA
  | X86_EMU_IOMMU
  | X86_EMU_PIT
  | X86_EMU_USE_PIRQ

type xen_x86_arch_domainconfig = {
  emulation_flags: x86_arch_emulation_flags list;
}

type arch_domainconfig =
  | ARM of xen_arm_arch_domainconfig
  | X86 of xen_x86_arch_domainconfig

type domaininfo = {
  domid : domid;
  dying : bool;
  shutdown : bool;
  paused : bool;
  blocked : bool;
  running : bool;
  hvm_guest : bool;
  shutdown_code : int;
  total_memory_pages : nativeint;
  max_memory_pages : nativeint;
  shared_info_frame : int64;
  cpu_time : int64;
  nr_online_vcpus : int;
  max_vcpu_id : int;
  ssidref : int32;
  handle : int array;
  arch_config : arch_domainconfig;
}
type sched_control = { weight : int; cap : int; }
type physinfo_cap_flag = CAP_HVM | CAP_DirectIO
type physinfo = {
  threads_per_core : int;
  cores_per_socket : int;
  nr_cpus          : int;
  max_node_id      : int;
  cpu_khz          : int;
  total_pages      : nativeint;
  free_pages       : nativeint;
  scrub_pages      : nativeint;
  capabilities     : physinfo_cap_flag list;
  max_nr_cpus      : int; (** compile-time max possible number of nr_cpus *)
}
type version = { major : int; minor : int; extra : string; }
type compile_info = {
  compiler : string;
  compile_by : string;
  compile_domain : string;
  compile_date : string;
}
type shutdown_reason = Poweroff | Reboot | Suspend | Crash | Watchdog | Soft_reset

type domain_create_flag = CDF_HVM | CDF_HAP

exception Error of string
type handle
external sizeof_core_header : unit -> int = "stub_sizeof_core_header"
external sizeof_vcpu_guest_context : unit -> int
  = "stub_sizeof_vcpu_guest_context"
external sizeof_xen_pfn : unit -> int = "stub_sizeof_xen_pfn"
external interface_open : unit -> handle = "stub_xc_interface_open"
external interface_close : handle -> unit = "stub_xc_interface_close"
val with_intf : (handle -> 'a) -> 'a
val domain_create : handle -> int32 -> domain_create_flag list -> string -> arch_domainconfig -> domid
val domain_sethandle : handle -> domid -> string -> unit
external domain_max_vcpus : handle -> domid -> int -> unit
  = "stub_xc_domain_max_vcpus"
external domain_pause : handle -> domid -> unit = "stub_xc_domain_pause"
external domain_unpause : handle -> domid -> unit = "stub_xc_domain_unpause"
external domain_resume_fast : handle -> domid -> unit
  = "stub_xc_domain_resume_fast"
external domain_destroy : handle -> domid -> unit = "stub_xc_domain_destroy"
external domain_shutdown : handle -> domid -> shutdown_reason -> unit
  = "stub_xc_domain_shutdown"
external _domain_getinfolist : handle -> domid -> int -> domaininfo list
  = "stub_xc_domain_getinfolist"
val domain_getinfolist : handle -> domid -> domaininfo list
external domain_getinfo : handle -> domid -> domaininfo
  = "stub_xc_domain_getinfo"
external domain_get_vcpuinfo : handle -> int -> int -> vcpuinfo
  = "stub_xc_vcpu_getinfo"
external domain_ioport_permission: handle -> domid -> int -> int -> bool -> unit
       = "stub_xc_domain_ioport_permission"
external domain_iomem_permission: handle -> domid -> nativeint -> nativeint -> bool -> unit
       = "stub_xc_domain_iomem_permission"
external domain_irq_permission: handle -> domid -> int -> bool -> unit
       = "stub_xc_domain_irq_permission"
external vcpu_affinity_set : handle -> domid -> int -> bool array -> unit
  = "stub_xc_vcpu_setaffinity"
external vcpu_affinity_get : handle -> domid -> int -> bool array
  = "stub_xc_vcpu_getaffinity"
external vcpu_context_get : handle -> domid -> int -> string
  = "stub_xc_vcpu_context_get"
external sched_id : handle -> int = "stub_xc_sched_id"
external sched_credit_domain_set : handle -> domid -> sched_control -> unit
  = "stub_sched_credit_domain_set"
external sched_credit_domain_get : handle -> domid -> sched_control
  = "stub_sched_credit_domain_get"
external shadow_allocation_set : handle -> domid -> int -> unit
  = "stub_shadow_allocation_set"
external shadow_allocation_get : handle -> domid -> int
  = "stub_shadow_allocation_get"
external evtchn_alloc_unbound : handle -> domid -> domid -> int
  = "stub_xc_evtchn_alloc_unbound"
external evtchn_reset : handle -> domid -> unit = "stub_xc_evtchn_reset"
external readconsolering : handle -> string = "stub_xc_readconsolering"
external send_debug_keys : handle -> string -> unit = "stub_xc_send_debug_keys"
external physinfo : handle -> physinfo = "stub_xc_physinfo"
external pcpu_info: handle -> int -> int64 array = "stub_xc_pcpu_info"
external domain_setmaxmem : handle -> domid -> int64 -> unit
  = "stub_xc_domain_setmaxmem"
external domain_set_memmap_limit : handle -> domid -> int64 -> unit
  = "stub_xc_domain_set_memmap_limit"
external domain_memory_increase_reservation :
  handle -> domid -> int64 -> unit
  = "stub_xc_domain_memory_increase_reservation"
external map_foreign_range :
  handle -> domid -> int -> nativeint -> Xenmmap.mmap_interface
  = "stub_map_foreign_range"
external domain_get_pfn_list :
  handle -> domid -> nativeint -> nativeint array
  = "stub_xc_domain_get_pfn_list"

external domain_assign_device: handle -> domid -> (int * int * int * int) -> unit
       = "stub_xc_domain_assign_device"
external domain_deassign_device: handle -> domid -> (int * int * int * int) -> unit
       = "stub_xc_domain_deassign_device"
external domain_test_assign_device: handle -> domid -> (int * int * int * int) -> bool
       = "stub_xc_domain_test_assign_device"

external version : handle -> version = "stub_xc_version_version"
external version_compile_info : handle -> compile_info
  = "stub_xc_version_compile_info"
external version_changeset : handle -> string = "stub_xc_version_changeset"
external version_capabilities : handle -> string
  = "stub_xc_version_capabilities"

type featureset_index = Featureset_raw | Featureset_host | Featureset_pv | Featureset_hvm
external get_cpu_featureset : handle -> featureset_index -> int64 array = "stub_xc_get_cpu_featureset"

type core_magic = Magic_hvm | Magic_pv
type core_header = {
  xch_magic : core_magic;
  xch_nr_vcpus : int;
  xch_nr_pages : nativeint;
  xch_index_offset : int64;
  xch_ctxt_offset : int64;
  xch_pages_offset : int64;
}
external marshall_core_header : core_header -> string
  = "stub_marshall_core_header"
val coredump : handle -> domid -> Unix.file_descr -> unit
external pages_to_kib : int64 -> int64 = "stub_pages_to_kib"
val pages_to_mib : int64 -> int64
external watchdog : handle -> int -> int32 -> int
  = "stub_xc_watchdog"

external domain_set_machine_address_size: handle -> domid -> int -> unit
  = "stub_xc_domain_set_machine_address_size"
external domain_get_machine_address_size: handle -> domid -> int
       = "stub_xc_domain_get_machine_address_size"

external domain_cpuid_set: handle -> domid -> (int64 * (int64 option))
                        -> string option array
                        -> string option array
       = "stub_xc_domain_cpuid_set"
external domain_cpuid_apply_policy: handle -> domid -> unit
       = "stub_xc_domain_cpuid_apply_policy"
