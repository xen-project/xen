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

(** *)
type domid = int

(* ** xenctrl.h ** *)

type vcpuinfo =
  {
    online: bool;
    blocked: bool;
    running: bool;
    cputime: int64;
    cpumap: int32;
  }

type xen_arm_arch_domainconfig =
  {
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
  | X86_EMU_VPCI

type x86_arch_misc_flags =
  | X86_MSR_RELAXED

type xen_x86_arch_domainconfig =
  {
    emulation_flags: x86_arch_emulation_flags list;
    misc_flags: x86_arch_misc_flags list;
  }

type arch_domainconfig =
  | ARM of xen_arm_arch_domainconfig
  | X86 of xen_x86_arch_domainconfig

type domain_create_flag =
  | CDF_HVM
  | CDF_HAP
  | CDF_S3_INTEGRITY
  | CDF_OOS_OFF
  | CDF_XS_DOMAIN
  | CDF_IOMMU
  | CDF_NESTED_VIRT
  | CDF_VPMU

type domain_create_iommu_opts =
  | IOMMU_NO_SHAREPT

type domctl_create_config =
  {
    ssidref: int32;
    handle: string;
    flags: domain_create_flag list;
    iommu_opts: domain_create_iommu_opts list;
    max_vcpus: int;
    max_evtchn_port: int;
    max_grant_frames: int;
    max_maptrack_frames: int;
    max_grant_version: int;
    altp2m_opts: int32;
    vmtrace_buf_kb: int32;
    cpupool_id: int32;
    arch: arch_domainconfig;
  }

type domaininfo =
  {
    domid             : domid;
    dying             : bool;
    shutdown          : bool;
    paused            : bool;
    blocked           : bool;
    running           : bool;
    hvm_guest         : bool;
    shutdown_code     : int;
    total_memory_pages: nativeint;
    max_memory_pages  : nativeint;
    shared_info_frame : int64;
    cpu_time          : int64;
    nr_online_vcpus   : int;
    max_vcpu_id       : int;
    ssidref           : int32;
    handle            : int array;
    arch_config       : arch_domainconfig;
  }

type sched_control =
  {
    weight : int;
    cap    : int;
  }

type physinfo_cap_flag =
  | CAP_HVM
  | CAP_PV
  | CAP_DirectIO
  | CAP_HAP
  | CAP_Shadow
  | CAP_IOMMU_HAP_PT_SHARE
  | CAP_Vmtrace
  | CAP_Vpmu
  | CAP_Gnttab_v1
  | CAP_Gnttab_v2

type arm_physinfo_caps =
  {
    sve_vl: int;
  }

type x86_physinfo_cap_flag

type arch_physinfo_cap_flags =
  | ARM of arm_physinfo_caps
  | X86 of x86_physinfo_cap_flag list

type physinfo =
  {
    threads_per_core : int;
    cores_per_socket : int;
    nr_cpus          : int;
    max_node_id      : int;
    cpu_khz          : int;
    total_pages      : nativeint;
    free_pages       : nativeint;
    scrub_pages      : nativeint;
    (* XXX hw_cap *)
    capabilities     : physinfo_cap_flag list;
    max_nr_cpus      : int;
    arch_capabilities : arch_physinfo_cap_flags;
  }

type version =
  {
    major : int;
    minor : int;
    extra : string;
  }


type compile_info =
  {
    compiler : string;
    compile_by : string;
    compile_domain : string;
    compile_date : string;
  }

type shutdown_reason = Poweroff | Reboot | Suspend | Crash | Watchdog | Soft_reset

exception Error of string

type handle

external interface_open: unit -> handle = "stub_xc_interface_open"

let handle = ref None

let get_handle () = !handle

let close_handle () =
  match !handle with
  | Some _ -> handle := None
  | None -> ()

let with_intf f =
  match !handle with
  | Some h -> f h
  | None ->
    let h =
      try interface_open () with
      | e ->
        let msg = Printexc.to_string e in
        failwith ("failed to open xenctrl: "^msg)
    in
    handle := Some h;
    f h

external domain_create_stub: handle -> domid -> domctl_create_config -> domid
  = "stub_xc_domain_create"

let domain_create handle ?(domid=0) config =
  domain_create_stub handle domid config

external domain_sethandle: handle -> domid -> string -> unit
  = "stub_xc_domain_sethandle"

external domain_max_vcpus: handle -> domid -> int -> unit
  = "stub_xc_domain_max_vcpus"

external domain_pause: handle -> domid -> unit = "stub_xc_domain_pause"
external domain_unpause: handle -> domid -> unit = "stub_xc_domain_unpause"
external domain_resume_fast: handle -> domid -> unit = "stub_xc_domain_resume_fast"
external domain_destroy: handle -> domid -> unit = "stub_xc_domain_destroy"

external domain_shutdown: handle -> domid -> shutdown_reason -> unit
  = "stub_xc_domain_shutdown"

external _domain_getinfolist: handle -> domid -> int -> domaininfo list
  = "stub_xc_domain_getinfolist"

let rev_append_fold acc e = List.rev_append e acc

(**
 * [rev_concat lst] is equivalent to [lst |> List.concat |> List.rev]
 * except it is tail recursive, whereas [List.concat] isn't.
 * Example:
 * rev_concat [[10;9;8];[7;6];[5]]] = [5; 6; 7; 8; 9; 10]
*)
let rev_concat lst = List.fold_left rev_append_fold [] lst

let domain_getinfolist handle first_domain =
  let nb = 1024 in
  let rec __getlist lst from =
    (* _domain_getinfolist returns domains in reverse order, largest first *)
    match _domain_getinfolist handle from nb with
    | [] -> rev_concat lst
    | (hd :: _) as l -> __getlist (l :: lst) (hd.domid + 1)
  in
  __getlist [] first_domain

external domain_getinfo: handle -> domid -> domaininfo= "stub_xc_domain_getinfo"

external domain_get_vcpuinfo: handle -> int -> int -> vcpuinfo
  = "stub_xc_vcpu_getinfo"

external domain_ioport_permission: handle -> domid -> int -> int -> bool -> unit
  = "stub_xc_domain_ioport_permission"
external domain_iomem_permission: handle -> domid -> nativeint -> nativeint -> bool -> unit
  = "stub_xc_domain_iomem_permission"
external domain_irq_permission: handle -> domid -> int -> bool -> unit
  = "stub_xc_domain_irq_permission"

external vcpu_affinity_set: handle -> domid -> int -> bool array -> unit
  = "stub_xc_vcpu_setaffinity"
external vcpu_affinity_get: handle -> domid -> int -> bool array
  = "stub_xc_vcpu_getaffinity"

external vcpu_context_get: handle -> domid -> int -> string
  = "stub_xc_vcpu_context_get"

external sched_id: handle -> int = "stub_xc_sched_id"

external sched_credit_domain_set: handle -> domid -> sched_control -> unit
  = "stub_sched_credit_domain_set"
external sched_credit_domain_get: handle -> domid -> sched_control
  = "stub_sched_credit_domain_get"

external shadow_allocation_set: handle -> domid -> int -> unit
  = "stub_shadow_allocation_set"
external shadow_allocation_get: handle -> domid -> int
  = "stub_shadow_allocation_get"

external evtchn_alloc_unbound: handle -> domid -> domid -> int
  = "stub_xc_evtchn_alloc_unbound"
external evtchn_reset: handle -> domid -> unit = "stub_xc_evtchn_reset"

(* FIFO has theoretical maximum of 2^28 ports, fits in an int *)
type evtchn_interdomain = { dom: domid; port: int }

type evtchn_stat =
  | EVTCHNSTAT_unbound of domid
  | EVTCHNSTAT_interdomain of evtchn_interdomain
  | EVTCHNSTAT_pirq of int
  | EVTCHNSTAT_virq of Xeneventchn.virq_t
  | EVTCHNSTAT_ipi

type evtchn_status = { vcpu: int; status: evtchn_stat }

external evtchn_status: handle -> domid -> int -> evtchn_status option =
  "stub_xc_evtchn_status"

external readconsolering: handle -> string = "stub_xc_readconsolering"

external send_debug_keys: handle -> string -> unit = "stub_xc_send_debug_keys"
external physinfo: handle -> physinfo = "stub_xc_physinfo"
external pcpu_info: handle -> int -> int64 array = "stub_xc_pcpu_info"

external domain_setmaxmem: handle -> domid -> int64 -> unit
  = "stub_xc_domain_setmaxmem"
external domain_set_memmap_limit: handle -> domid -> int64 -> unit
  = "stub_xc_domain_set_memmap_limit"
external domain_memory_increase_reservation: handle -> domid -> int64 -> unit
  = "stub_xc_domain_memory_increase_reservation"

external map_foreign_range: handle -> domid -> int
  -> nativeint -> Xenmmap.mmap_interface
  = "stub_map_foreign_range"

type hvm_param =
  | HVM_PARAM_CALLBACK_IRQ
  | HVM_PARAM_STORE_PFN
  | HVM_PARAM_STORE_EVTCHN
  | HVM_PARAM_UNDEF_3
  | HVM_PARAM_PAE_ENABLED
  | HVM_PARAM_IOREQ_PFN
  | HVM_PARAM_BUFIOREQ_PFN
  | HVM_PARAM_UNDEF_7
  | HVM_PARAM_UNDEF_8
  | HVM_PARAM_VIRIDIAN
  | HVM_PARAM_TIMER_MODE
  | HVM_PARAM_HPET_ENABLED
  | HVM_PARAM_IDENT_PT
  | HVM_PARAM_UNDEF_13
  | HVM_PARAM_ACPI_S_STATE
  | HVM_PARAM_VM86_TSS
  | HVM_PARAM_VPT_ALIGN
  | HVM_PARAM_CONSOLE_PFN
  | HVM_PARAM_CONSOLE_EVTCHN
  | HVM_PARAM_ACPI_IOPORTS_LOCATION
  | HVM_PARAM_MEMORY_EVENT_CR0
  | HVM_PARAM_MEMORY_EVENT_CR3
  | HVM_PARAM_MEMORY_EVENT_CR4
  | HVM_PARAM_MEMORY_EVENT_INT3
  | HVM_PARAM_NESTEDHVM
  | HVM_PARAM_MEMORY_EVENT_SINGLE_STEP
  | HVM_PARAM_UNDEF_26
  | HVM_PARAM_PAGING_RING_PFN
  | HVM_PARAM_MONITOR_RING_PFN
  | HVM_PARAM_SHARING_RING_PFN
  | HVM_PARAM_MEMORY_EVENT_MSR
  | HVM_PARAM_TRIPLE_FAULT_REASON
  | HVM_PARAM_IOREQ_SERVER_PFN
  | HVM_PARAM_NR_IOREQ_SERVER_PAGES
  | HVM_PARAM_VM_GENERATION_ID_ADDR
  | HVM_PARAM_ALTP2M
  | HVM_PARAM_X87_FIP_WIDTH
  | HVM_PARAM_VM86_TSS_SIZED
  | HVM_PARAM_MCA_CAP

external hvm_param_get: handle -> domid -> hvm_param -> int64
  = "stub_xc_hvm_param_get"

external hvm_param_set: handle -> domid -> hvm_param -> int64 -> unit
  = "stub_xc_hvm_param_set"

external domain_assign_device: handle -> domid -> (int * int * int * int) -> unit
  = "stub_xc_domain_assign_device"
external domain_deassign_device: handle -> domid -> (int * int * int * int) -> unit
  = "stub_xc_domain_deassign_device"
external domain_test_assign_device: handle -> domid -> (int * int * int * int) -> bool
  = "stub_xc_domain_test_assign_device"

external version: handle -> version = "stub_xc_version_version"
external version_compile_info: handle -> compile_info
  = "stub_xc_version_compile_info"
external version_changeset: handle -> string = "stub_xc_version_changeset"
external version_capabilities: handle -> string =
  "stub_xc_version_capabilities"

type featureset_index =
  | Featureset_raw
  | Featureset_host
  | Featureset_pv
  | Featureset_hvm
  | Featureset_pv_max
  | Featureset_hvm_max
external get_cpu_featureset : handle -> featureset_index -> int64 array = "stub_xc_get_cpu_featureset"

external watchdog : handle -> int -> int32 -> int
  = "stub_xc_watchdog"

(* ** Misc ** *)

(**
   Convert the given number of pages to an amount in KiB, rounded up.
*)
external pages_to_kib : int64 -> int64 = "stub_pages_to_kib"
let pages_to_mib pages = Int64.div (pages_to_kib pages) 1024L

let _ = Callback.register_exception "xc.error" (Error "register_callback")
