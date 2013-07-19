# configuration: what needs translation

unions  = [ "vcpu_cr_regs",
            "vcpu_ar_regs" ];

structs = [ "start_info",
            "trap_info",
            "cpu_user_regs",
            "vcpu_guest_core_regs",
            "vcpu_guest_context",
            "arch_vcpu_info",
            "vcpu_time_info",
            "vcpu_info",
            "arch_shared_info",
            "shared_info" ];

defines = [ "__arm__",
            "__aarch64__",
            "__i386__",
            "__x86_64__",

            "XEN_HAVE_PV_GUEST_ENTRY",

            # arm
            # None

            # x86_{32,64}
            "FLAT_RING1_CS",
            "FLAT_RING1_DS",
            "FLAT_RING1_SS",

            "FLAT_RING3_CS64",
            "FLAT_RING3_DS64",
            "FLAT_RING3_SS64",
            "FLAT_KERNEL_CS64",
            "FLAT_KERNEL_DS64",
            "FLAT_KERNEL_SS64",

            "FLAT_KERNEL_CS",
            "FLAT_KERNEL_DS",
            "FLAT_KERNEL_SS",

            # x86_{32,64}
            "_VGCF_i387_valid",
            "VGCF_i387_valid",
            "_VGCF_in_kernel",
            "VGCF_in_kernel",
            "_VGCF_failsafe_disables_events",
            "VGCF_failsafe_disables_events",
            "_VGCF_syscall_disables_events",
            "VGCF_syscall_disables_events",
            "_VGCF_online",
            "VGCF_online",

            # all archs
            "xen_pfn_to_cr3",
            "xen_cr3_to_pfn",
            "XEN_LEGACY_MAX_VCPUS",
            "MAX_GUEST_CMDLINE" ];

# Architectures which must be compatible, i.e. identical
compat_arches = {
    'arm32': 'arm64',
    'arm64': 'arm32',
}
