/*
 * Hypercall interface description:
 * Used by scripts/gen_hypercall.awk to generate hypercall prototypes and call
 * sequences.
 *
 * Syntax is like a prototype, but without return type and without the ";" at
 * the end. Pointer types will be automatically converted to use the
 * XEN_GUEST_HANDLE_PARAM() macro. Handlers with no parameters just use a
 * definition like "fn()".
 * Hypercall/function names are without the leading "__HYPERVISOR_"/"do_"
 * strings.
 *
 * The return type of a class of prototypes using the same prefix is set via:
 * rettype: <prefix> <type>
 * Default return type is "long". A return type for a prefix can be set only
 * once and it needs to be set before that prefix is being used via the
 * "prefix:" directive.
 *
 * The prefix of the prototypes is set via a line:
 * prefix: <prefix> ...
 * Multiple prefixes are possible (restriction see below). Prefixes are without
 * a trailing "_". The current prefix settings are active until a new "prefix:"
 * line.
 *
 * Caller macros are suffixed with a selectable name via lines like:
 * caller: <suffix>
 * When a caller suffix is active, there is only one active prefix allowed.
 *
 * With a "defhandle:" line it is possible to add a DEFINE_XEN_GUEST_HANDLE()
 * to the generated header:
 * defhandle: <handle-type> [<type>]
 * Without specifying <type> only a DEFINE_XEN_GUEST_HANDLE(<handle-type>)
 * will be generated, otherwise it will be a
 * __DEFINE_XEN_GUEST_HANDLE(<handle-type>, <type>) being generated. Note that
 * the latter will include the related "const" handle "const_<handle-type>".
 *
 * In order to support using coding style compliant pointers in the
 * prototypes it is possible to add translation entries to generate the correct
 * handle types:
 * handle: <handle-type> <type>
 * This will result in the prototype translation from "<type> *" to
 * "XEN_GUEST_HANDLE_PARAM(<handle-type>)".
 *
 * The hypercall handler calling code will be generated from a final table in
 * the source file, which is started via the line:
 * table: <caller> <caller> ...
 * with the <caller>s specifying the designated caller macro of each column of
 * the table. Any column of a <caller> not having been set via a "caller:"
 * line will be ignored.
 * The first column of the table contains the hypercall/prototype, each
 * <caller> column contains the prefix for the function to use for that caller.
 * A function prefix can be annotated with a priority by adding ":<prio>" to it
 * ("1" being the highest priority, higher numbers mean lower priority, no
 * priority specified is the lowest priority). The generated code will try to
 * achieve better performance for calling high priority handlers.
 * A column not being supported by a <caller> is marked with "-". Lines with all
 * entries being "-" after removal of inactive <caller> columns are ignored.
 *
 * This file is being preprocessed using $(CPP), so #ifdef CONFIG_* conditionals
 * are possible.
 */

/*
 * Cppcheck thinks this file needs to be analysed because it is preprocessed by
 * the compiler, but it gets confused because this file does not contains C
 * code. Hence protect the code when CPPCHECK is used.
 */
#ifndef CPPCHECK

#ifdef CONFIG_HVM
#define PREFIX_hvm hvm
#else
#define PREFIX_hvm
#endif

#ifdef CONFIG_COMPAT
#define PREFIX_compat compat
rettype: compat int
#else
#define PREFIX_compat
#endif

#ifdef CONFIG_ARM
#define PREFIX_dep dep
#define PREFIX_do_arm do_arm
rettype: do_arm int
#else
#define PREFIX_dep
#define PREFIX_do_arm
#endif

handle: uint unsigned int
handle: const_void const void
handle: const_char const char

#ifdef CONFIG_COMPAT
defhandle: multicall_entry_compat_t
#ifndef CONFIG_PV_SHIM_EXCLUSIVE
defhandle: compat_platform_op_t
#endif
#endif
#ifdef CONFIG_PV32
defhandle: trap_info_compat_t
defhandle: physdev_op_compat_t
#endif

prefix: do PREFIX_hvm PREFIX_compat PREFIX_do_arm
physdev_op(int cmd, void *arg)

prefix: do PREFIX_hvm PREFIX_compat
#if defined(CONFIG_GRANT_TABLE) || defined(CONFIG_PV_SHIM)
grant_table_op(unsigned int cmd, void *uop, unsigned int count)
#endif

prefix: do PREFIX_hvm
memory_op(unsigned long cmd, void *arg)

prefix: do PREFIX_compat
xen_version(int cmd, void *arg)
vcpu_op(int cmd, unsigned int vcpuid, void *arg)
sched_op(int cmd, void *arg)
xsm_op(void *op)
callback_op(int cmd, const void *arg)
#ifdef CONFIG_ARGO
argo_op(unsigned int cmd, void *arg1, void *arg2, unsigned long arg3, unsigned long arg4)
#endif
#ifdef CONFIG_PV
iret()
nmi_op(unsigned int cmd, void *arg)
#ifdef CONFIG_XENOPROF
xenoprof_op(int op, void *arg)
#endif
#endif /* CONFIG_PV */

#ifdef CONFIG_COMPAT
prefix: compat
set_timer_op(uint32_t lo, uint32_t hi)
multicall(multicall_entry_compat_t *call_list, unsigned long nr_calls)
memory_op(unsigned int cmd, void *arg)
#ifdef CONFIG_IOREQ_SERVER
dm_op(domid_t domid, unsigned int nr_bufs, void *bufs)
#endif
mmuext_op(void *arg, unsigned int count, uint *pdone, unsigned int foreigndom)
#ifdef CONFIG_PV32
set_trap_table(trap_info_compat_t *traps)
set_gdt(unsigned int *frame_list, unsigned int entries)
set_callbacks(unsigned long event_selector, unsigned long event_address, unsigned long failsafe_selector, unsigned long failsafe_address)
update_descriptor(uint32_t pa_lo, uint32_t pa_hi, uint32_t desc_lo, uint32_t desc_hi)
update_va_mapping(unsigned int va, uint32_t lo, uint32_t hi, unsigned int flags)
physdev_op_compat(physdev_op_compat_t *uop)
update_va_mapping_otherdomain(unsigned int va, uint32_t lo, uint32_t hi, unsigned int flags, domid_t domid)
#endif
#ifndef CONFIG_PV_SHIM_EXCLUSIVE
platform_op(compat_platform_op_t *u_xenpf_op)
#endif
#ifdef CONFIG_KEXEC
kexec_op(unsigned int op, void *uarg)
#endif
#endif /* CONFIG_COMPAT */

#if defined(CONFIG_PV) || defined(CONFIG_ARM)
prefix: do PREFIX_dep
event_channel_op_compat(evtchn_op_t *uop)
physdev_op_compat(physdev_op_t *uop)
/* Legacy hypercall (as of 0x00030101). */
sched_op_compat(int cmd, unsigned long arg)
#endif

prefix: do
set_timer_op(s_time_t timeout)
console_io(unsigned int cmd, unsigned int count, char *buffer)
vm_assist(unsigned int cmd, unsigned int type)
event_channel_op(int cmd, void *arg)
mmuext_op(mmuext_op_t *uops, unsigned int count, unsigned int *pdone, unsigned int foreigndom)
multicall(multicall_entry_t *call_list, unsigned long nr_calls)
#ifdef CONFIG_PV
mmu_update(mmu_update_t *ureqs, unsigned int count, unsigned int *pdone, unsigned int foreigndom)
stack_switch(unsigned long ss, unsigned long esp)
fpu_taskswitch(int set)
set_debugreg(int reg, unsigned long value)
get_debugreg(int reg)
set_segment_base(unsigned int which, unsigned long base)
mca(xen_mc_t *u_xen_mc)
set_trap_table(const_trap_info_t *traps)
set_gdt(xen_ulong_t *frame_list, unsigned int entries)
set_callbacks(unsigned long event_address, unsigned long failsafe_address, unsigned long syscall_address)
update_descriptor(uint64_t gaddr, seg_desc_t desc)
update_va_mapping(unsigned long va, uint64_t val64, unsigned long flags)
update_va_mapping_otherdomain(unsigned long va, uint64_t val64, unsigned long flags, domid_t domid)
#endif
#ifdef CONFIG_KEXEC
kexec_op(unsigned long op, void *uarg)
#endif
#ifdef CONFIG_IOREQ_SERVER
dm_op(domid_t domid, unsigned int nr_bufs, xen_dm_op_buf_t *bufs)
#endif
#ifndef CONFIG_PV_SHIM_EXCLUSIVE
sysctl(xen_sysctl_t *u_sysctl)
domctl(xen_domctl_t *u_domctl)
paging_domctl_cont(xen_domctl_t *u_domctl)
platform_op(xen_platform_op_t *u_xenpf_op)
#endif
#ifdef CONFIG_HVM
hvm_op(unsigned long op, void *arg)
#endif
#ifdef CONFIG_HYPFS
hypfs_op(unsigned int cmd, const char *arg1, unsigned long arg2, void *arg3, unsigned long arg4)
#endif
#ifdef CONFIG_X86
xenpmu_op(unsigned int op, xen_pmu_params_t *arg)
#endif

#ifdef CONFIG_PV
caller: pv64
#ifdef CONFIG_PV32
caller: pv32
#endif
#endif
#if defined(CONFIG_HVM) && defined(CONFIG_X86)
caller: hvm64
#ifdef CONFIG_COMPAT
caller: hvm32
#endif
#endif
#ifdef CONFIG_ARM
caller: arm
#endif

table:                             pv32     pv64     hvm32    hvm64    arm
set_trap_table                     compat   do       -        -        -
mmu_update                         do:1     do:1     -        -        -
set_gdt                            compat   do       -        -        -
stack_switch                       do:2     do:2     -        -        -
set_callbacks                      compat   do       -        -        -
fpu_taskswitch                     do       do       -        -        -
sched_op_compat                    do       do       -        -        dep
#ifndef CONFIG_PV_SHIM_EXCLUSIVE
platform_op                        compat   do       compat   do       do
#endif
set_debugreg                       do       do       -        -        -
get_debugreg                       do       do       -        -        -
update_descriptor                  compat   do       -        -        -
memory_op                          compat   do       hvm      hvm      do
multicall                          compat:2 do:2     compat   do       do
update_va_mapping                  compat   do       -        -        -
set_timer_op                       compat   do       compat   do       -
event_channel_op_compat            do       do       -        -        dep
xen_version                        do       do       do       do       do
console_io                         do       do       do       do       do
physdev_op_compat                  compat   do       -        -        dep
#if defined(CONFIG_GRANT_TABLE)
grant_table_op                     compat   do       hvm      hvm      do
#elif defined(CONFIG_PV_SHIM)
grant_table_op                     compat   do       -        -        -
#endif
vm_assist                          do       do       do       do       do
update_va_mapping_otherdomain      compat   do       -        -        -
iret                               compat:1 do:1     -        -        -
vcpu_op                            compat   do       compat:1 do:1     do
set_segment_base                   do:2     do:2     -        -        -
#ifdef CONFIG_PV
mmuext_op                          compat:2 do:2     compat   do       -
#endif
xsm_op                             compat   do       compat   do       do
nmi_op                             compat   do       -        -        -
sched_op                           compat   do       compat   do       do
callback_op                        compat   do       -        -        -
#ifdef CONFIG_XENOPROF
xenoprof_op                        compat   do       -        -        -
#endif
event_channel_op                   do       do       do:1     do:1     do:1
physdev_op                         compat   do       hvm      hvm      do_arm
#ifdef CONFIG_HVM
hvm_op                             do       do       do       do       do
#endif
#ifndef CONFIG_PV_SHIM_EXCLUSIVE
sysctl                             do       do       do       do       do
domctl                             do       do       do       do       do
#endif
#ifdef CONFIG_KEXEC
kexec_op                           compat   do       -        -        -
#endif
tmem_op                            -        -        -        -        -
#ifdef CONFIG_ARGO
argo_op                            compat   do       compat   do       do
#endif
xenpmu_op                          do       do       do       do       -
#ifdef CONFIG_IOREQ_SERVER
dm_op                              compat   do       compat   do       do
#endif
#ifdef CONFIG_HYPFS
hypfs_op                           do       do       do       do       do
#endif
mca                                do       do       -        -        -
#ifndef CONFIG_PV_SHIM_EXCLUSIVE
paging_domctl_cont                 do       do       do       do       -
#endif

#endif /* !CPPCHECK */
