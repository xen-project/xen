/*
 * Copyright (C) 2009      Citrix Ltd.
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
 */

/*
 * libxl API compatibility
 *
 * From Xen 4.2 onwards the API of libxl will be maintained in a
 * stable manner. This means that it should be possible to write an
 * application against the API provided by libxl in Xen 4.2 and expect
 * that it will continue to compile against future versions of Xen
 * without source modification.
 *
 * In order to make such compatibility possible it is required that
 * application which want to be exposed to a particular API #define
 * LIBXL_API_VERSION before including libxl.h or any other libxl
 * header. The syntax of the LIBXL_API_VERSION is:
 *    0xVVSSEE
 * where ($(XEN_xxx) from xen/Makefile):
 *   VV is the Xen major release number, $(XEN_VERSION)
 *   SS is the Xen sub version number, $(XEN_SUBVERSION)
 *   EE is the Xen extra version digit, first numeric part of
 *     $(XEN_EXTRAVERSION) not including the leading "."
 * For example the first stable API version, supported by Xen 4.2.0,
 * is 0x040200.
 *
 * Lack of LIBXL_API_VERSION means "the latest" which will
 * change. Specifying an unknown LIBXL_API_VERSION will result in a
 * compile time error.
 *
 * Identical versions of the libxl API will represented by the version
 * containing the earliest instance of that API. e.g. if 4.2.0 and
 * 4.3.0 contain an identical libxl API then only LIBXL_API_VERSION
 * 0x040200 will be valid.
 *
 * We will try especially hard to avoid changing the API during a
 * stable series, i.e. it should be unusual for the last byte of
 * LIBXL_API_VERSION to be non-zero.
 *
 * In the event that a change is required which cannot be made
 * backwards compatible in this manner a #define of the form
 * LIBXL_HAVE_<interface> will always be added in order to make it
 * possible to write applications which build against any version of
 * libxl. Such changes are expected to be exceptional and used as a
 * last resort. The barrier for backporting such a change to a stable
 * branch will be very high.
 *
 * These guarantees apply only to stable releases of Xen. When an
 * incompatible change is made in the unstable tree then
 * LIBXL_API_VERSION will be bumped to the next expected stable
 * release number on the first such change only. Applications which
 * want to support building against Xen unstable are expected to track
 * API changes in that tree until it is released as a stable release.
 *
 * API compatibility will be maintained for all versions of Xen using
 * the same $(XEN_VERSION) (e.g. throughout a major release).
 */

/* LIBXL_HAVE_CONSOLE_NOTIFY_FD
 *
 * If this is defined, libxl_console_exec and
 * libxl_primary_console_exe take a notify_fd parameter. That
 * parameter will be used to notify the caller that the console is connected.
 */
#define LIBXL_HAVE_CONSOLE_NOTIFY_FD 1

/* LIBXL_HAVE_CONST_COPY_AND_LENGTH_FUNCTIONS
 *
 * If this is defined, the copy functions have constified src parameter and the
 * length functions accept constified parameter.
 */
#define LIBXL_HAVE_CONST_COPY_AND_LENGTH_FUNCTIONS 1

/* LIBXL_HAVE_DOMAIN_NEED_MEMORY_CONST_B_INFO
 *
 * If this is defined, libxl_domain_need_memory no longer modifies
 * the b_info paseed in.
 */
#define LIBXL_HAVE_DOMAIN_NEED_MEMORY_CONST_B_INFO 1

/* LIBXL_HAVE_VNUMA
 *
 * If this is defined the type libxl_vnode_info exists, and a
 * field 'vnuma_nodes' is present in libxl_domain_build_info.
 */
#define LIBXL_HAVE_VNUMA 1

/* LIBXL_HAVE_USERDATA_UNLINK
 *
 * If it is defined, libxl has a library function called
 * libxl_userdata_unlink.
 */
#define LIBXL_HAVE_USERDATA_UNLINK 1

/* LIBXL_HAVE_CPUPOOL_QUALIFIER_TO_CPUPOOLID
 *
 * If this is defined, libxl has a library function called
 * libxl_cpupool_qualifier_to_cpupoolid, which takes in a CPU pool
 * qualifier in the form of number or string, then returns the ID of
 * that CPU pool.
 */
#define LIBXL_HAVE_CPUPOOL_QUALIFIER_TO_CPUPOOLID 1

/* LIBXL_HAVE_CPUPOOL_ADD_REM_CPUMAP
 *
 * If this is defined, libxl has two library functions called
 * libxl_cpupool_cpuadd_cpumap and libxl_cpupool_cpuremove_cpumap,
 * which allow to add to or remove from a cpupool all the cpus
 * specified in a bitmap.
 */
#define LIBXL_HAVE_CPUPOOL_ADD_REM_CPUMAP 1

/*
 *
 * LIBXL_HAVE_BITMAP_AND_OR
 *
 * If this is defined, libxl has two library functions, libxl_bitmap_and
 * and libxl_bitmap_or to compute the logical and and or of two bitmaps
 */
#define LIBXL_HAVE_BITMAP_AND_OR 1

/*
 * LIBXL_HAVE_FIRMWARE_PASSTHROUGH indicates the feature for
 * passing in SMBIOS and ACPI firmware to HVM guests is present
 * in the library.
 */
#define LIBXL_HAVE_FIRMWARE_PASSTHROUGH 1

/*
 * LIBXL_HAVE_DOMAIN_NODEAFFINITY indicates that a 'nodemap' field
 * (of libxl_bitmap type) is present in libxl_domain_build_info,
 * containing the node-affinity for the domain.
 */
#define LIBXL_HAVE_DOMAIN_NODEAFFINITY 1

/*
 * LIBXL_HAVE_PVUSB indicates functions for plugging in USB devices
 * through pvusb -- both hotplug and at domain creation time..
 */
#define LIBXL_HAVE_PVUSB 1

/*
 * LIBXL_HAVE_BUILDINFO_HVM_VENDOR_DEVICE indicates that the
 * libxl_vendor_device field is present in the hvm sections of
 * libxl_domain_build_info. This field tells libxl which
 * flavour of xen-pvdevice to enable in QEMU.
 */
#define LIBXL_HAVE_BUILDINFO_HVM_VENDOR_DEVICE 1

/*
 * The libxl_domain_build_info has the event_channels field.
 */
#define LIBXL_HAVE_BUILDINFO_EVENT_CHANNELS 1

/*
 * libxl_domain_build_info has the u.hvm.ms_vm_genid field.
 */
#define LIBXL_HAVE_BUILDINFO_HVM_MS_VM_GENID 1

/*
 * LIBXL_HAVE_VCPUINFO_SOFT_AFFINITY indicates that a 'cpumap_soft'
 * field (of libxl_bitmap type) is present in libxl_vcpuinfo,
 * containing the soft affinity of a vcpu.
 */
#define LIBXL_HAVE_VCPUINFO_SOFT_AFFINITY 1

/*
 * LIBXL_HAVE_SET_VCPUAFFINITY_FORCE indicates that the
 * libxl_set_vcpuaffinity_force() library call is available.
 */
#define LIBXL_HAVE_SET_VCPUAFFINITY_FORCE 1

/*
 * LIBXL_HAVE_DEVICE_DISK_DIRECT_IO_SAFE indicates that a
 * 'direct_io_safe' field (of boolean type) is present in
 * libxl_device_disk.
 */
#define LIBXL_HAVE_DEVICE_DISK_DIRECT_IO_SAFE 1

/*
 * The libxl_device_disk has the discard_enable field.
 */
#define LIBXL_HAVE_LIBXL_DEVICE_DISK_DISCARD_ENABLE 1

/*
 * LIBXL_HAVE_BUILDINFO_IOMEM_START_GFN indicates that it is possible
 * to specify the start guest frame number used to map a range of I/O
 * memory machine frame numbers via the 'gfn' field (of type uint64)
 * of the 'iomem' structure. An array of iomem structures is embedded
 * in libxl_domain_build_info and used to map the indicated memory
 * ranges during domain build.
 */
#define LIBXL_HAVE_BUILDINFO_IOMEM_START_GFN 1

/*
 * LIBXL_HAVE_SCHED_RTDS indicates that the RTDS real time scheduler
 * is available. A 'budget' field added in libxl_domain_sched_params.
 */
#define LIBXL_HAVE_SCHED_RTDS 1

/*
 * libxl_domain_build_info has u.hvm.viridian_enable and _disable bitmaps
 * of the specified width.
 */
#define LIBXL_HAVE_BUILDINFO_HVM_VIRIDIAN_ENABLE_DISABLE 1
#define LIBXL_BUILDINFO_HVM_VIRIDIAN_ENABLE_DISABLE_WIDTH 64

/*
 * libxl_domain_build_info has the u.hvm.mmio_hole_memkb field.
 */
#define LIBXL_HAVE_BUILDINFO_HVM_MMIO_HOLE_MEMKB 1

/*
 * libxl_domain_info returns ERROR_DOMAIN_NOTFOUND if the domain
 * is not present, instead of ERROR_INVAL.
 */
#define LIBXL_HAVE_ERROR_DOMAIN_NOTFOUND 1

/*
 * libxl_domain_build_info has device_tree and libxl_device_dtdev
 * exists. This mean Device Tree passthrough is supported for ARM
 */
#define LIBXL_HAVE_DEVICETREE_PASSTHROUGH 1

/*
 * libxl_domain_build_info has device_model_user to specify the user to
 * run the device model with. See docs/misc/qemu-deprivilege.txt.
 */
#define LIBXL_HAVE_DEVICE_MODEL_USER 1

/*
 * libxl_vcpu_sched_params is used to store per-vcpu params.
 */
#define LIBXL_HAVE_VCPU_SCHED_PARAMS 1

/*
 * LIBXL_HAVE_SCHED_RTDS_VCPU_PARAMS indicates RTDS scheduler
 * now supports per-vcpu settings.
 */
#define LIBXL_HAVE_SCHED_RTDS_VCPU_PARAMS 1

/*
 * libxl_domain_build_info has the arm.gic_version field.
 */
#define LIBXL_HAVE_BUILDINFO_ARM_GIC_VERSION 1

/*
 * LIBXL_HAVE_SOFT_RESET indicates that libxl supports performing
 * 'soft reset' for domains and there is 'soft_reset' shutdown reason
 * in enum libxl_shutdown_reason.
 */
#define LIBXL_HAVE_SOFT_RESET 1

/*
 * LIBXL_HAVE_APIC_ASSIST indicates that the 'apic_assist' value
 * is present in the viridian enlightenment enumeration.
 */
#define LIBXL_HAVE_APIC_ASSIST 1

/*
 * LIBXL_HAVE_BUILD_ID means that libxl_version_info has the extra
 * field for the hypervisor build_id.
 */
#define LIBXL_HAVE_BUILD_ID 1

/*
 * LIBXL_HAVE_QEMU_MONITOR_COMMAND indiactes the availability of the
 * libxl_qemu_monitor_command() function.
 */
#define LIBXL_HAVE_QEMU_MONITOR_COMMAND 1

/*
 * LIBXL_HAVE_SCHED_CREDIT2_PARAMS indicates the existance of a
 * libxl_sched_credit2_params structure, containing Credit2 scheduler
 * wide parameters (i.e., the ratelimiting value).
 */
#define LIBXL_HAVE_SCHED_CREDIT2_PARAMS 1

/*
 * LIBXL_BUILDINFO_SUBFIELD_PVH     #defined to simply   u.pvh.  or empty
 * LIBXL_BUILDINFO_SUBFIELD_PV      #defined to simply   u.pv.   or empty
 * LIBXL_BUILDINFO_SUBFIELD_HVM     #defined to simply   u.hvm.  or empty
 *
 * int LIBXL_BUILDINFO_ACCESS_PVH_{PV,HVM}_OK(
 *                 libxl_domain_build_info *b_info,
 *            )
 * field_type *LIBXL_BUILDINFO_ACCESS_PVH_{PV,HVM}(
 *                 libxl_domain_build_info *b_info,
 *                 field_name
 *            )
 *
 * Maybe used to access these fields of libxl_domain_build_info
 *
 *     Xen 4.9 and earlier      Xen <= 4.9        Xen 4.10 and later
 *      HVM and PV guests        PVH guests        all guests
 *
 *       .u.pv.bootloader        .u.pvh.bootloader         .bootloader
 *       .u.pv.bootloader_args   .u.pvh.bootloader_args    .bootloader_args
 *       .u.hvm.timer_mode       .u.pvh.timer_mode         .timer_mode
 *       .u.hvm.apic             .u.pvh.apic               .apic
 *       .u.hvm.nested_hvm       .u.pvh.nested_hvm         .nested_hvm
 *
 *     [1] introduced, like this macro, in the PVH backport series
 #       for Meltdown.
 *
 * _SUBFIELD_FOO can be used when the guest type is known to be FOO
 * (specifically, when b_info->type is LIBXL_DOMAIN_TYPE_FOO)
 *
 * _ACCESS_PVH_FOO should be used for fields which were in .u.foo,
 * at points in the code where the guest type is not fully known.
 * It is only safe to evaluate if the guest type is PVH or FOO.
 * This can be checked with _ACCESS_PVH_FOO_OK.
 *
 * We recommend the folllowing idiom:
 *
 *    #if defined(LIBXL_BUILDINFO_PVH_ACCESS_PVH_HVM) // post-Meltdown
 *    # define U_PV_OK( b) LIBXL_BUILDINFO_ACCESS_PVH_PV_OK( (b))
 *    # define U_HVM_OK(b) LIBXL_BUILDINFO_ACCESS_PVH_HVM_OK((b))
 *    # define U_PV_F( b, f) LIBXL_BUILDINFO_ACCESS_PVH_PV( (b),f)
 *    # define U_HVM_F(b, f) LIBXL_BUILDINFO_ACCESS_PVH_HVM((b),f)
 *    # define U_PVH LIBXL_BUILDINFO_SUBFIELD_PVH
 *    # define U_PV  LIBXL_BUILDINFO_SUBFIELD_PV
 *    # define U_HVM LIBXL_BUILDINFO_SUBFIELD_HVM
 #    #elif defined(LIBXL_HAVE_BUILDINFO_APIC) // >= 4.10 pre-Meltdown
 *    # define U_PV_OK( b) 1
 *    # define U_HVM_OK(b) 1
 *    # define U_PV_F( b, f) (&(b)->f)
 *    # define U_HVM_F(b, f) (&(b)->f)
 *    * define U_PVH // empty
 *    * define U_PV  // empty
 *    * define U_HVM // empty
 *    #else // Xen <= 4.9 pre-Meltdown
 #    # define U_PV_OK( b) ((b)->type == LIBXL_DOMAIN_TYPE_PV )
 #    # define U_HVM_OK(b) ((b)->type == LIBXL_DOMAIN_TYPE_HVM)
 *    # define U_PV_F( b, f) (&(b)->u.pv .f)
 *    # define U_HVM_F(b, f) (&(b)->u.hvm.f)
 *    # define U_PVH UNAVAILABLE_BECAUSE_NO_PVH_SUPPORT_XEN_TOO_OLD
 *    # define U_PV  u.pv.
 *    # define U_HVM u.hvm.
 *    #endif
 *
 * And then something like this:
 *
 *     if (U_HVM_OK(b_info))
 *         libxl_defbool_set(U_HVM(b_info, apic), 1);
 *
 *     case LIBXL_DOMAIN_TYPE_PV:
 *         if (b_info->U_PV bootloader) {
 */

#define LIBXL_BUILDINFO_ACCESS_PVH_PV(b_info, field_name)               \
  ((b_info)->type == LIBXL_DOMAIN_TYPE_PV  ? &(b_info)->u.pv .field_name : \
   (b_info)->type == LIBXL_DOMAIN_TYPE_PVH ? &(b_info)->u.pvh.field_name : \
   (abort(), (typeof(&(b_info)->u.pv. field_name))0))

#define LIBXL_BUILDINFO_ACCESS_PVH_HVM(b_info, field_name)              \
  ((b_info)->type == LIBXL_DOMAIN_TYPE_HVM ? &(b_info)->u.hvm.field_name : \
   (b_info)->type == LIBXL_DOMAIN_TYPE_PVH ? &(b_info)->u.pvh.field_name : \
   (abort(), (typeof(&(b_info)->u.hvm.field_name))0))

#define LIBXL_BUILDINFO_ACCESS_PVH_PV_OK(b_info, field_name)    \
  ((b_info)->type == LIBXL_DOMAIN_TYPE_PV  ? 1 :               \
   (b_info)->type == LIBXL_DOMAIN_TYPE_PVH ? 1 :               \
   0)

#define LIBXL_BUILDINFO_ACCESS_PVH_HVM_OK(b_info, field_name)   \
  ((b_info)->type == LIBXL_DOMAIN_TYPE_HVM ? 1 :               \
   (b_info)->type == LIBXL_DOMAIN_TYPE_PVH ? 1 :               \
   0)

#define LIBXL_BUILDINFO_SUBFIELD_PVH  UNAVAILABLE_BECAUSE_NO_PVH_SUPPORT_XEN_TOO_OLD
#define LIBXL_BUILDINFO_SUBFIELD_PV   u.pv.
#define LIBXL_BUILDINFO_SUBFIELD_HVM  u.hvm.

/*
 * libxl ABI compatibility
 *
 * The only guarantee which libxl makes regarding ABI compatibility
 * across releases is that the SONAME will always be bumped whenever
 * the ABI is changed in an incompatible way.
 *
 * This applies within stable branches as well as
 * development branches. It is possible that a new stable release of
 * Xen may require a rebuild of applications using the
 * library. However per the API compatibility gaurantees such a
 * rebuild should not normally require any source level changes.
 *
 * As with the API compatiblity the SONAME will only be bumped for the
 * first ABI incompatible change in a development branch.
 */

/*
 * libxl memory management
 *
 * From the point of view of the application (ie, libxl's caller),
 * struct libxl_ctx* is threadsafe, and all returned allocated
 * structures are obtained from malloc(), and must be freed by the
 * caller either directly or by calling an appropriate free function
 * provided by libxl.  Ie the application does not get automatic
 * assistance from libxl in managing these allocations.
 *
 * Specific details are in the header comments which should be found
 * in libxl.h or libxlutil.h, next to the relevant function
 * declarations.
 *
 * Internally, libxl has a garbage collection scheme which allows much libxl
 * code to allocate strings etc. for internal use without needing to
 * free them.  These are called "temporary allocations".
 *
 * The pool for these temporary allocations, along with any other
 * thread-specific data which is private to libxl but shared between
 * libxl functions (such as the current xenstore transaction), is
 * stored in the "gc context" which is a special enhanced context
 * structure allocated automatically by convenience macros at every
 * entry to libxl.
 *
 * Every libxl function falls into one of these categories:
 *
 * 1. Public functions (declared in libxl.h, libxlutil.h), which may
 *    be called by libxl applications.  If a public function returns
 *    any allocated object to its caller, that object must have come
 *    from malloc.
 *
 *    The definitions of public functions MUST use the gc context
 *    initialisation macros (or do the equivalent work themselves).
 *    These macros will ensure that all temporary allocations will be
 *    automatically freed before the function returns to its caller.
 *
 *    A public function may be called from within libxl; the call
 *    context initialisation macros will make sure that the internal
 *    caller's context is reused (eg, so that the same xenstore
 *    transaction is used).  But in-libxl callers of libxl public
 *    functions should note that any libxl public function may cause
 *    recursively reentry into libxl via the application's event
 *    callback hook.
 *
 *    Public functions have names like libxl_foobar.
 *
 * 2. Private functions, which may not be called by libxl
 *    applications; they are not declared in libxl.h or libxlutil.h
 *    and they may not be called other than by other libxl functions.
 *
 *    Private functions should not use the gc context initialisation
 *    macros.
 *
 *    Private functions have names like libxl__foobar (NB, two underscores).
 *    Also the declaration of such functions must be preceeded by the _hidden
 *    macro.
 *
 * Allocations made by a libxl function fall into one of the following
 * categories (where "object" includes any memory allocation):
 *
 * (a) Objects which are not returned to the function's caller.
 *     These should be allocated from the temporary pool.
 *
 * (b) Objects which are intended for return to the calling
 *     application.  This includes all allocated objects returned by
 *     any public function.
 *
 *     It may also include objects allocated by an internal function
 *     specifically for eventual return by the function's external
 *     callers, but this situation should be clearly documented in
 *     comments.
 *
 *     These should be allocated from malloc() et al. and comments
 *     near the function declaration should explain the memory
 *     ownership.  If a simple free() by the application is not
 *     sufficient, a suitable public freeing function should be
 *     provided.
 *
 * (c) Internal objects whose size and/or lifetime dictate explicit
 *     memory management within libxl.  This includes objects which
 *     will be embedded in opaque structures which will be returned to
 *     the libxl caller (more generally, any internal object whose
 *     lifetime exceeds the libxl entrypoint which creates it) and
 *     objects which are so large or numerous that explicit memory
 *     management is required.
 *
 *     These should be allocated from malloc() et al., and freed
 *     explicitly at the appropriate point.  The situation should be
 *     documented in comments.
 *
 * (d) Objects which are allocated by internal-only functions and
 *     returned to the function's (therefore, internal) caller but are
 *     strictly for internal use by other parts of libxl.  These
 *     should be allocated from the temporary pool.
 *
 *     Where a function's primary purpose is to return such an object,
 *     it should have a libxl__gc * as it's first argument.
 *
 *     Note that there are two ways to change an allocation from this
 *     category to the "public" category. Either the implementation
 *     is kept internal and a wrapper function duplicates all memory
 *     allocations so that they are suitable for return to external
 *     callers or the implementation uses plain malloc() et al calls
 *     and an internal wrapper adds the relevant pointers to the gc.
 *     The latter method is preferred for obvious performance reasons.
 *
 * No temporary objects allocated from the pool may be explicitly freed.
 * Therefore public functions which initialize a libxl__gc MUST call
 * libxl__free_all() before returning.
 *
 * Memory allocation failures are not handled gracefully.  If malloc
 * (or realloc) fails, libxl will cause the entire process to print
 * a message to stderr and exit with status 255.
 */
/*
 * libxl types
 *
 * Most libxl types are defined by the libxl IDL (see
 * libxl_types.idl). The library provides a common set of methods for
 * initialising and freeing these types.
 *
 * IDL-generated libxl types should be used as follows: the user must
 * always call the "init" function before using a type, even if the
 * variable is simply being passed by reference as an out parameter
 * to a libxl function.  The user must always calls "dispose" exactly
 * once afterwards, to clean up, regardless of whether operations on
 * this object succeeded or failed.  See the xl code for examples.
 *
 * "init" and "dispose" are idempotent.
 *
 * void libxl_<type>_init(<type> *p):
 *
 *    Initialises the members of "p" to all defaults. These may either
 *    be special value which indicates to the library that it should
 *    select an appropriate default when using this field or actual
 *    default values.
 *
 *    Some fields within a data type (e.g. unions) cannot be sensibly
 *    initialised without further information. In these cases a
 *    separate subfield initialisation function is provided (see
 *    below).
 *
 *    An instance which has been initialised using this method can
 *    always be safely passed to the dispose function (see
 *    below). This is true even if the data type contains fields which
 *    require a separate call to a subfield initialisation function.
 *
 *    This method is provided for any aggregate type which is used as
 *    an input parameter.
 *
 * void libxl_<type>_init_<subfield>(<type> *p, subfield):
 *
 *    Initialise those parts of "p" which are not initialised by the
 *    main init function due to the unknown value of "subfield". Sets
 *    p->subfield as well as initialising any fields to their default
 *    values.
 *
 *    p->subfield must not have been previously initialised.
 *
 *    This method is provided for any aggregate type.
 *
 * void libxl_<type>_dispose(instance *p):
 *
 *    Frees any dynamically allocated memory used by the members of
 *    "p" but not the storage used by "p" itself (this allows for the
 *    allocation of arrays of types and for the composition of types).
 *
 * char *libxl_<type>_to_json(instance *p)
 *
 *    Generates a JSON object from "p" in the form of a NULL terminated
 *    string.
 *
 * <type *> libxl_<type>_from_json(const char *json)
 * int      libxl_<type>_from_json(const char *json)
 *
 *    Parses "json" and returns:
 *
 *    an int value, if <type> is enumeration type. The value is the enum value
 *    representing the respective string in "json".
 *
 *    an instance of <type>, if <type> is aggregate type. The returned
 *    instance has its fields filled in by the parser according to "json".
 *
 *    If the parsing fails, caller cannot rely on the value / instance
 *    returned.
 */
#ifndef LIBXL_H
#define LIBXL_H

#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/wait.h> /* for pid_t */

#include <xentoollog.h>

typedef struct libxl__ctx libxl_ctx;

#include <libxl_uuid.h>
#include <_libxl_list.h>

/* API compatibility. */
#ifdef LIBXL_API_VERSION
#if LIBXL_API_VERSION != 0x040200 && LIBXL_API_VERSION != 0x040300 && \
    LIBXL_API_VERSION != 0x040400 && LIBXL_API_VERSION != 0x040500
#error Unknown LIBXL_API_VERSION
#endif
#endif

/* LIBXL_HAVE_RETRIEVE_DOMAIN_CONFIGURATION
 *
 * If this is defined we have libxl_retrieve_domain_configuration which
 * returns the current configuration of a domain, which can be used to
 * rebuild a domain.
 */
#define LIBXL_HAVE_RETRIEVE_DOMAIN_CONFIGURATION 1

/*
 * LIBXL_HAVE_BUILDINFO_VCPU_AFFINITY_ARRAYS
 *
 * If this is defined, then the libxl_domain_build_info structure will
 * contain two arrays of libxl_bitmap-s, with all the necessary information
 * to set the hard affinity (vcpu_hard_affinity) and the soft affinity
 * (vcpu_soft_affinity) of the VCPUs.
 *
 * Note that, if the vcpu_hard_affinity array is used, libxl will ignore
 * the content of the cpumap field of libxl_domain_build_info. That is to
 * say, if the array is allocated and used by the caller, it is it and
 * only it that determines the hard affinity of the domain's VCPUs.
 *
 * The number of libxl_bitmap-s in the arrays should be equal to the
 * maximum number of VCPUs of the domain. If there only are N elements in
 * an array, with N smaller the the maximum number of VCPUs, the hard or
 * soft affinity (depending on which array we are talking about) will be
 * set only for the first N VCPUs. The other VCPUs will just have affinity,
 * both hard and soft, with all the host PCPUs.
 * Each bitmap should be big enough to accommodate the maximum number of
 * PCPUs of the host.
 */
#define LIBXL_HAVE_BUILDINFO_VCPU_AFFINITY_ARRAYS 1

/*
 * LIBXL_HAVE_BUILDINFO_USBDEVICE_LIST
 *
 * If this is defined, then the libxl_domain_build_info structure will
 * contain hvm.usbdevice_list, a libxl_string_list type that contains
 * a list of USB devices to specify on the qemu command-line.
 *
 * If it is set, callers may use either hvm.usbdevice or
 * hvm.usbdevice_list, but not both; if both are set, libxl will
 * throw an error.
 *
 * If this is not defined, callers can only use hvm.usbdevice.  Note
 * that this means only one device can be added at domain build time.
 */
#define LIBXL_HAVE_BUILDINFO_USBDEVICE_LIST 1

/*
 * LIBXL_HAVE_BUILDINFO_USBVERSION
 *
 * If this is defined, then the libxl_domain_build_info structure will
 * contain hvm.usbversion, a integer type that contains a USB
 * controller version to specify on the qemu upstream command-line.
 *
 * If it is set, callers may use hvm.usbversion to specify if the usb
 * controller is usb1, usb2 or usb3.
 *
 * If this is not defined, the hvm.usbversion field does not exist.
 */
#define LIBXL_HAVE_BUILDINFO_USBVERSION 1

/*
 * LIBXL_HAVE_DEVICE_BACKEND_DOMNAME
 *
 * If this is defined, libxl_device_* structures containing a backend_domid
 * field also contain a backend_domname field.  If backend_domname is set, it is
 * resolved to a domain ID when the device is used and takes precedence over the
 * backend_domid field.
 *
 * If this is not defined, the backend_domname field does not exist.
 */
#define LIBXL_HAVE_DEVICE_BACKEND_DOMNAME 1

/*
 * LIBXL_HAVE_NONCONST_EVENT_OCCURS_EVENT_ARG
 *
 * This argument was erroneously "const" in the 4.2 release despite
 * the requirement for the callback to free the event.
 */
#if LIBXL_API_VERSION != 0x040200
#define LIBXL_HAVE_NONCONST_EVENT_OCCURS_EVENT_ARG 1
#endif

/*
 * LIBXL_HAVE_NONCONST_LIBXL_BASENAME_RETURN_VALUE
 *
 * The return value of libxl_basename is malloc'ed but the erroneously
 * marked as "const" in releases before 4.5.
 */
#if !defined(LIBXL_API_VERSION) || LIBXL_API_VERSION >= 0x040500
#define LIBXL_HAVE_NONCONST_LIBXL_BASENAME_RETURN_VALUE 1
#endif

/*
 * LIBXL_HAVE_PHYSINFO_OUTSTANDING_PAGES
 *
 * If this is defined, libxl_physinfo structure will contain an uint64 field
 * called outstanding_pages, containing the number of pages claimed but not
 * yet allocated for all domains.
 */
#define LIBXL_HAVE_PHYSINFO_OUTSTANDING_PAGES 1

/*
 * LIBXL_HAVE_DOMINFO_OUTSTANDING_MEMKB 1
 *
 * If this is defined, libxl_dominfo will contain a MemKB type field called
 * outstanding_memkb, containing the amount of claimed but not yet allocated
 * memory for a specific domain.
 */
#define LIBXL_HAVE_DOMINFO_OUTSTANDING_MEMKB 1

/*
 * LIBXL_HAVE_DOMINFO_NEVER_STOP
 *
 * If this is defined, libxl_dominfo will contain a flag called never_stop
 * indicating that the specific domain should never be stopped by the
 * toolstack.
 */
#define LIBXL_HAVE_DOMINFO_NEVER_STOP 1

/*
 * LIBXL_HAVE_QXL
 *
 * If defined, then the libxl_vga_interface_type will contain another value:
 * "QXL". This value define if qxl vga is supported.
 *
 * If this is not defined, the qxl vga support is missed.
 */
#define LIBXL_HAVE_QXL 1

/*
 * LIBXL_HAVE_SPICE_VDAGENT
 *
 * If defined, then the libxl_spice_info structure will contain a boolean type:
 * vdagent and clipboard_sharing. These values define if Spice vdagent and
 * clipboard sharing are enabled.
 *
 * If this is not defined, the Spice vdagent support is ignored.
 */
#define LIBXL_HAVE_SPICE_VDAGENT 1

/*
 * LIBXL_HAVE_SPICE_USBREDIRECTION
 *
 * If defined, then the libxl_spice_info structure will contain an integer type
 * field: usbredirection. This value defines if Spice usbredirection is enabled
 * and with how much channels.
 *
 * If this is not defined, the Spice usbredirection support is ignored.
 */
#define LIBXL_HAVE_SPICE_USBREDIREDIRECTION 1

/*
 * LIBXL_HAVE_SPICE_IMAGECOMPRESSION
 *
 * If defined, then the libxl_spice_info structure will contain a string type
 * field: image_compression. This value defines what Spice image compression
 * is used.
 *
 * If this is not defined, the Spice image compression setting support is ignored.
 */
#define LIBXL_HAVE_SPICE_IMAGECOMPRESSION 1

/*
 * LIBXL_HAVE_SPICE_STREAMINGVIDEO
 *
 * If defined, then the libxl_spice_info structure will contain a string type
 * field: streaming_video. This value defines what Spice streaming video setting
 * is used.
 *
 * If this is not defined, the Spice streaming video setting support is ignored.
 */
#define LIBXL_HAVE_SPICE_STREAMINGVIDEO 1

/*
 * LIBXL_HAVE_HVM_HDTYPE
 *
 * If defined, then the u.hvm structure will contain a enum type
 * hdtype.
 */
#define LIBXL_HAVE_HVM_HDTYPE 1

/*
 * LIBXL_HAVE_DOMAIN_CREATE_RESTORE_PARAMS 1
 *
 * If this is defined, libxl_domain_create_restore()'s API has changed to
 * include a params structure.
 */
#define LIBXL_HAVE_DOMAIN_CREATE_RESTORE_PARAMS 1

/*
 * LIBXL_HAVE_DOMAIN_CREATE_RESTORE_SEND_BACK_FD 1
 *
 * If this is defined, libxl_domain_create_restore()'s API includes the
 * send_back_fd param. This is used only with COLO, for the libxl migration
 * back channel; other callers should pass -1.
 */
#define LIBXL_HAVE_DOMAIN_CREATE_RESTORE_SEND_BACK_FD 1

/*
 * LIBXL_HAVE_CREATEINFO_PVH
 * If this is defined, then libxl supports creation of a PVH guest.
 */
#define LIBXL_HAVE_CREATEINFO_PVH 1

/*
 * LIBXL_HAVE_DRIVER_DOMAIN_CREATION 1
 *
 * If this is defined, libxl_domain_create_info contains a driver_domain
 * field that can be used to tell libxl that the domain that is going
 * to be created is a driver domain, so the necessary actions are taken.
 */
#define LIBXL_HAVE_DRIVER_DOMAIN_CREATION 1

/*
 * LIBXL_HAVE_SIGCHLD_SELECTIVE_REAP
 *
 * If this is defined:
 *
 * Firstly, the enum libxl_sigchld_owner (in libxl_event.h) has the
 * value libxl_sigchld_owner_libxl_always_selective_reap which may be
 * passed to libxl_childproc_setmode in hooks->chldmode.
 *
 * Secondly, the function libxl_childproc_sigchld_occurred exists.
 */
#define LIBXL_HAVE_SIGCHLD_OWNER_SELECTIVE_REAP 1

/*
 * LIBXL_HAVE_SIGCHLD_SHARING
 *
 * If this is defined, it is permissible for multiple libxl ctxs
 * to simultaneously "own" SIGCHLD.  See "Subprocess handling"
 * in libxl_event.h.
 */
#define LIBXL_HAVE_SIGCHLD_SHARING 1

/*
 * LIBXL_HAVE_NO_SUSPEND_RESUME
 *
 * Is this is defined then the platform has no support for saving,
 * restoring or migrating a domain. In this case the related functions
 * should be expected to return failure. That is:
 *  - libxl_domain_suspend
 *  - libxl_domain_resume
 *  - libxl_domain_remus_start
 */
#if defined(__arm__) || defined(__aarch64__)
#define LIBXL_HAVE_NO_SUSPEND_RESUME 1
#endif

/*
 * LIBXL_HAVE_DEVICE_PCI_SEIZE
 *
 * If this is defined, then the libxl_device_pci struct will contain
 * the "seize" boolean field.  If this field is set, libxl_pci_add will
 * check to see if the device is currently assigned to pciback, and if not,
 * it will attempt to do so (unbinding the device from the existing driver).
 */
#define LIBXL_HAVE_DEVICE_PCI_SEIZE 1

/*
 * LIBXL_HAVE_BUILDINFO_KERNEL
 *
 * If this is defined, then the libxl_domain_build_info structure will
 * contain 'kernel', 'ramdisk', 'cmdline' fields. 'kernel' is a string
 * to indicate kernel image location, 'ramdisk' is a string to indicate
 * ramdisk location, 'cmdline' is a string to indicate the paramters which
 * would be appended to kernel image.
 *
 * Both PV guest and HVM guest can use these fields for direct kernel boot.
 * But for compatibility reason, u.pv.kernel, u.pv.ramdisk and u.pv.cmdline
 * still exist.
 */
#define LIBXL_HAVE_BUILDINFO_KERNEL 1

/*
 * LIBXL_HAVE_DEVICE_CHANNEL
 *
 * If this is defined, then the libxl_device_channel struct exists
 * and channels can be attached to a domain. Channels manifest as consoles
 * with names, see docs/misc/console.txt.
 */
#define LIBXL_HAVE_DEVICE_CHANNEL 1

/*
 * LIBXL_HAVE_AO_ABORT indicates the availability of libxl_ao_abort
 */
#define LIBXL_HAVE_AO_ABORT 1

/* Functions annotated with LIBXL_EXTERNAL_CALLERS_ONLY may not be
 * called from within libxl itself. Callers outside libxl, who
 * do not #include libxl_internal.h, are fine. */
#ifndef LIBXL_EXTERNAL_CALLERS_ONLY
#define LIBXL_EXTERNAL_CALLERS_ONLY /* disappears for callers outside libxl */
#endif

/*
 *  LIBXL_HAVE_UUID_COPY_CTX_PARAM
 *
 * If this is defined, libxl_uuid_copy has changed to take a libxl_ctx
 * structure.
 */
#define LIBXL_HAVE_UUID_COPY_CTX_PARAM 1

/*
 * LIBXL_HAVE_SSID_LABEL
 *
 * If this is defined, then libxl IDL contains string of XSM security
 * label in all XSM related structures.
 *
 * If set this string takes precedence over the numeric field.
 */
#define LIBXL_HAVE_SSID_LABEL 1

/*
 * LIBXL_HAVE_CPUPOOL_NAME
 *
 * If this is defined, then libxl IDL contains string of CPU pool
 * name in all CPU pool related structures.
 *
 * If set this string takes precedence over the numeric field.
 */
#define LIBXL_HAVE_CPUPOOL_NAME 1

/*
 * LIBXL_HAVE_BUILDINFO_SERIAL_LIST
 *
 * If this is defined, then the libxl_domain_build_info structure will
 * contain hvm.serial_list, a libxl_string_list type that contains
 * a list of serial ports to specify on the qemu command-line.
 *
 * If it is set, callers may use either hvm.serial or
 * hvm.serial_list, but not both; if both are set, libxl will
 * throw an error.
 *
 * If this is not defined, callers can only use hvm.serial.  Note
 * that this means only one serial port can be added at domain build time.
 */
#define LIBXL_HAVE_BUILDINFO_SERIAL_LIST 1

/*
 * LIBXL_HAVE_ALTP2M
 * If this is defined, then libxl supports alternate p2m functionality.
 */
#define LIBXL_HAVE_ALTP2M 1

/*
 * LIBXL_HAVE_REMUS
 * If this is defined, then libxl supports remus.
 */
#define LIBXL_HAVE_REMUS 1

typedef uint8_t libxl_mac[6];
#define LIBXL_MAC_FMT "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx"
#define LIBXL_MAC_FMTLEN ((2*6)+5) /* 6 hex bytes plus 5 colons */
#define LIBXL_MAC_BYTES(mac) mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
void libxl_mac_copy(libxl_ctx *ctx, libxl_mac *dst, const libxl_mac *src);

#if defined(__i386__) || defined(__x86_64__)
/*
 * LIBXL_HAVE_PSR_CMT
 *
 * If this is defined, the Cache Monitoring Technology feature is supported.
 */
#define LIBXL_HAVE_PSR_CMT 1

/*
 * LIBXL_HAVE_PSR_MBM
 *
 * If this is defined, the Memory Bandwidth Monitoring feature is supported.
 */
#define LIBXL_HAVE_PSR_MBM 1

/*
 * LIBXL_HAVE_PSR_CAT
 *
 * If this is defined, the Cache Allocation Technology feature is supported.
 */
#define LIBXL_HAVE_PSR_CAT 1

/*
 * LIBXL_HAVE_PSR_CDP
 *
 * If this is defined, the Code and Data Prioritization feature is supported.
 */
#define LIBXL_HAVE_PSR_CDP 1
#endif

/*
 * LIBXL_HAVE_PCITOPOLOGY
 *
 * If this is defined, then interface to query hypervisor about PCI device
 * topology is available.
 */
#define LIBXL_HAVE_PCITOPOLOGY 1

/*
 * LIBXL_HAVE_SOCKET_BITMAP
 *
 * If this is defined, then libxl_socket_bitmap_alloc and
 * libxl_get_online_socketmap exist.
 */
#define LIBXL_HAVE_SOCKET_BITMAP 1

/*
 * LIBXL_HAVE_SRM_V2
 *
 * If this is defined, then the libxl_domain_create_restore() interface takes
 * a "stream_version" parameter and supports a value of 2.
 *
 * libxl_domain_suspend() will produce a v2 stream.
 */
#define LIBXL_HAVE_SRM_V2 1

/*
 * LIBXL_HAVE_SRM_V1
 *
 * In the case that LIBXL_HAVE_SRM_V2 is set, LIBXL_HAVE_SRM_V1
 * indicates that libxl_domain_create_restore() can handle a "stream_version"
 * parameter of 1, and convert the stream format automatically.
 */
#define LIBXL_HAVE_SRM_V1 1

/*
 * libxl_domain_build_info has the u.hvm.gfx_passthru_kind field and
 * the libxl_gfx_passthru_kind enumeration is defined.
*/
#define LIBXL_HAVE_GFX_PASSTHRU_KIND

/*
 * LIBXL_HAVE_CHECKPOINTED_STREAM
 *
 * If this is defined, then libxl_checkpointed_stream exists.
 */
#define LIBXL_HAVE_CHECKPOINTED_STREAM 1

/*
 * LIBXL_HAVE_BUILDINFO_HVM_SYSTEM_FIRMWARE
 *
 * libxl_domain_build_info has u.hvm.system_firmware field which can be use
 * to provide a different firmware blob (like SeaBIOS or OVMF).
 */
#define LIBXL_HAVE_BUILDINFO_HVM_SYSTEM_FIRMWARE

/*
 * ERROR_REMUS_XXX error code only exists from Xen 4.5, Xen 4.6 and it
 * is changed to ERROR_CHECKPOINT_XXX in Xen 4.7
 */
#if defined(LIBXL_API_VERSION) && LIBXL_API_VERSION >= 0x040500 \
                               && LIBXL_API_VERSION < 0x040700
#define ERROR_REMUS_DEVOPS_DOES_NOT_MATCH \
        ERROR_CHECKPOINT_DEVOPS_DOES_NOT_MATCH
#define ERROR_REMUS_DEVICE_NOT_SUPPORTED \
        ERROR_CHECKPOINT_DEVICE_NOT_SUPPORTED
#endif

/*
 * LIBXL_HAVE_VGA_INTERFACE_TYPE_UNKNOWN
 *
 * In the case that LIBXL_HAVE_VGA_INTERFACE_TYPE_UNKNOWN is set the
 * libxl_vga_interface_type enumeration type contains a
 * LIBXL_VGA_INTERFACE_TYPE_UNKNOWN identifier. This is used to signal
 * that a libxl_vga_interface_type type has not been initialized yet.
 */
#define LIBXL_HAVE_VGA_INTERFACE_TYPE_UNKNOWN 1

/*
 * LIBXL_HAVE_BYTEARRAY_UUID
 *
 * If this is defined, the internal member of libxl_uuid is defined
 * as a 16 byte array that contains the UUID in big endian format.
 * Also, the same structure layout is used across all OSes.
 */
#define LIBXL_HAVE_BYTEARRAY_UUID 1

/*
 * LIBXL_HAVE_MEMKB_64BITS
 *
 * If this is defined libxl_set_memory_target(), libxl_domain_setmaxmem()
 * and libxl_wait_for_free_memory()  will take a 64 bit value for the memory
 * size parameter.
 * From Xen 4.8 on libxl_get_memory_target(), libxl_domain_need_memory() and
 * libxl_get_free_memory() return the memory size in a 64 bit value, too.
 */
#define LIBXL_HAVE_MEMKB_64BITS 1

/*
 * LIBXL_HAVE_PV_SHIM
 *
 * If this is defined, libxl_domain_build_info's pvh type information
 * contains members pvshim, pvshim_path, pvshim_cmdline, pvshim_extra.
 */
#define LIBXL_HAVE_PV_SHIM 1

typedef char **libxl_string_list;
void libxl_string_list_dispose(libxl_string_list *sl);
int libxl_string_list_length(const libxl_string_list *sl);
void libxl_string_list_copy(libxl_ctx *ctx, libxl_string_list *dst,
                            const libxl_string_list *src);

typedef char **libxl_key_value_list;
void libxl_key_value_list_dispose(libxl_key_value_list *kvl);
int libxl_key_value_list_length(const libxl_key_value_list *kvl);
void libxl_key_value_list_copy(libxl_ctx *ctx,
                               libxl_key_value_list *dst,
                               const libxl_key_value_list *src);

typedef uint32_t libxl_hwcap[8];
void libxl_hwcap_copy(libxl_ctx *ctx, libxl_hwcap *dst, const libxl_hwcap *src);

typedef uint64_t libxl_ev_user;

typedef struct {
    uint32_t size;          /* number of bytes in map */
    uint8_t *map;
} libxl_bitmap;
void libxl_bitmap_init(libxl_bitmap *map);
void libxl_bitmap_dispose(libxl_bitmap *map);

/* libxl_cpuid_policy_list is a dynamic array storing CPUID policies
 * for multiple leafs. It is terminated with an entry holding
 * XEN_CPUID_INPUT_UNUSED in input[0]
 */
typedef struct libxl__cpuid_policy libxl_cpuid_policy;
typedef libxl_cpuid_policy * libxl_cpuid_policy_list;
void libxl_cpuid_dispose(libxl_cpuid_policy_list *cpuid_list);
int libxl_cpuid_policy_list_length(const libxl_cpuid_policy_list *l);
void libxl_cpuid_policy_list_copy(libxl_ctx *ctx,
                                  libxl_cpuid_policy_list *dst,
                                  const libxl_cpuid_policy_list *src);

#define LIBXL_PCI_FUNC_ALL (~0U)

typedef uint32_t libxl_domid;
typedef int libxl_devid;

/*
 * Formatting Enumerations.
 *
 * Each enumeration type libxl_E declares an associated lookup table
 * libxl_E_string_table and a lookup function libxl_E_from_string.
 */
typedef struct {
    const char *s;
    int v;
} libxl_enum_string_table;

struct libxl_event;
typedef LIBXL_TAILQ_ENTRY(struct libxl_event) libxl_ev_link;

/*
 * A boolean variable with an explicit default state.
 *
 * Users should treat this struct as opaque and use the following
 * defined macros and accessor functions.
 *
 * To allow users of the library to naively select all defaults this
 * state is represented as 0. False is < 0 and True is > 0.
 */
typedef struct {
    int val;
} libxl_defbool;

void libxl_defbool_set(libxl_defbool *db, bool b);
/* Resets to default */
void libxl_defbool_unset(libxl_defbool *db);
/* Sets db only if it is currently == default */
void libxl_defbool_setdefault(libxl_defbool *db, bool b);
bool libxl_defbool_is_default(libxl_defbool db);
/* db must not be == default */
bool libxl_defbool_val(libxl_defbool db);

const char *libxl_defbool_to_string(libxl_defbool b);

#define LIBXL_TIMER_MODE_DEFAULT -1
#define LIBXL_MEMKB_DEFAULT ~0ULL

/*
 * We'd like to set a memory boundary to determine if we need to check
 * any overlap with reserved device memory.
 */
#define LIBXL_RDM_MEM_BOUNDARY_MEMKB_DEFAULT (2048 * 1024)

#define LIBXL_MS_VM_GENID_LEN 16
typedef struct {
    uint8_t bytes[LIBXL_MS_VM_GENID_LEN];
} libxl_ms_vm_genid;

#include "_libxl_types.h"

const libxl_version_info* libxl_get_version_info(libxl_ctx *ctx);

/*
 * Some libxl operations can take a long time.  These functions take a
 * parameter to control their concurrency:
 *     libxl_asyncop_how *ao_how
 *
 * If ao_how==NULL, the function will be synchronous.
 *
 * If ao_how!=NULL, the function will set the operation going, and if
 * this is successful will return 0.  In this case the zero error
 * response does NOT mean that the operation was successful; it just
 * means that it has been successfully started.  It will finish later,
 * perhaps with an error.
 *
 * If ao_how->callback!=NULL, the callback will be called when the
 * operation completes.  The same rules as for libxl_event_hooks
 * apply, including the reentrancy rules and the possibility of
 * "disaster", except that libxl calls ao_how->callback instead of
 * libxl_event_hooks.event_occurs.  (See libxl_event.h.)
 *
 * If ao_how->callback==NULL, a libxl_event will be generated which
 * can be obtained from libxl_event_wait or libxl_event_check.  The
 * event will have type OPERATION_COMPLETE (which is not used
 * elsewhere).
 *
 * Note that it is possible for an asynchronous operation which is to
 * result in a callback to complete during its initiating function
 * call.  In this case the initiating function will return 0
 * indicating the at the operation is "in progress", even though by
 * the time it returns the operation is complete and the callback has
 * already happened.
 *
 * The application must set and use ao_how->for_event (which will be
 * copied into libxl_event.for_user) or ao_how->for_callback (passed
 * to the callback) to determine which operation finished, and it must
 * of course check the rc value for errors.
 *
 * *ao_how does not need to remain valid after the initiating function
 * returns. All other parameters must remain valid for the lifetime of
 * the asynchronous operation, unless otherwise specified.
 *
 * Callbacks may occur on any thread in which the application calls
 * libxl.
 */

typedef struct {
    void (*callback)(libxl_ctx *ctx, int rc, void *for_callback);
    union {
        libxl_ev_user for_event; /* used if callback==NULL */
        void *for_callback; /* passed to callback */
    } u;
} libxl_asyncop_how;

/*
 * Some more complex asynchronous operations can report intermediate
 * progress.  How this is to be reported is controlled, for each
 * function, by a parameter
 *    libxl_asyncprogress_how *aop_FOO_how;
 * for each kind of progress FOO supported by that function.  Each
 * such kind of progress is associated with an event type.
 *
 * The function description will document whether, when, and how
 * many times, the intermediate progress will be reported, and
 * what the corresponding event type(s) are.
 *
 * If aop_FOO_how==NULL, intermediate progress reports are discarded.
 *
 * If aop_FOO_how->callback==NULL, intermediate progress reports
 * generate libxl events which can be obtained from libxl_event_wait
 * or libxl_event_check.
 *
 * If aop_FOO_how->callback!=NULL, libxl will report intermediate
 * progress by calling callback(ctx, &event, for_callback).
 *
 * The rules for these events are otherwise the same as those for
 * ordinary events.  The reentrancy and threading rules for the
 * callback are the same as those for ao completion callbacks.
 *
 * Note that the callback, if provided, is responsible for freeing
 * the event.
 *
 * If callbacks are requested, they will be made, and returned, before
 * the long-running libxl operation is considered finished (so if the
 * long-running libxl operation was invoked with ao_how==NULL then any
 * callbacks will occur strictly before the long-running operation
 * returns).  However, the callbacks may occur on any thread.
 *
 * In general, otherwise, no promises are made about the relative
 * order of callbacks in a multithreaded program.  In particular
 * different callbacks relating to the same long-running operation may
 * be delivered out of order.
 */

typedef struct {
    void (*callback)(libxl_ctx *ctx, libxl_event*, void *for_callback);
    libxl_ev_user for_event; /* always used */
    void *for_callback; /* passed to callback */
} libxl_asyncprogress_how;

/*
 * It is sometimes possible to abort an asynchronous operation.
 *
 * libxl_ao_abort searches for an ongoing asynchronous operation whose
 * ao_how is identical to *how, and tries to abort it.  The return
 * values from libxl_ao_abort are as follows:
 *
 *  0
 *
 *     The operation was found, and attempts are being made to cut it
 *     short.  However, it may still take some time to stop.  It is
 *     also possible that the operation will nevertheless complete
 *     successfully.
 *
 *  ERROR_NOTFOUND
 *
 *      No matching ongoing operation was found.  This might happen
 *      for an actual operation if the operation has already completed
 *      (perhaps on another thread).  The call to libxl_ao_abort has
 *      had no effect.
 *
 *  ERROR_ABORTED
 *
 *     The operation has already been the subject of at least one
 *     call to libxl_ao_abort.
 *
 * If the operation was indeed cut short due to the abort request, it
 * will complete, at some point in the future, with ERROR_ABORTED.  In
 * that case, depending on the operation it have performed some of the
 * work in question and left the operation half-done.  Consult the
 * documentation for individual operations.
 *
 * Note that an aborted operation might still fail for other reasons
 * even after the abort was requested.
 *
 * If your application is multithreaded you must not reuse an
 * ao_how->for_event or ao_how->for_callback value (with a particular
 * ao_how->callback) unless you are sure that none of your other
 * threads are going to abort the previous operation using that
 * value; otherwise you risk aborting the wrong operation if the
 * intended target of the abort request completes in the meantime.
 *
 * It is possible to abort even an operation which is being performed
 * synchronously, but since in that case how==NULL you had better only
 * have one such operation, because it is not possible to tell them
 * apart (and libxl_ao_abort will abort only the first one it finds).
 * (And, if you want to do this, obviously the abort would have to be
 * requested on a different thread.)
 */
int libxl_ao_abort(libxl_ctx *ctx, const libxl_asyncop_how *how)
                   LIBXL_EXTERNAL_CALLERS_ONLY;


#define LIBXL_VERSION 0

/* context functions */
int libxl_ctx_alloc(libxl_ctx **pctx, int version,
                    unsigned flags /* none currently defined */,
                    xentoollog_logger *lg);
int libxl_ctx_free(libxl_ctx *ctx /* 0 is OK */);

/* domain related functions */

/* If the result is ERROR_ABORTED, the domain may or may not exist
 * (in a half-created state).  *domid will be valid and will be the
 * domain id, or -1, as appropriate */

int libxl_domain_create_new(libxl_ctx *ctx, libxl_domain_config *d_config,
                            uint32_t *domid,
                            const libxl_asyncop_how *ao_how,
                            const libxl_asyncprogress_how *aop_console_how)
                            LIBXL_EXTERNAL_CALLERS_ONLY;
int libxl_domain_create_restore(libxl_ctx *ctx, libxl_domain_config *d_config,
                                uint32_t *domid, int restore_fd,
                                int send_back_fd,
                                const libxl_domain_restore_params *params,
                                const libxl_asyncop_how *ao_how,
                                const libxl_asyncprogress_how *aop_console_how)
                                LIBXL_EXTERNAL_CALLERS_ONLY;

#if defined(LIBXL_API_VERSION) && LIBXL_API_VERSION < 0x040400

static inline int libxl_domain_create_restore_0x040200(
    libxl_ctx *ctx, libxl_domain_config *d_config,
    uint32_t *domid, int restore_fd,
    const libxl_asyncop_how *ao_how,
    const libxl_asyncprogress_how *aop_console_how)
    LIBXL_EXTERNAL_CALLERS_ONLY
{
    libxl_domain_restore_params params;
    int ret;

    libxl_domain_restore_params_init(&params);

    ret = libxl_domain_create_restore(
        ctx, d_config, domid, restore_fd, -1, &params, ao_how, aop_console_how);

    libxl_domain_restore_params_dispose(&params);
    return ret;
}

#define libxl_domain_create_restore libxl_domain_create_restore_0x040200

#elif defined(LIBXL_API_VERSION) && LIBXL_API_VERSION >= 0x040400 \
                                 && LIBXL_API_VERSION < 0x040700

static inline int libxl_domain_create_restore_0x040400(
    libxl_ctx *ctx, libxl_domain_config *d_config,
    uint32_t *domid, int restore_fd,
    const libxl_domain_restore_params *params,
    const libxl_asyncop_how *ao_how,
    const libxl_asyncprogress_how *aop_console_how)
    LIBXL_EXTERNAL_CALLERS_ONLY
{
    return libxl_domain_create_restore(ctx, d_config, domid, restore_fd,
                                       -1, params, ao_how, aop_console_how);
}

#define libxl_domain_create_restore libxl_domain_create_restore_0x040400

#endif

int libxl_domain_soft_reset(libxl_ctx *ctx,
                            libxl_domain_config *d_config,
                            uint32_t domid,
                            const libxl_asyncop_how *ao_how,
                            const libxl_asyncprogress_how
                            *aop_console_how)
                            LIBXL_EXTERNAL_CALLERS_ONLY;

  /* A progress report will be made via ao_console_how, of type
   * domain_create_console_available, when the domain's primary
   * console is available and can be connected to.
   */

void libxl_domain_config_init(libxl_domain_config *d_config);
void libxl_domain_config_dispose(libxl_domain_config *d_config);

/*
 * Retrieve domain configuration and filled it in d_config. The
 * returned configuration can be used to rebuild a domain. It only
 * works with DomU.
 */
int libxl_retrieve_domain_configuration(libxl_ctx *ctx, uint32_t domid,
                                        libxl_domain_config *d_config)
                                        LIBXL_EXTERNAL_CALLERS_ONLY;

int libxl_domain_suspend(libxl_ctx *ctx, uint32_t domid, int fd,
                         int flags, /* LIBXL_SUSPEND_* */
                         const libxl_asyncop_how *ao_how)
                         LIBXL_EXTERNAL_CALLERS_ONLY;
#define LIBXL_SUSPEND_DEBUG 1
#define LIBXL_SUSPEND_LIVE 2

/* @param suspend_cancel [from xenctrl.h:xc_domain_resume( @param fast )]
 *   If this parameter is true, use co-operative resume. The guest
 *   must support this.
 */
int libxl_domain_resume(libxl_ctx *ctx, uint32_t domid, int suspend_cancel,
                        const libxl_asyncop_how *ao_how)
                        LIBXL_EXTERNAL_CALLERS_ONLY;

/*
 * This function doesn't return unless something has gone wrong with
 * the replication to the secondary. If this function returns then the
 * caller should resume the (primary) domain.
 */
int libxl_domain_remus_start(libxl_ctx *ctx, libxl_domain_remus_info *info,
                             uint32_t domid, int send_fd, int recv_fd,
                             const libxl_asyncop_how *ao_how)
                             LIBXL_EXTERNAL_CALLERS_ONLY;

int libxl_domain_shutdown(libxl_ctx *ctx, uint32_t domid);
int libxl_domain_reboot(libxl_ctx *ctx, uint32_t domid);
int libxl_domain_destroy(libxl_ctx *ctx, uint32_t domid,
                         const libxl_asyncop_how *ao_how)
                         LIBXL_EXTERNAL_CALLERS_ONLY;
int libxl_domain_preserve(libxl_ctx *ctx, uint32_t domid, libxl_domain_create_info *info, const char *name_suffix, libxl_uuid new_uuid);

/* get max. number of cpus supported by hypervisor */
int libxl_get_max_cpus(libxl_ctx *ctx);

/* get the actual number of currently online cpus on the host */
int libxl_get_online_cpus(libxl_ctx *ctx);
  /* Beware that no locking or serialization is provided by libxl,
   * so the information can be outdated as far as the function
   * returns. If there are other entities in the system capable
   * of onlining/offlining CPUs, it is up to the application
   * to guarantee consistency, if that is important. */

/* get max. number of NUMA nodes supported by hypervisor */
int libxl_get_max_nodes(libxl_ctx *ctx);

int libxl_domain_rename(libxl_ctx *ctx, uint32_t domid,
                        const char *old_name, const char *new_name);

  /* if old_name is NULL, any old name is OK; otherwise we check
   * transactionally that the domain has the old old name; if
   * trans is not 0 we use caller's transaction and caller must do retries */

int libxl_domain_pause(libxl_ctx *ctx, uint32_t domid);
int libxl_domain_unpause(libxl_ctx *ctx, uint32_t domid);

int libxl_domain_core_dump(libxl_ctx *ctx, uint32_t domid,
                           const char *filename,
                           const libxl_asyncop_how *ao_how)
                           LIBXL_EXTERNAL_CALLERS_ONLY;

int libxl_domain_setmaxmem(libxl_ctx *ctx, uint32_t domid, uint64_t target_memkb);
int libxl_set_memory_target(libxl_ctx *ctx, uint32_t domid, int64_t target_memkb, int relative, int enforce);
int libxl_get_memory_target(libxl_ctx *ctx, uint32_t domid, uint64_t *out_target);
int libxl_get_memory_target_0x040700(libxl_ctx *ctx, uint32_t domid,
                                     uint32_t *out_target)
    LIBXL_EXTERNAL_CALLERS_ONLY;

/*
 * WARNING
 * This memory management API is unstable even in Xen 4.2.
 * It has a numer of deficiencies and we intend to replace it.
 *
 * The semantics of these functions should not be relied on to be very
 * coherent or stable.  We will however endeavour to keep working
 * existing programs which use them in roughly the same way as libxl.
 */
/* how much free memory in the system a domain needs to be built */
int libxl_domain_need_memory(libxl_ctx *ctx,
                             const libxl_domain_build_info *b_info_in,
                             uint64_t *need_memkb);
int libxl_domain_need_memory_0x040700(libxl_ctx *ctx,
                                      const libxl_domain_build_info *b_info_in,
                                      uint32_t *need_memkb)
    LIBXL_EXTERNAL_CALLERS_ONLY;
/* how much free memory is available in the system */
int libxl_get_free_memory(libxl_ctx *ctx, uint64_t *memkb);
int libxl_get_free_memory_0x040700(libxl_ctx *ctx, uint32_t *memkb)
    LIBXL_EXTERNAL_CALLERS_ONLY;
/* wait for a given amount of memory to be free in the system */
int libxl_wait_for_free_memory(libxl_ctx *ctx, uint32_t domid, uint64_t memory_kb, int wait_secs);
/*
 * Wait for the memory target of a domain to be reached. Does not
 * decrement wait_secs if the domain is making progress toward reaching
 * the target. If the domain is not making progress, wait_secs is
 * decremented. If the timeout expires before the target is reached, the
 * function returns ERROR_FAIL.
 *
 * Older versions of this function (Xen 4.5 and older), decremented
 * wait_secs even if the domain was making progress, resulting in far
 * lower overall wait times. To make sure that your calling routine
 * works with new and old implementations of the function, pass enough
 * time for the guest to reach its target as an argument.
 */
int libxl_wait_for_memory_target(libxl_ctx *ctx, uint32_t domid, int wait_secs);

#if defined(LIBXL_API_VERSION) && LIBXL_API_VERSION < 0x040800
#define libxl_get_memory_target libxl_get_memory_target_0x040700
#define libxl_domain_need_memory libxl_domain_need_memory_0x040700
#define libxl_get_free_memory libxl_get_free_memory_0x040700
#endif

int libxl_vncviewer_exec(libxl_ctx *ctx, uint32_t domid, int autopass);

/*
 * If notify_fd is not -1, xenconsole will write 0x00 to it to nofity
 * the caller that it has connected to the guest console.
 */
int libxl_console_exec(libxl_ctx *ctx, uint32_t domid, int cons_num,
                       libxl_console_type type, int notify_fd);
/* libxl_primary_console_exec finds the domid and console number
 * corresponding to the primary console of the given vm, then calls
 * libxl_console_exec with the right arguments (domid might be different
 * if the guest is using stubdoms).
 * This function can be called after creating the device model, in
 * case of HVM guests, and before libxl_run_bootloader in case of PV
 * guests using pygrub.
 * If notify_fd is not -1, xenconsole will write 0x00 to it to nofity
 * the caller that it has connected to the guest console.
 */
int libxl_primary_console_exec(libxl_ctx *ctx, uint32_t domid_vm,
                               int notify_fd);

#if defined(LIBXL_API_VERSION) && LIBXL_API_VERSION < 0x040800

static inline int libxl_console_exec_0x040700(libxl_ctx *ctx,
                                              uint32_t domid, int cons_num,
                                              libxl_console_type type)
{
    return libxl_console_exec(ctx, domid, cons_num, type, -1);
}
#define libxl_console_exec libxl_console_exec_0x040700

static inline int libxl_primary_console_exec_0x040700(libxl_ctx *ctx,
                                                      uint32_t domid_vm)
{
    return libxl_primary_console_exec(ctx, domid_vm, -1);
}
#define libxl_primary_console_exec libxl_primary_console_exec_0x040700

#endif

/* libxl_console_get_tty retrieves the specified domain's console tty path
 * and stores it in path. Caller is responsible for freeing the memory.
 */
int libxl_console_get_tty(libxl_ctx *ctx, uint32_t domid, int cons_num,
                          libxl_console_type type, char **path);

/* libxl_primary_console_get_tty retrieves the specified domain's primary
 * console tty path and stores it in path. Caller is responsible for freeing
 * the memory.
 */
int libxl_primary_console_get_tty(libxl_ctx *ctx, uint32_t domid_vm, char **path);

/* May be called with info_r == NULL to check for domain's existence.
 * Returns ERROR_DOMAIN_NOTFOUND if domain does not exist (used to return
 * ERROR_INVAL for this scenario). */
int libxl_domain_info(libxl_ctx*, libxl_dominfo *info_r,
                      uint32_t domid);

/* These functions each return (on success) an array of elements,
 * and the length via the int* out parameter.  These arrays and
 * their contents come from malloc, and must be freed with the
 * corresponding libxl_THING_list_free function.
 */
libxl_dominfo * libxl_list_domain(libxl_ctx*, int *nb_domain_out);
void libxl_dominfo_list_free(libxl_dominfo *list, int nb_domain);

libxl_cpupoolinfo * libxl_list_cpupool(libxl_ctx*, int *nb_pool_out);
void libxl_cpupoolinfo_list_free(libxl_cpupoolinfo *list, int nb_pool);

libxl_vminfo * libxl_list_vm(libxl_ctx *ctx, int *nb_vm_out);
void libxl_vminfo_list_free(libxl_vminfo *list, int nb_vm);

#define LIBXL_CPUTOPOLOGY_INVALID_ENTRY (~(uint32_t)0)
libxl_cputopology *libxl_get_cpu_topology(libxl_ctx *ctx, int *nb_cpu_out);
void libxl_cputopology_list_free(libxl_cputopology *, int nb_cpu);

#define LIBXL_PCITOPOLOGY_INVALID_ENTRY (~(uint32_t)0)
libxl_pcitopology *libxl_get_pci_topology(libxl_ctx *ctx, int *num_devs);
void libxl_pcitopology_list_free(libxl_pcitopology *, int num_devs);

#define LIBXL_NUMAINFO_INVALID_ENTRY (~(uint32_t)0)
libxl_numainfo *libxl_get_numainfo(libxl_ctx *ctx, int *nr);
void libxl_numainfo_list_free(libxl_numainfo *, int nr);

libxl_vcpuinfo *libxl_list_vcpu(libxl_ctx *ctx, uint32_t domid,
                                int *nb_vcpu, int *nr_cpus_out);
void libxl_vcpuinfo_list_free(libxl_vcpuinfo *, int nr_vcpus);

void libxl_device_vtpm_list_free(libxl_device_vtpm*, int nr_vtpms);
void libxl_vtpminfo_list_free(libxl_vtpminfo *, int nr_vtpms);

/*
 * Devices
 * =======
 *
 * Each device is represented by a libxl_device_<TYPE> data structure
 * which is defined via the IDL. In addition some devices have an
 * additional data type libxl_device_<TYPE>_getinfo which contains
 * further runtime information about the device.
 *
 * In addition to the general methods available for libxl types (see
 * "libxl types" above) a common set of methods are available for each
 * device type. These are described below.
 *
 * Querying
 * --------
 *
 * libxl_device_<type>_list(ctx, domid, nr):
 *
 *   Returns an array of libxl_device_<type> length nr representing
 *   the devices attached to the specified domain.
 *
 * libxl_device_<type>_getinfo(ctx, domid, device, info):
 *
 *   Initialises info with details of the given device which must be
 *   attached to the specified domain.
 *
 * Creation / Control
 * ------------------
 *
 * libxl_device_<type>_add(ctx, domid, device):
 *
 *   Adds the given device to the specified domain. This can be called
 *   while the guest is running (hotplug) or before boot (coldplug).
 *
 *   This function only sets up the device but does not wait for the
 *   domain to connect to the device and therefore cannot block on the
 *   guest.
 *
 *   device is an in/out parameter:  fields left unspecified when the
 *   structure is passed in are filled in with appropriate values for
 *   the device created.
 *
 * libxl_device_<type>_remove(ctx, domid, device):
 *
 *   Removes the given device from the specified domain by performing
 *   an orderly unplug with guest co-operation. This requires that the
 *   guest is running.
 *
 *   This method is currently synchronous and therefore can block
 *   while interacting with the guest.
 *
 * libxl_device_<type>_destroy(ctx, domid, device):
 *
 *   Removes the given device from the specified domain without guest
 *   co-operation. It is guest specific what affect this will have on
 *   a running guest.
 *
 *   This function does not interact with the guest and therefore
 *   cannot block on the guest.
 *
 * Controllers
 * -----------
 *
 * Most devices are treated individually.  Some classes of device,
 * however, like USB or SCSI, inherently have the need to have a
 * hierarchy of different levels, with lower-level devices "attached"
 * to higher-level ones.  USB for instance has "controllers" at the
 * top, which have buses, on which are devices, which consist of
 * multiple interfaces.  SCSI has "hosts" at the top, then buses,
 * targets, and LUNs.
 *
 * In that case, for each <class>, there will be a set of functions
 * and types for each <level>.  For example, for <class>=usb, there
 * may be <levels> ctrl (controller) and dev (device), with ctrl being
 * level 0.
 *
 * libxl_device_<class><level0>_<function> will act more or
 * less like top-level non-bus devices: they will either create or
 * accept a libxl_devid which will be unique within the
 * <class><level0> libxl_devid namespace.
 *
 * Lower-level devices must have a unique way to be identified.  One
 * way to do this would be to name it via the name of the next level
 * up plus an index; for instance, <ctrl devid, port number>.  Another
 * way would be to have another devid namespace for that level.  This
 * identifier will be used for queries and removals.
 *
 * Lower-level devices will include in their
 * libxl_device_<class><level> struct a field referring to the unique
 * index of the level above.  For instance, libxl_device_usbdev might
 * contain the controller devid.
 *
 * In the case where there are multiple different ways to implement a
 * given device -- for instance, one which is fully PV and one which
 * uses an emulator -- the controller will contain a field which
 * specifies what type of implementation is used.  The implementations
 * of individual devices will be known by the controller to which they
 * are attached.
 *
 * If libxl_device_<class><level>_add receives an empty reference to
 * the level above, it may return an error.  Or it may (but is not
 * required to) automatically choose a suitable device in the level
 * above to which to attach the new device at this level.  It may also
 * (but is not required to) automatically create a new device at the
 * level above if no suitable devices exist.  Each class should
 * document its behavior.
 *
 * libxl_device_<class><level>_list will list all devices of <class>
 * at <level> in the domain.  For example, libxl_device_usbctrl_list
 * will list all usb controllers; libxl_class_usbdev_list will list
 * all usb devices across all controllers.
 *
 * For each class, the domain config file will contain a single list
 * for each level.  libxl will first iterate through the list of
 * top-level devices, then iterate through each level down in turn,
 * adding devices to devices in the level above.  For instance, there
 * will be one list for all usb controllers, and one list for all usb
 * devices.
 *
 * If libxl_device_<class><level>_add automatically creates
 * higher-level devices as necessary, then it is permissible for the
 * higher-level lists to be empty and the device list to have devices
 * with the field containing a reference to the higher level device
 * uninitialized.
 */

/* Disks */
int libxl_device_disk_add(libxl_ctx *ctx, uint32_t domid,
                          libxl_device_disk *disk,
                          const libxl_asyncop_how *ao_how)
                          LIBXL_EXTERNAL_CALLERS_ONLY;
int libxl_device_disk_remove(libxl_ctx *ctx, uint32_t domid,
                             libxl_device_disk *disk,
                             const libxl_asyncop_how *ao_how)
                             LIBXL_EXTERNAL_CALLERS_ONLY;
int libxl_device_disk_destroy(libxl_ctx *ctx, uint32_t domid,
                              libxl_device_disk *disk,
                              const libxl_asyncop_how *ao_how)
                              LIBXL_EXTERNAL_CALLERS_ONLY;

libxl_device_disk *libxl_device_disk_list(libxl_ctx *ctx, uint32_t domid, int *num);
int libxl_device_disk_getinfo(libxl_ctx *ctx, uint32_t domid,
                              libxl_device_disk *disk, libxl_diskinfo *diskinfo);

/*
 * Insert a CD-ROM device. A device corresponding to disk must already
 * be attached to the guest.
 */
int libxl_cdrom_insert(libxl_ctx *ctx, uint32_t domid, libxl_device_disk *disk,
                       const libxl_asyncop_how *ao_how)
                       LIBXL_EXTERNAL_CALLERS_ONLY;

/*
 * USB
 *
 * For each device removed or added, one of these protocols is available:
 * - PV (i.e., PVUSB)
 * - DEVICEMODEL (i.e, qemu)
 *
 * PV is available for either PV or HVM domains.  DEVICEMODEL is only
 * available for HVM domains.  The caller can additionally specify
 * "AUTO", in which case the library will try to determine the best
 * protocol automatically.
 *
 * At the moment, the only protocol implemented is PV.
 *
 * One can add/remove USB controllers to/from guest, and attach/detach USB
 * devices to/from USB controllers.
 *
 * To add USB controllers and USB devices, one can adding USB controllers
 * first and then attaching USB devices to some USB controller, or adding
 * USB devices to guest directly, it will automatically create a USB
 * controller for USB devices to attach.
 *
 * To remove USB controllers or USB devices, one can remove USB devices
 * under USB controller one by one and then remove USB controller, or
 * remove USB controller directly, it will remove all USB devices under
 * it automatically.
 *
 */
/* USB Controllers*/
int libxl_device_usbctrl_add(libxl_ctx *ctx, uint32_t domid,
                             libxl_device_usbctrl *usbctrl,
                             const libxl_asyncop_how *ao_how)
                             LIBXL_EXTERNAL_CALLERS_ONLY;

int libxl_device_usbctrl_remove(libxl_ctx *ctx, uint32_t domid,
                                libxl_device_usbctrl *usbctrl,
                                const libxl_asyncop_how *ao_how)
                                LIBXL_EXTERNAL_CALLERS_ONLY;

int libxl_device_usbctrl_destroy(libxl_ctx *ctx, uint32_t domid,
                                 libxl_device_usbctrl *usbctrl,
                                 const libxl_asyncop_how *ao_how)
                                 LIBXL_EXTERNAL_CALLERS_ONLY;

libxl_device_usbctrl *libxl_device_usbctrl_list(libxl_ctx *ctx,
                                                uint32_t domid, int *num);

void libxl_device_usbctrl_list_free(libxl_device_usbctrl *list, int nr);


int libxl_device_usbctrl_getinfo(libxl_ctx *ctx, uint32_t domid,
                                 libxl_device_usbctrl *usbctrl,
                                 libxl_usbctrlinfo *usbctrlinfo);

/* USB Devices */

int libxl_device_usbdev_add(libxl_ctx *ctx, uint32_t domid,
                            libxl_device_usbdev *usbdev,
                            const libxl_asyncop_how *ao_how)
                            LIBXL_EXTERNAL_CALLERS_ONLY;

int libxl_device_usbdev_remove(libxl_ctx *ctx, uint32_t domid,
                               libxl_device_usbdev *usbdev,
                               const libxl_asyncop_how *ao_how)
                               LIBXL_EXTERNAL_CALLERS_ONLY;

libxl_device_usbdev *
libxl_device_usbdev_list(libxl_ctx *ctx, uint32_t domid, int *num);

void libxl_device_usbdev_list_free(libxl_device_usbdev *list, int nr);

/* Network Interfaces */
int libxl_device_nic_add(libxl_ctx *ctx, uint32_t domid, libxl_device_nic *nic,
                         const libxl_asyncop_how *ao_how)
                         LIBXL_EXTERNAL_CALLERS_ONLY;
int libxl_device_nic_remove(libxl_ctx *ctx, uint32_t domid,
                            libxl_device_nic *nic,
                            const libxl_asyncop_how *ao_how)
                            LIBXL_EXTERNAL_CALLERS_ONLY;
int libxl_device_nic_destroy(libxl_ctx *ctx, uint32_t domid,
                             libxl_device_nic *nic,
                             const libxl_asyncop_how *ao_how)
                             LIBXL_EXTERNAL_CALLERS_ONLY;

libxl_device_nic *libxl_device_nic_list(libxl_ctx *ctx, uint32_t domid, int *num);
int libxl_device_nic_getinfo(libxl_ctx *ctx, uint32_t domid,
                              libxl_device_nic *nic, libxl_nicinfo *nicinfo);

/*
 * Virtual Channels
 * Channels manifest as consoles with names, see docs/misc/channels.txt
 */
libxl_device_channel *libxl_device_channel_list(libxl_ctx *ctx,
                                                uint32_t domid,
                                                int *num);
int libxl_device_channel_getinfo(libxl_ctx *ctx, uint32_t domid,
                                 libxl_device_channel *channel,
                                 libxl_channelinfo *channelinfo);

/* Virtual TPMs */
int libxl_device_vtpm_add(libxl_ctx *ctx, uint32_t domid, libxl_device_vtpm *vtpm,
                          const libxl_asyncop_how *ao_how)
                          LIBXL_EXTERNAL_CALLERS_ONLY;
int libxl_device_vtpm_remove(libxl_ctx *ctx, uint32_t domid,
                            libxl_device_vtpm *vtpm,
                            const libxl_asyncop_how *ao_how)
                            LIBXL_EXTERNAL_CALLERS_ONLY;
int libxl_device_vtpm_destroy(libxl_ctx *ctx, uint32_t domid,
                              libxl_device_vtpm *vtpm,
                              const libxl_asyncop_how *ao_how)
                              LIBXL_EXTERNAL_CALLERS_ONLY;

libxl_device_vtpm *libxl_device_vtpm_list(libxl_ctx *ctx, uint32_t domid, int *num);
int libxl_device_vtpm_getinfo(libxl_ctx *ctx, uint32_t domid,
                               libxl_device_vtpm *vtpm, libxl_vtpminfo *vtpminfo);

/* Keyboard */
int libxl_device_vkb_add(libxl_ctx *ctx, uint32_t domid, libxl_device_vkb *vkb,
                         const libxl_asyncop_how *ao_how)
                         LIBXL_EXTERNAL_CALLERS_ONLY;
int libxl_device_vkb_remove(libxl_ctx *ctx, uint32_t domid,
                            libxl_device_vkb *vkb,
                            const libxl_asyncop_how *ao_how)
                            LIBXL_EXTERNAL_CALLERS_ONLY;
int libxl_device_vkb_destroy(libxl_ctx *ctx, uint32_t domid,
                             libxl_device_vkb *vkb,
                             const libxl_asyncop_how *ao_how)
                            LIBXL_EXTERNAL_CALLERS_ONLY;

/* Framebuffer */
int libxl_device_vfb_add(libxl_ctx *ctx, uint32_t domid, libxl_device_vfb *vfb,
                         const libxl_asyncop_how *ao_how)
                         LIBXL_EXTERNAL_CALLERS_ONLY;
int libxl_device_vfb_remove(libxl_ctx *ctx, uint32_t domid,
                            libxl_device_vfb *vfb,
                            const libxl_asyncop_how *ao_how)
                             LIBXL_EXTERNAL_CALLERS_ONLY;
int libxl_device_vfb_destroy(libxl_ctx *ctx, uint32_t domid,
                             libxl_device_vfb *vfb,
                             const libxl_asyncop_how *ao_how)
                             LIBXL_EXTERNAL_CALLERS_ONLY;

/* PCI Passthrough */
int libxl_device_pci_add(libxl_ctx *ctx, uint32_t domid,
                         libxl_device_pci *pcidev,
                         const libxl_asyncop_how *ao_how)
                         LIBXL_EXTERNAL_CALLERS_ONLY;
int libxl_device_pci_remove(libxl_ctx *ctx, uint32_t domid,
                            libxl_device_pci *pcidev,
                            const libxl_asyncop_how *ao_how)
                            LIBXL_EXTERNAL_CALLERS_ONLY;
int libxl_device_pci_destroy(libxl_ctx *ctx, uint32_t domid,
                             libxl_device_pci *pcidev,
                             const libxl_asyncop_how *ao_how)
                             LIBXL_EXTERNAL_CALLERS_ONLY;

libxl_device_pci *libxl_device_pci_list(libxl_ctx *ctx, uint32_t domid,
                                        int *num);

/*
 * Turns the current process into a backend device service daemon
 * for a driver domain.
 *
 * From a libxl API point of view, this starts a long-running
 * operation.  That operation consists of "being a driver domain"
 * and never completes.
 *
 * Attempting to abort this operation is not advisable; proper
 * shutdown of the driver domain task is not supported.
 */
int libxl_device_events_handler(libxl_ctx *ctx,
                                const libxl_asyncop_how *ao_how)
                                LIBXL_EXTERNAL_CALLERS_ONLY;

/*
 * Functions related to making devices assignable -- that is, bound to
 * the pciback driver, ready to be given to a guest via
 * libxl_pci_device_add.
 *
 * - ..._add() will unbind the device from its current driver (if
 * already bound) and re-bind it to pciback; at that point it will be
 * ready to be assigned to a VM.  If rebind is set, it will store the
 * path to the old driver in xenstore so that it can be handed back to
 * dom0 on restore.
 *
 * - ..._remove() will unbind the device from pciback, and if
 * rebind is non-zero, attempt to assign it back to the driver
 * from whence it came.
 *
 * - ..._list() will return a list of the PCI devices available to be
 * assigned.
 *
 * add and remove are idempotent: if the device in question is already
 * added or is not bound, the functions will emit a warning but return
 * SUCCESS.
 */
int libxl_device_pci_assignable_add(libxl_ctx *ctx, libxl_device_pci *pcidev, int rebind);
int libxl_device_pci_assignable_remove(libxl_ctx *ctx, libxl_device_pci *pcidev, int rebind);
libxl_device_pci *libxl_device_pci_assignable_list(libxl_ctx *ctx, int *num);

/* CPUID handling */
int libxl_cpuid_parse_config(libxl_cpuid_policy_list *cpuid, const char* str);
int libxl_cpuid_parse_config_xend(libxl_cpuid_policy_list *cpuid,
                                  const char* str);
void libxl_cpuid_apply_policy(libxl_ctx *ctx, uint32_t domid);
void libxl_cpuid_set(libxl_ctx *ctx, uint32_t domid,
                     libxl_cpuid_policy_list cpuid);

/*
 * Functions for allowing users of libxl to store private data
 * relating to a domain.  The data is an opaque sequence of bytes and
 * is not interpreted or used by libxl.
 *
 * Data is indexed by the userdata userid, which is a short printable
 * ASCII string.  The following list is a registry of userdata userids
 * (the registry may be updated by posting a patch to xen-devel):
 *
 *  userid        Data contents
 *  "xl"          domain config file in xl format, Unix line endings
 *  "libvirt-xml" domain config file in libvirt XML format.  See
 *                http://libvirt.org/formatdomain.html
 *  "domain-userdata-lock"  lock file to protect domain userdata in libxl.
 *                          It's a per-domain lock. Applications should
 *                          not touch this file.
 *  "libxl-json"  libxl_domain_config object in JSON format, generated
 *                by libxl. Applications should not access this file
 *                directly. This file is protected by domain-userdata-lock
 *                for against Read-Modify-Write operation and domain
 *                destruction.
 *
 * libxl does not enforce the registration of userdata userids or the
 * semantics of the data.  For specifications of the data formats
 * see the code or documentation for the libxl caller in question.
 */
int libxl_userdata_store(libxl_ctx *ctx, uint32_t domid,
                              const char *userdata_userid,
                              const uint8_t *data, int datalen)
                              LIBXL_EXTERNAL_CALLERS_ONLY;
  /* If datalen==0, data is not used and the user data for
   * that domain and userdata_userid is deleted. */
int libxl_userdata_retrieve(libxl_ctx *ctx, uint32_t domid,
                                 const char *userdata_userid,
                                 uint8_t **data_r, int *datalen_r)
                                 LIBXL_EXTERNAL_CALLERS_ONLY;
  /* On successful return, *data_r is from malloc.
   * If there is no data for that domain and userdata_userid,
   * *data_r and *datalen_r will be set to 0.
   * data_r and datalen_r may be 0.
   * On error return, *data_r and *datalen_r are undefined.
   */
int libxl_userdata_unlink(libxl_ctx *ctx, uint32_t domid,
                          const char *userdata_userid);


int libxl_get_physinfo(libxl_ctx *ctx, libxl_physinfo *physinfo);
int libxl_set_vcpuaffinity(libxl_ctx *ctx, uint32_t domid, uint32_t vcpuid,
                           const libxl_bitmap *cpumap_hard,
                           const libxl_bitmap *cpumap_soft);
int libxl_set_vcpuaffinity_force(libxl_ctx *ctx, uint32_t domid,
                                 uint32_t vcpuid,
                                 const libxl_bitmap *cpumap_hard,
                                 const libxl_bitmap *cpumap_soft);
int libxl_set_vcpuaffinity_all(libxl_ctx *ctx, uint32_t domid,
                               unsigned int max_vcpus,
                               const libxl_bitmap *cpumap_hard,
                               const libxl_bitmap *cpumap_soft);

#if defined (LIBXL_API_VERSION) && LIBXL_API_VERSION < 0x040500

#define libxl_set_vcpuaffinity(ctx, domid, vcpuid, map) \
    libxl_set_vcpuaffinity((ctx), (domid), (vcpuid), (map), NULL)
#define libxl_set_vcpuaffinity_all(ctx, domid, max_vcpus, map) \
    libxl_set_vcpuaffinity_all((ctx), (domid), (max_vcpus), (map), NULL)

#endif

int libxl_domain_set_nodeaffinity(libxl_ctx *ctx, uint32_t domid,
                                  libxl_bitmap *nodemap);
int libxl_domain_get_nodeaffinity(libxl_ctx *ctx, uint32_t domid,
                                  libxl_bitmap *nodemap);
int libxl_set_vcpuonline(libxl_ctx *ctx, uint32_t domid, libxl_bitmap *cpumap);

/* A return value less than 0 should be interpreted as a libxl_error, while a
 * return value greater than or equal to 0 should be interpreted as a
 * libxl_scheduler. */
int libxl_get_scheduler(libxl_ctx *ctx);

/* Per-scheduler parameters */
int libxl_sched_credit_params_get(libxl_ctx *ctx, uint32_t poolid,
                                  libxl_sched_credit_params *scinfo);
int libxl_sched_credit_params_set(libxl_ctx *ctx, uint32_t poolid,
                                  libxl_sched_credit_params *scinfo);
int libxl_sched_credit2_params_get(libxl_ctx *ctx, uint32_t poolid,
                                   libxl_sched_credit2_params *scinfo);
int libxl_sched_credit2_params_set(libxl_ctx *ctx, uint32_t poolid,
                                   libxl_sched_credit2_params *scinfo);

/* Scheduler Per-domain parameters */

#define LIBXL_DOMAIN_SCHED_PARAM_WEIGHT_DEFAULT    -1
#define LIBXL_DOMAIN_SCHED_PARAM_CAP_DEFAULT       -1
#define LIBXL_DOMAIN_SCHED_PARAM_PERIOD_DEFAULT    -1
#define LIBXL_DOMAIN_SCHED_PARAM_SLICE_DEFAULT     -1
#define LIBXL_DOMAIN_SCHED_PARAM_LATENCY_DEFAULT   -1
#define LIBXL_DOMAIN_SCHED_PARAM_EXTRATIME_DEFAULT -1
#define LIBXL_DOMAIN_SCHED_PARAM_BUDGET_DEFAULT    -1

/* Per-VCPU parameters */
#define LIBXL_SCHED_PARAM_VCPU_INDEX_DEFAULT   -1

/* Get the per-domain scheduling parameters.
 * For schedulers that support per-vcpu settings (e.g., RTDS),
 * calling *_domain_get functions will get default scheduling
 * parameters.
 */
int libxl_domain_sched_params_get(libxl_ctx *ctx, uint32_t domid,
                                  libxl_domain_sched_params *params);

/* Set the per-domain scheduling parameters.
 * For schedulers that support per-vcpu settings (e.g., RTDS),
 * calling *_domain_set functions will set all vcpus with the same
 * scheduling parameters.
 */
int libxl_domain_sched_params_set(libxl_ctx *ctx, uint32_t domid,
                                  const libxl_domain_sched_params *params);

/* Get the per-vcpu scheduling parameters */
int libxl_vcpu_sched_params_get(libxl_ctx *ctx, uint32_t domid,
                                libxl_vcpu_sched_params *params);

/* Get the per-vcpu scheduling parameters of all vcpus of a domain */
int libxl_vcpu_sched_params_get_all(libxl_ctx *ctx, uint32_t domid,
                                    libxl_vcpu_sched_params *params);

/* Set the per-vcpu scheduling parameters */
int libxl_vcpu_sched_params_set(libxl_ctx *ctx, uint32_t domid,
                                const libxl_vcpu_sched_params *params);

/* Set the per-vcpu scheduling parameters of all vcpus of a domain */
int libxl_vcpu_sched_params_set_all(libxl_ctx *ctx, uint32_t domid,
                                    const libxl_vcpu_sched_params *params);

int libxl_send_trigger(libxl_ctx *ctx, uint32_t domid,
                       libxl_trigger trigger, uint32_t vcpuid);
int libxl_send_sysrq(libxl_ctx *ctx, uint32_t domid, char sysrq);
int libxl_send_debug_keys(libxl_ctx *ctx, char *keys);

typedef struct libxl__xen_console_reader libxl_xen_console_reader;

libxl_xen_console_reader *
    libxl_xen_console_read_start(libxl_ctx *ctx, int clear);
int libxl_xen_console_read_line(libxl_ctx *ctx,
                                libxl_xen_console_reader *cr,
                                char **line_r);
void libxl_xen_console_read_finish(libxl_ctx *ctx,
                                   libxl_xen_console_reader *cr);

uint32_t libxl_vm_get_start_time(libxl_ctx *ctx, uint32_t domid);

char *libxl_tmem_list(libxl_ctx *ctx, uint32_t domid, int use_long);
int libxl_tmem_freeze(libxl_ctx *ctx, uint32_t domid);
int libxl_tmem_thaw(libxl_ctx *ctx, uint32_t domid);
int libxl_tmem_set(libxl_ctx *ctx, uint32_t domid, char* name,
                   uint32_t set);
int libxl_tmem_shared_auth(libxl_ctx *ctx, uint32_t domid, char* uuid,
                           int auth);
int libxl_tmem_freeable(libxl_ctx *ctx);

int libxl_get_freecpus(libxl_ctx *ctx, libxl_bitmap *cpumap);
int libxl_cpupool_create(libxl_ctx *ctx, const char *name,
                         libxl_scheduler sched,
                         libxl_bitmap cpumap, libxl_uuid *uuid,
                         uint32_t *poolid);
int libxl_cpupool_destroy(libxl_ctx *ctx, uint32_t poolid);
int libxl_cpupool_rename(libxl_ctx *ctx, const char *name, uint32_t poolid);
int libxl_cpupool_cpuadd(libxl_ctx *ctx, uint32_t poolid, int cpu);
int libxl_cpupool_cpuadd_node(libxl_ctx *ctx, uint32_t poolid, int node, int *cpus);
int libxl_cpupool_cpuadd_cpumap(libxl_ctx *ctx, uint32_t poolid,
                                const libxl_bitmap *cpumap);
int libxl_cpupool_cpuremove(libxl_ctx *ctx, uint32_t poolid, int cpu);
int libxl_cpupool_cpuremove_node(libxl_ctx *ctx, uint32_t poolid, int node, int *cpus);
int libxl_cpupool_cpuremove_cpumap(libxl_ctx *ctx, uint32_t poolid,
                                   const libxl_bitmap *cpumap);
int libxl_cpupool_movedomain(libxl_ctx *ctx, uint32_t poolid, uint32_t domid);
int libxl_cpupool_info(libxl_ctx *ctx, libxl_cpupoolinfo *info, uint32_t poolid);

int libxl_domid_valid_guest(uint32_t domid);

int libxl_flask_context_to_sid(libxl_ctx *ctx, char *buf, size_t len,
                               uint32_t *ssidref);
int libxl_flask_sid_to_context(libxl_ctx *ctx, uint32_t ssidref, char **buf,
                               size_t *len);
int libxl_flask_getenforce(libxl_ctx *ctx);
int libxl_flask_setenforce(libxl_ctx *ctx, int mode);
int libxl_flask_loadpolicy(libxl_ctx *ctx, void *policy, uint32_t size);

int libxl_ms_vm_genid_generate(libxl_ctx *ctx, libxl_ms_vm_genid *id);
bool libxl_ms_vm_genid_is_zero(const libxl_ms_vm_genid *id);
void libxl_ms_vm_genid_copy(libxl_ctx *ctx, libxl_ms_vm_genid *dst,
                            const libxl_ms_vm_genid *src);

#ifdef LIBXL_HAVE_PSR_CMT
int libxl_psr_cmt_attach(libxl_ctx *ctx, uint32_t domid);
int libxl_psr_cmt_detach(libxl_ctx *ctx, uint32_t domid);
int libxl_psr_cmt_domain_attached(libxl_ctx *ctx, uint32_t domid);
int libxl_psr_cmt_enabled(libxl_ctx *ctx);
int libxl_psr_cmt_get_total_rmid(libxl_ctx *ctx, uint32_t *total_rmid);
int libxl_psr_cmt_get_l3_cache_size(libxl_ctx *ctx,
                                    uint32_t socketid,
                                    uint32_t *l3_cache_size);
int libxl_psr_cmt_get_cache_occupancy(libxl_ctx *ctx,
                                      uint32_t domid,
                                      uint32_t socketid,
                                      uint32_t *l3_cache_occupancy);
#endif

#ifdef LIBXL_HAVE_PSR_MBM
int libxl_psr_cmt_type_supported(libxl_ctx *ctx, libxl_psr_cmt_type type);
int libxl_psr_cmt_get_sample(libxl_ctx *ctx,
                             uint32_t domid,
                             libxl_psr_cmt_type type,
                             uint64_t scope,
                             uint64_t *sample_r,
                             uint64_t *tsc_r);
#endif

#ifdef LIBXL_HAVE_PSR_CAT
/*
 * Function to set a domain's cbm. It operates on a single or multiple
 * target(s) defined in 'target_map'. The definition of 'target_map' is
 * related to 'type':
 * 'L3_CBM': 'target_map' specifies all the sockets to be operated on.
 */
int libxl_psr_cat_set_cbm(libxl_ctx *ctx, uint32_t domid,
                          libxl_psr_cbm_type type, libxl_bitmap *target_map,
                          uint64_t cbm);
/*
 * Function to get a domain's cbm. It operates on a single 'target'.
 * The definition of 'target' is related to 'type':
 * 'L3_CBM': 'target' specifies which socket to be operated on.
 */
int libxl_psr_cat_get_cbm(libxl_ctx *ctx, uint32_t domid,
                          libxl_psr_cbm_type type, uint32_t target,
                          uint64_t *cbm_r);

/*
 * On success, the function returns an array of elements in 'info',
 * and the length in 'nr'.
 */
int libxl_psr_cat_get_l3_info(libxl_ctx *ctx, libxl_psr_cat_info **info,
                              int *nr);
void libxl_psr_cat_info_list_free(libxl_psr_cat_info *list, int nr);
#endif

/* misc */

/* Each of these sets or clears the flag according to whether the
 * 2nd parameter is nonzero.  On failure, they log, and
 * return ERROR_FAIL, but also leave errno valid. */
int libxl_fd_set_cloexec(libxl_ctx *ctx, int fd, int cloexec);
int libxl_fd_set_nonblock(libxl_ctx *ctx, int fd, int nonblock);

/*
 * Issue a qmp monitor command to the device model of the specified domain.
 * The function returns the output of the command in a new allocated buffer
 * via output.
 */
int libxl_qemu_monitor_command(libxl_ctx *ctx, uint32_t domid,
                               const char *command_line, char **output);

#include <libxl_event.h>

#endif /* LIBXL_H */

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
