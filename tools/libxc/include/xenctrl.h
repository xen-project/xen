/******************************************************************************
 * xenctrl.h
 *
 * A library for low-level access to the Xen control interfaces.
 *
 * Copyright (c) 2003-2004, K A Fraser.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef XENCTRL_H
#define XENCTRL_H

/* Tell the Xen public headers we are a user-space tools build. */
#ifndef __XEN_TOOLS__
#define __XEN_TOOLS__ 1
#endif

#include <unistd.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <xen/xen.h>
#include <xen/domctl.h>
#include <xen/physdev.h>
#include <xen/sysctl.h>
#include <xen/version.h>
#include <xen/event_channel.h>
#include <xen/sched.h>
#include <xen/memory.h>
#include <xen/grant_table.h>
#include <xen/hvm/dm_op.h>
#include <xen/hvm/params.h>
#include <xen/xsm/flask_op.h>
#include <xen/tmem.h>
#include <xen/kexec.h>
#include <xen/platform.h>

#include "xentoollog.h"

#if defined(__i386__) || defined(__x86_64__)
#include <xen/foreign/x86_32.h>
#include <xen/foreign/x86_64.h>
#include <xen/arch-x86/xen-mca.h>
#endif

#define XC_PAGE_SHIFT           12
#define XC_PAGE_SIZE            (1UL << XC_PAGE_SHIFT)
#define XC_PAGE_MASK            (~(XC_PAGE_SIZE-1))

#define INVALID_MFN  (~0UL)

/*
 *  DEFINITIONS FOR CPU BARRIERS
 */

#define xen_barrier() asm volatile ( "" : : : "memory")

#if defined(__i386__)
#define xen_mb()  asm volatile ( "lock; addl $0,0(%%esp)" : : : "memory" )
#define xen_rmb() xen_barrier()
#define xen_wmb() xen_barrier()
#elif defined(__x86_64__)
#define xen_mb()  asm volatile ( "mfence" : : : "memory")
#define xen_rmb() xen_barrier()
#define xen_wmb() xen_barrier()
#elif defined(__arm__)
#define xen_mb()   asm volatile ("dmb" : : : "memory")
#define xen_rmb()  asm volatile ("dmb" : : : "memory")
#define xen_wmb()  asm volatile ("dmb" : : : "memory")
#elif defined(__aarch64__)
#define xen_mb()   asm volatile ("dmb sy" : : : "memory")
#define xen_rmb()  asm volatile ("dmb sy" : : : "memory")
#define xen_wmb()  asm volatile ("dmb sy" : : : "memory")
#else
#error "Define barriers"
#endif


#define XENCTRL_HAS_XC_INTERFACE 1
/* In Xen 4.0 and earlier, xc_interface_open and xc_evtchn_open would
 * both return ints being the file descriptor.  In 4.1 and later, they
 * return an xc_interface* and xc_evtchn*, respectively - ie, a
 * pointer to an opaque struct.  This #define is provided in 4.1 and
 * later, allowing out-of-tree callers to more easily distinguish
 * between, and be compatible with, both versions.
 */


/*
 *  GENERAL
 *
 * Unless otherwise specified, each function here returns zero or a
 * non-null pointer on success; or in case of failure, sets errno and
 * returns -1 or a null pointer.
 *
 * Unless otherwise specified, errors result in a call to the error
 * handler function, which by default prints a message to the
 * FILE* passed as the caller_data, which by default is stderr.
 * (This is described below as "logging errors".)
 *
 * The error handler can safely trash errno, as libxc saves it across
 * the callback.
 */

typedef struct xc_interface_core xc_interface;

enum xc_error_code {
  XC_ERROR_NONE = 0,
  XC_INTERNAL_ERROR = 1,
  XC_INVALID_KERNEL = 2,
  XC_INVALID_PARAM = 3,
  XC_OUT_OF_MEMORY = 4,
  /* new codes need to be added to xc_error_level_to_desc too */
};

typedef enum xc_error_code xc_error_code;


/*
 *  INITIALIZATION FUNCTIONS
 */

/**
 * This function opens a handle to the hypervisor interface.  This function can
 * be called multiple times within a single process.  Multiple processes can
 * have an open hypervisor interface at the same time.
 *
 * Note:
 * After fork a child process must not use any opened xc interface
 * handle inherited from their parent. They must open a new handle if
 * they want to interact with xc.
 *
 * Each call to this function should have a corresponding call to
 * xc_interface_close().
 *
 * This function can fail if the caller does not have superuser permission or
 * if a Xen-enabled kernel is not currently running.
 *
 * @return a handle to the hypervisor interface
 */
xc_interface *xc_interface_open(xentoollog_logger *logger,
                                xentoollog_logger *dombuild_logger,
                                unsigned open_flags);
  /* if logger==NULL, will log to stderr
   * if dombuild_logger=NULL, will log to a file
   */

/*
 * Note: if XC_OPENFLAG_NON_REENTRANT is passed then libxc must not be
 * called reentrantly and the calling application is responsible for
 * providing mutual exclusion surrounding all libxc calls itself.
 *
 * In particular xc_{get,clear}_last_error only remain valid for the
 * duration of the critical section containing the call which failed.
 */
enum xc_open_flags {
    XC_OPENFLAG_DUMMY =  1<<0, /* do not actually open a xenctrl interface */
    XC_OPENFLAG_NON_REENTRANT = 1<<1, /* assume library is only every called from a single thread */
};

/**
 * This function closes an open hypervisor interface.
 *
 * This function can fail if the handle does not represent an open interface or
 * if there were problems closing the interface.  In the latter case
 * the interface is still closed.
 *
 * @parm xch a handle to an open hypervisor interface
 * @return 0 on success, -1 otherwise.
 */
int xc_interface_close(xc_interface *xch);

/*
 * HYPERCALL SAFE MEMORY BUFFER
 *
 * Ensure that memory which is passed to a hypercall has been
 * specially allocated in order to be safe to access from the
 * hypervisor.
 *
 * Each user data pointer is shadowed by an xc_hypercall_buffer data
 * structure. You should never define an xc_hypercall_buffer type
 * directly, instead use the DECLARE_HYPERCALL_BUFFER* macros below.
 *
 * The strucuture should be considered opaque and all access should be
 * via the macros and helper functions defined below.
 *
 * Once the buffer is declared the user is responsible for explicitly
 * allocating and releasing the memory using
 * xc_hypercall_buffer_alloc(_pages) and
 * xc_hypercall_buffer_free(_pages).
 *
 * Once the buffer has been allocated the user can initialise the data
 * via the normal pointer. The xc_hypercall_buffer structure is
 * transparently referenced by the helper macros (such as
 * xen_set_guest_handle) in order to check at compile time that the
 * correct type of memory is being used.
 */
struct xc_hypercall_buffer {
    /* Hypercall safe memory buffer. */
    void *hbuf;

    /*
     * Reference to xc_hypercall_buffer passed as argument to the
     * current function.
     */
    struct xc_hypercall_buffer *param_shadow;

    /*
     * Direction of copy for bounce buffering.
     */
    int dir;

    /* Used iff dir != 0. */
    void *ubuf;
    size_t sz;
};
typedef struct xc_hypercall_buffer xc_hypercall_buffer_t;

/*
 * Construct the name of the hypercall buffer for a given variable.
 * For internal use only
 */
#define XC__HYPERCALL_BUFFER_NAME(_name) xc__hypercall_buffer_##_name

/*
 * Returns the hypercall_buffer associated with a variable.
 */
#define HYPERCALL_BUFFER(_name)                                 \
    ({  xc_hypercall_buffer_t _hcbuf_buf1;                      \
        typeof(XC__HYPERCALL_BUFFER_NAME(_name)) *_hcbuf_buf2 = \
                &XC__HYPERCALL_BUFFER_NAME(_name);              \
        (void)(&_hcbuf_buf1 == _hcbuf_buf2);                    \
        (_hcbuf_buf2)->param_shadow ?                           \
                (_hcbuf_buf2)->param_shadow : (_hcbuf_buf2);    \
     })

#define HYPERCALL_BUFFER_INIT_NO_BOUNCE .dir = 0, .sz = 0, .ubuf = (void *)-1

/*
 * Defines a hypercall buffer and user pointer with _name of _type.
 *
 * The user accesses the data as normal via _name which will be
 * transparently converted to the hypercall buffer as necessary.
 */
#define DECLARE_HYPERCALL_BUFFER(_type, _name)                 \
    _type *(_name) = NULL;                                     \
    xc_hypercall_buffer_t XC__HYPERCALL_BUFFER_NAME(_name) = { \
        .hbuf = NULL,                                          \
        .param_shadow = NULL,                                  \
        HYPERCALL_BUFFER_INIT_NO_BOUNCE                        \
    }

/*
 * Like DECLARE_HYPERCALL_BUFFER() but using an already allocated
 * hypercall buffer, _hbuf.
 *
 * Useful when a hypercall buffer is passed to a function and access
 * via the user pointer is required.
 *
 * See DECLARE_HYPERCALL_BUFFER_ARGUMENT() if the user pointer is not
 * required.
 */
#define DECLARE_HYPERCALL_BUFFER_SHADOW(_type, _name, _hbuf)   \
    _type *(_name) = (_hbuf)->hbuf;                            \
    __attribute__((unused))                                    \
    xc_hypercall_buffer_t XC__HYPERCALL_BUFFER_NAME(_name) = { \
        .hbuf = (void *)-1,                                    \
        .param_shadow = (_hbuf),                               \
        HYPERCALL_BUFFER_INIT_NO_BOUNCE                        \
    }

/*
 * Declare the necessary data structure to allow a hypercall buffer
 * passed as an argument to a function to be used in the normal way.
 */
#define DECLARE_HYPERCALL_BUFFER_ARGUMENT(_name)               \
    xc_hypercall_buffer_t XC__HYPERCALL_BUFFER_NAME(_name) = { \
        .hbuf = (void *)-1,                                    \
        .param_shadow = (_name),                               \
        HYPERCALL_BUFFER_INIT_NO_BOUNCE                        \
    }

/*
 * Get the hypercall buffer data pointer in a form suitable for use
 * directly as a hypercall argument.
 */
#define HYPERCALL_BUFFER_AS_ARG(_name)                          \
    ({  xc_hypercall_buffer_t _hcbuf_arg1;                      \
        typeof(XC__HYPERCALL_BUFFER_NAME(_name)) *_hcbuf_arg2 = \
                HYPERCALL_BUFFER(_name);                        \
        (void)(&_hcbuf_arg1 == _hcbuf_arg2);                    \
        (unsigned long)(_hcbuf_arg2)->hbuf;                     \
     })

/*
 * Set a xen_guest_handle in a type safe manner, ensuring that the
 * data pointer has been correctly allocated.
 */
#define set_xen_guest_handle_impl(_hnd, _val, _byte_off)        \
    do {                                                        \
        xc_hypercall_buffer_t _hcbuf_hnd1;                      \
        typeof(XC__HYPERCALL_BUFFER_NAME(_val)) *_hcbuf_hnd2 =  \
                HYPERCALL_BUFFER(_val);                         \
        (void) (&_hcbuf_hnd1 == _hcbuf_hnd2);                   \
        set_xen_guest_handle_raw(_hnd,                          \
                (_hcbuf_hnd2)->hbuf + (_byte_off));             \
    } while (0)

#undef set_xen_guest_handle
#define set_xen_guest_handle(_hnd, _val)                        \
    set_xen_guest_handle_impl(_hnd, _val, 0)

#define set_xen_guest_handle_offset(_hnd, _val, _off)           \
    set_xen_guest_handle_impl(_hnd, _val,                       \
            ((sizeof(*_val)*(_off))))

/* Use with set_xen_guest_handle in place of NULL */
extern xc_hypercall_buffer_t XC__HYPERCALL_BUFFER_NAME(HYPERCALL_BUFFER_NULL);

/*
 * Allocate and free hypercall buffers with byte granularity.
 */
void *xc__hypercall_buffer_alloc(xc_interface *xch, xc_hypercall_buffer_t *b, size_t size);
#define xc_hypercall_buffer_alloc(_xch, _name, _size) xc__hypercall_buffer_alloc(_xch, HYPERCALL_BUFFER(_name), _size)
void xc__hypercall_buffer_free(xc_interface *xch, xc_hypercall_buffer_t *b);
#define xc_hypercall_buffer_free(_xch, _name) xc__hypercall_buffer_free(_xch, HYPERCALL_BUFFER(_name))

/*
 * Allocate and free hypercall buffers with page alignment.
 */
void *xc__hypercall_buffer_alloc_pages(xc_interface *xch, xc_hypercall_buffer_t *b, int nr_pages);
#define xc_hypercall_buffer_alloc_pages(_xch, _name, _nr) xc__hypercall_buffer_alloc_pages(_xch, HYPERCALL_BUFFER(_name), _nr)
void xc__hypercall_buffer_free_pages(xc_interface *xch, xc_hypercall_buffer_t *b, int nr_pages);
#define xc_hypercall_buffer_free_pages(_xch, _name, _nr)                    \
    do {                                                                    \
        if ( _name )                                                        \
            xc__hypercall_buffer_free_pages(_xch, HYPERCALL_BUFFER(_name),  \
                                            _nr);                           \
    } while (0)

/*
 * Array of hypercall buffers.
 *
 * Create an array with xc_hypercall_buffer_array_create() and
 * populate it by declaring one hypercall buffer in a loop and
 * allocating the buffer with xc_hypercall_buffer_array_alloc().
 *
 * To access a previously allocated buffers, declare a new hypercall
 * buffer and call xc_hypercall_buffer_array_get().
 *
 * Destroy the array with xc_hypercall_buffer_array_destroy() to free
 * the array and all its allocated hypercall buffers.
 */
struct xc_hypercall_buffer_array;
typedef struct xc_hypercall_buffer_array xc_hypercall_buffer_array_t;

xc_hypercall_buffer_array_t *xc_hypercall_buffer_array_create(xc_interface *xch, unsigned n);
void *xc__hypercall_buffer_array_alloc(xc_interface *xch, xc_hypercall_buffer_array_t *array,
                                       unsigned index, xc_hypercall_buffer_t *hbuf, size_t size);
#define xc_hypercall_buffer_array_alloc(_xch, _array, _index, _name, _size) \
    xc__hypercall_buffer_array_alloc(_xch, _array, _index, HYPERCALL_BUFFER(_name), _size)
void *xc__hypercall_buffer_array_get(xc_interface *xch, xc_hypercall_buffer_array_t *array,
                                     unsigned index, xc_hypercall_buffer_t *hbuf);
#define xc_hypercall_buffer_array_get(_xch, _array, _index, _name, _size) \
    xc__hypercall_buffer_array_get(_xch, _array, _index, HYPERCALL_BUFFER(_name))
void xc_hypercall_buffer_array_destroy(xc_interface *xc, xc_hypercall_buffer_array_t *array);

/*
 * CPUMAP handling
 */
typedef uint8_t *xc_cpumap_t;

/* return maximum number of cpus the hypervisor supports */
int xc_get_max_cpus(xc_interface *xch);

/* return the number of online cpus */
int xc_get_online_cpus(xc_interface *xch);

/* return array size for cpumap */
int xc_get_cpumap_size(xc_interface *xch);

/* allocate a cpumap */
xc_cpumap_t xc_cpumap_alloc(xc_interface *xch);

/* clear an CPU from the cpumap. */
void xc_cpumap_clearcpu(int cpu, xc_cpumap_t map);

/* set an CPU in the cpumap. */
void xc_cpumap_setcpu(int cpu, xc_cpumap_t map);

/* Test whether the CPU in cpumap is set. */
int xc_cpumap_testcpu(int cpu, xc_cpumap_t map);

/*
 * NODEMAP handling
 */
typedef uint8_t *xc_nodemap_t;

/* return maximum number of NUMA nodes the hypervisor supports */
int xc_get_max_nodes(xc_interface *xch);

/* return array size for nodemap */
int xc_get_nodemap_size(xc_interface *xch);

/* allocate a nodemap */
xc_nodemap_t xc_nodemap_alloc(xc_interface *xch);

/*
 * DOMAIN DEBUGGING FUNCTIONS
 */

typedef struct xc_core_header {
    unsigned int xch_magic;
    unsigned int xch_nr_vcpus;
    unsigned int xch_nr_pages;
    unsigned int xch_ctxt_offset;
    unsigned int xch_index_offset;
    unsigned int xch_pages_offset;
} xc_core_header_t;

#define XC_CORE_MAGIC     0xF00FEBED
#define XC_CORE_MAGIC_HVM 0xF00FEBEE

/*
 * DOMAIN MANAGEMENT FUNCTIONS
 */

typedef struct xc_dominfo {
    uint32_t      domid;
    uint32_t      ssidref;
    unsigned int  dying:1, crashed:1, shutdown:1,
                  paused:1, blocked:1, running:1,
                  hvm:1, debugged:1, xenstore:1, hap:1;
    unsigned int  shutdown_reason; /* only meaningful if shutdown==1 */
    unsigned long nr_pages; /* current number, not maximum */
    unsigned long nr_outstanding_pages;
    unsigned long nr_shared_pages;
    unsigned long nr_paged_pages;
    unsigned long shared_info_frame;
    uint64_t      cpu_time;
    unsigned long max_memkb;
    unsigned int  nr_online_vcpus;
    unsigned int  max_vcpu_id;
    xen_domain_handle_t handle;
    unsigned int  cpupool;
    struct xen_arch_domainconfig arch_config;
} xc_dominfo_t;

typedef xen_domctl_getdomaininfo_t xc_domaininfo_t;

typedef union 
{
#if defined(__i386__) || defined(__x86_64__)
    vcpu_guest_context_x86_64_t x64;
    vcpu_guest_context_x86_32_t x32;   
#endif
    vcpu_guest_context_t c;
} vcpu_guest_context_any_t;

typedef union
{
#if defined(__i386__) || defined(__x86_64__)
    shared_info_x86_64_t x64;
    shared_info_x86_32_t x32;
#endif
    shared_info_t s;
} shared_info_any_t;

#if defined(__i386__) || defined(__x86_64__)
typedef union
{
    start_info_x86_64_t x64;
    start_info_x86_32_t x32;
    start_info_t s;
} start_info_any_t;
#endif

typedef struct xc_vcpu_extstate {
    uint64_t xfeature_mask;
    uint64_t size;
    void *buffer;
} xc_vcpu_extstate_t;

typedef struct xen_arch_domainconfig xc_domain_configuration_t;
int xc_domain_create(xc_interface *xch, uint32_t ssidref,
                     xen_domain_handle_t handle, uint32_t flags,
                     uint32_t *pdomid, xc_domain_configuration_t *config);


/* Functions to produce a dump of a given domain
 *  xc_domain_dumpcore - produces a dump to a specified file
 *  xc_domain_dumpcore_via_callback - produces a dump, using a specified
 *                                    callback function
 */
int xc_domain_dumpcore(xc_interface *xch,
                       uint32_t domid,
                       const char *corename);

/* Define the callback function type for xc_domain_dumpcore_via_callback.
 *
 * This function is called by the coredump code for every "write",
 * and passes an opaque object for the use of the function and
 * created by the caller of xc_domain_dumpcore_via_callback.
 */
typedef int (dumpcore_rtn_t)(xc_interface *xch,
                             void *arg, char *buffer, unsigned int length);

int xc_domain_dumpcore_via_callback(xc_interface *xch,
                                    uint32_t domid,
                                    void *arg,
                                    dumpcore_rtn_t dump_rtn);

/*
 * This function sets the maximum number of vcpus that a domain may create.
 *
 * @parm xch a handle to an open hypervisor interface.
 * @parm domid the domain id in which vcpus are to be created.
 * @parm max the maximum number of vcpus that the domain may create.
 * @return 0 on success, -1 on failure.
 */
int xc_domain_max_vcpus(xc_interface *xch,
                        uint32_t domid,
                        unsigned int max);

/**
 * This function pauses a domain. A paused domain still exists in memory
 * however it does not receive any timeslices from the hypervisor.
 *
 * @parm xch a handle to an open hypervisor interface
 * @parm domid the domain id to pause
 * @return 0 on success, -1 on failure.
 */
int xc_domain_pause(xc_interface *xch,
                    uint32_t domid);
/**
 * This function unpauses a domain.  The domain should have been previously
 * paused.
 *
 * @parm xch a handle to an open hypervisor interface
 * @parm domid the domain id to unpause
 * return 0 on success, -1 on failure
 */
int xc_domain_unpause(xc_interface *xch,
                      uint32_t domid);

/**
 * This function will destroy a domain.  Destroying a domain removes the domain
 * completely from memory.  This function should be called after sending the
 * domain a SHUTDOWN control message to free up the domain resources.
 *
 * @parm xch a handle to an open hypervisor interface
 * @parm domid the domain id to destroy
 * @return 0 on success, -1 on failure
 */
int xc_domain_destroy(xc_interface *xch,
                      uint32_t domid);


/**
 * This function resumes a suspended domain. The domain should have
 * been previously suspended.
 *
 * Note that there are 'xc_domain_suspend' as suspending a domain
 * is quite the endeavour.
 *
 * For the purpose of this explanation there are three guests:
 * PV (using hypercalls for privilgied operations), HVM
 * (fully hardware virtualized guests using emulated devices for everything),
 * and PVHVM (PV aware with hardware virtualisation).
 *
 * HVM guest are the simplest - they suspend via S3 / S4 and resume from
 * S3 / S4. Upon resume they have to re-negotiate with the emulated devices.
 *
 * PV and PVHVM communicate via hypercalls for suspend (and resume).
 * For suspend the toolstack initiates the process by writing an value
 * in XenBus "control/shutdown" with the string "suspend".
 *
 * The PV guest stashes anything it deems neccessary in 'struct
 * start_info' in case of failure (PVHVM may ignore this) and calls
 * the SCHEDOP_shutdown::SHUTDOWN_suspend hypercall (for PV as
 * argument it passes the MFN to 'struct start_info').
 *
 * And then the guest is suspended.
 *
 * The checkpointing or notifying a guest that the suspend failed or
 * cancelled (in case of checkpoint) is by having the
 * SCHEDOP_shutdown::SHUTDOWN_suspend hypercall return a non-zero
 * value.
 *
 * The PV and PVHVM resume path are similar. For PV it would be
 * similar to bootup - figure out where the 'struct start_info' is (or
 * if the suspend was cancelled aka checkpointed - reuse the saved
 * values).
 *
 * From here on they differ depending whether the guest is PV or PVHVM
 * in specifics but follow overall the same path:
 *  - PV: Bringing up the vCPUS,
 *  - PVHVM: Setup vector callback,
 *  - Bring up vCPU runstates,
 *  - Remap the grant tables if checkpointing or setup from scratch,
 *
 *
 * If the resume was not checkpointing (or if suspend was succesful) we would
 * setup the PV timers and the different PV events. Lastly the PV drivers
 * re-negotiate with the backend.
 *
 * This function would return before the guest started resuming. That is
 * the guest would be in non-running state and its vCPU context would be
 * in the the SCHEDOP_shutdown::SHUTDOWN_suspend hypercall return path
 * (for PV and PVHVM). For HVM it would be in would be in QEMU emulated
 * BIOS handling S3 suspend.
 *
 * @parm xch a handle to an open hypervisor interface
 * @parm domid the domain id to resume
 * @parm fast use cooperative resume (guest must support this)
 * return 0 on success, -1 on failure
 */
int xc_domain_resume(xc_interface *xch,
		     uint32_t domid,
		     int fast);

/**
 * This function will shutdown a domain. This is intended for use in
 * fully-virtualized domains where this operation is analogous to the
 * sched_op operations in a paravirtualized domain. The caller is
 * expected to give the reason for the shutdown.
 *
 * @parm xch a handle to an open hypervisor interface
 * @parm domid the domain id to destroy
 * @parm reason is the reason (SHUTDOWN_xxx) for the shutdown
 * @return 0 on success, -1 on failure
 */
int xc_domain_shutdown(xc_interface *xch,
                       uint32_t domid,
                       int reason);

int xc_watchdog(xc_interface *xch,
		uint32_t id,
		uint32_t timeout);

/**
 * This function explicitly sets the host NUMA nodes the domain will
 * have affinity with.
 *
 * @parm xch a handle to an open hypervisor interface.
 * @parm domid the domain id one wants to set the affinity of.
 * @parm nodemap the map of the affine nodes.
 * @return 0 on success, -1 on failure.
 */
int xc_domain_node_setaffinity(xc_interface *xch,
                               uint32_t domind,
                               xc_nodemap_t nodemap);

/**
 * This function retrieves the host NUMA nodes the domain has
 * affinity with.
 *
 * @parm xch a handle to an open hypervisor interface.
 * @parm domid the domain id one wants to get the node affinity of.
 * @parm nodemap the map of the affine nodes.
 * @return 0 on success, -1 on failure.
 */
int xc_domain_node_getaffinity(xc_interface *xch,
                               uint32_t domind,
                               xc_nodemap_t nodemap);

/**
 * This function specifies the CPU affinity for a vcpu.
 *
 * There are two kinds of affinity. Soft affinity is on what CPUs a vcpu
 * prefers to run. Hard affinity is on what CPUs a vcpu is allowed to run.
 * If flags contains XEN_VCPUAFFINITY_SOFT, the soft affinity it is set to
 * what cpumap_soft_inout contains. If flags contains XEN_VCPUAFFINITY_HARD,
 * the hard affinity is set to what cpumap_hard_inout contains. Both flags
 * can be set at the same time, in which case both soft and hard affinity are
 * set to what the respective parameter contains.
 *
 * The function also returns the effective hard or/and soft affinity, still
 * via the cpumap_soft_inout and cpumap_hard_inout parameters. Effective
 * affinity is, in case of soft affinity, the intersection of soft affinity,
 * hard affinity and the cpupool's online CPUs for the domain, and is returned
 * in cpumap_soft_inout, if XEN_VCPUAFFINITY_SOFT is set in flags. In case of
 * hard affinity, it is the intersection between hard affinity and the
 * cpupool's online CPUs, and is returned in cpumap_hard_inout, if
 * XEN_VCPUAFFINITY_HARD is set in flags. If both flags are set, both soft
 * and hard affinity are returned in the respective parameter.
 *
 * We do report it back as effective affinity is what the Xen scheduler will
 * actually use, and we thus allow checking whether or not that matches with,
 * or at least is good enough for, the caller's purposes.
 *
 * @param xch a handle to an open hypervisor interface.
 * @param domid the id of the domain to which the vcpu belongs
 * @param vcpu the vcpu id wihin the domain
 * @param cpumap_hard_inout specifies(/returns) the (effective) hard affinity
 * @param cpumap_soft_inout specifies(/returns) the (effective) soft affinity
 * @param flags what we want to set
 */
int xc_vcpu_setaffinity(xc_interface *xch,
                        uint32_t domid,
                        int vcpu,
                        xc_cpumap_t cpumap_hard_inout,
                        xc_cpumap_t cpumap_soft_inout,
                        uint32_t flags);

/**
 * This function retrieves hard and soft CPU affinity of a vcpu,
 * depending on what flags are set.
 *
 * Soft affinity is returned in cpumap_soft if XEN_VCPUAFFINITY_SOFT is set.
 * Hard affinity is returned in cpumap_hard if XEN_VCPUAFFINITY_HARD is set.
 *
 * @param xch a handle to an open hypervisor interface.
 * @param domid the id of the domain to which the vcpu belongs
 * @param vcpu the vcpu id wihin the domain
 * @param cpumap_hard is where hard affinity is returned
 * @param cpumap_soft is where soft affinity is returned
 * @param flags what we want get
 */
int xc_vcpu_getaffinity(xc_interface *xch,
                        uint32_t domid,
                        int vcpu,
                        xc_cpumap_t cpumap_hard,
                        xc_cpumap_t cpumap_soft,
                        uint32_t flags);


/**
 * This function will return the guest_width (in bytes) for the
 * specified domain.
 *
 * @param xch a handle to an open hypervisor interface.
 * @param domid the domain id one wants the address size width of.
 * @param addr_size the address size.
 */
int xc_domain_get_guest_width(xc_interface *xch, uint32_t domid,
                              unsigned int *guest_width);


/**
 * This function will return information about one or more domains. It is
 * designed to iterate over the list of domains. If a single domain is
 * requested, this function will return the next domain in the list - if
 * one exists. It is, therefore, important in this case to make sure the
 * domain requested was the one returned.
 *
 * @parm xch a handle to an open hypervisor interface
 * @parm first_domid the first domain to enumerate information from.  Domains
 *                   are currently enumerate in order of creation.
 * @parm max_doms the number of elements in info
 * @parm info an array of max_doms size that will contain the information for
 *            the enumerated domains.
 * @return the number of domains enumerated or -1 on error
 */
int xc_domain_getinfo(xc_interface *xch,
                      uint32_t first_domid,
                      unsigned int max_doms,
                      xc_dominfo_t *info);


/**
 * This function will set the execution context for the specified vcpu.
 *
 * @parm xch a handle to an open hypervisor interface
 * @parm domid the domain to set the vcpu context for
 * @parm vcpu the vcpu number for the context
 * @parm ctxt pointer to the the cpu context with the values to set
 * @return the number of domains enumerated or -1 on error
 */
int xc_vcpu_setcontext(xc_interface *xch,
                       uint32_t domid,
                       uint32_t vcpu,
                       vcpu_guest_context_any_t *ctxt);
/**
 * This function will return information about one or more domains, using a
 * single hypercall.  The domain information will be stored into the supplied
 * array of xc_domaininfo_t structures.
 *
 * @parm xch a handle to an open hypervisor interface
 * @parm first_domain the first domain to enumerate information from.
 *                    Domains are currently enumerate in order of creation.
 * @parm max_domains the number of elements in info
 * @parm info an array of max_doms size that will contain the information for
 *            the enumerated domains.
 * @return the number of domains enumerated or -1 on error
 */
int xc_domain_getinfolist(xc_interface *xch,
                          uint32_t first_domain,
                          unsigned int max_domains,
                          xc_domaininfo_t *info);

/**
 * This function set p2m for broken page
 * &parm xch a handle to an open hypervisor interface
 * @parm domid the domain id which broken page belong to
 * @parm pfn the pfn number of the broken page
 * @return 0 on success, -1 on failure
 */
int xc_set_broken_page_p2m(xc_interface *xch,
                           uint32_t domid,
                           unsigned long pfn);

/**
 * This function returns information about the context of a hvm domain
 * @parm xch a handle to an open hypervisor interface
 * @parm domid the domain to get information from
 * @parm ctxt_buf a pointer to a structure to store the execution context of
 *            the hvm domain
 * @parm size the size of ctxt_buf in bytes
 * @return 0 on success, -1 on failure
 */
int xc_domain_hvm_getcontext(xc_interface *xch,
                             uint32_t domid,
                             uint8_t *ctxt_buf,
                             uint32_t size);


/**
 * This function returns one element of the context of a hvm domain
 * @parm xch a handle to an open hypervisor interface
 * @parm domid the domain to get information from
 * @parm typecode which type of elemnt required 
 * @parm instance which instance of the type
 * @parm ctxt_buf a pointer to a structure to store the execution context of
 *            the hvm domain
 * @parm size the size of ctxt_buf (must be >= HVM_SAVE_LENGTH(typecode))
 * @return 0 on success, -1 on failure
 */
int xc_domain_hvm_getcontext_partial(xc_interface *xch,
                                     uint32_t domid,
                                     uint16_t typecode,
                                     uint16_t instance,
                                     void *ctxt_buf,
                                     uint32_t size);

/**
 * This function will set the context for hvm domain
 *
 * @parm xch a handle to an open hypervisor interface
 * @parm domid the domain to set the hvm domain context for
 * @parm hvm_ctxt pointer to the the hvm context with the values to set
 * @parm size the size of hvm_ctxt in bytes
 * @return 0 on success, -1 on failure
 */
int xc_domain_hvm_setcontext(xc_interface *xch,
                             uint32_t domid,
                             uint8_t *hvm_ctxt,
                             uint32_t size);

/**
 * This function will return guest IO ABI protocol
 *
 * @parm xch a handle to an open hypervisor interface
 * @parm domid the domain to get IO ABI protocol for
 * @return guest protocol on success, NULL on failure
 */
const char *xc_domain_get_native_protocol(xc_interface *xch,
                                          uint32_t domid);

/**
 * This function returns information about the execution context of a
 * particular vcpu of a domain.
 *
 * @parm xch a handle to an open hypervisor interface
 * @parm domid the domain to get information from
 * @parm vcpu the vcpu number
 * @parm ctxt a pointer to a structure to store the execution context of the
 *            domain
 * @return 0 on success, -1 on failure
 */
int xc_vcpu_getcontext(xc_interface *xch,
                       uint32_t domid,
                       uint32_t vcpu,
                       vcpu_guest_context_any_t *ctxt);

/**
 * This function initializes the vuart emulation and returns
 * the event to be used by the backend for communicating with
 * the emulation code.
 *
 * @parm xch a handle to an open hypervisor interface
 * #parm type type of vuart
 * @parm domid the domain to get information from
 * @parm console_domid the domid of the backend console
 * @parm gfn the guest pfn to be used as the ring buffer
 * @parm evtchn the event channel to be used for events
 * @return 0 on success, negative error on failure
 */
int xc_dom_vuart_init(xc_interface *xch,
                      uint32_t type,
                      uint32_t domid,
                      uint32_t console_domid,
                      xen_pfn_t gfn,
                      evtchn_port_t *evtchn);

/**
 * This function returns information about the XSAVE state of a particular
 * vcpu of a domain. If extstate->size and extstate->xfeature_mask are 0,
 * the call is considered a query to retrieve them and the buffer is not
 * filled.
 *
 * @parm xch a handle to an open hypervisor interface
 * @parm domid the domain to get information from
 * @parm vcpu the vcpu number
 * @parm extstate a pointer to a structure to store the XSAVE state of the
 *                domain
 * @return 0 on success, negative error code on failure
 */
int xc_vcpu_get_extstate(xc_interface *xch,
                         uint32_t domid,
                         uint32_t vcpu,
                         xc_vcpu_extstate_t *extstate);

typedef struct xen_domctl_getvcpuinfo xc_vcpuinfo_t;
int xc_vcpu_getinfo(xc_interface *xch,
                    uint32_t domid,
                    uint32_t vcpu,
                    xc_vcpuinfo_t *info);

long long xc_domain_get_cpu_usage(xc_interface *xch,
                                  uint32_t domid,
                                  int vcpu);

int xc_domain_sethandle(xc_interface *xch, uint32_t domid,
                        xen_domain_handle_t handle);

typedef struct xen_domctl_shadow_op_stats xc_shadow_op_stats_t;
int xc_shadow_control(xc_interface *xch,
                      uint32_t domid,
                      unsigned int sop,
                      xc_hypercall_buffer_t *dirty_bitmap,
                      unsigned long pages,
                      unsigned long *mb,
                      uint32_t mode,
                      xc_shadow_op_stats_t *stats);

int xc_sched_credit_domain_set(xc_interface *xch,
                               uint32_t domid,
                               struct xen_domctl_sched_credit *sdom);

int xc_sched_credit_domain_get(xc_interface *xch,
                               uint32_t domid,
                               struct xen_domctl_sched_credit *sdom);
int xc_sched_credit_params_set(xc_interface *xch,
                               uint32_t cpupool_id,
                               struct xen_sysctl_credit_schedule *schedule);
int xc_sched_credit_params_get(xc_interface *xch,
                               uint32_t cpupool_id,
                               struct xen_sysctl_credit_schedule *schedule);

int xc_sched_credit2_params_set(xc_interface *xch,
                                uint32_t cpupool_id,
                                struct xen_sysctl_credit2_schedule *schedule);
int xc_sched_credit2_params_get(xc_interface *xch,
                                uint32_t cpupool_id,
                                struct xen_sysctl_credit2_schedule *schedule);
int xc_sched_credit2_domain_set(xc_interface *xch,
                                uint32_t domid,
                                struct xen_domctl_sched_credit2 *sdom);
int xc_sched_credit2_domain_get(xc_interface *xch,
                                uint32_t domid,
                                struct xen_domctl_sched_credit2 *sdom);

int xc_sched_rtds_domain_set(xc_interface *xch,
                             uint32_t domid,
                             struct xen_domctl_sched_rtds *sdom);
int xc_sched_rtds_domain_get(xc_interface *xch,
                             uint32_t domid,
                             struct xen_domctl_sched_rtds *sdom);
int xc_sched_rtds_vcpu_set(xc_interface *xch,
                           uint32_t domid,
                           struct xen_domctl_schedparam_vcpu *vcpus,
                           uint32_t num_vcpus);
int xc_sched_rtds_vcpu_get(xc_interface *xch,
                           uint32_t domid,
                           struct xen_domctl_schedparam_vcpu *vcpus,
                           uint32_t num_vcpus);

int
xc_sched_arinc653_schedule_set(
    xc_interface *xch,
    uint32_t cpupool_id,
    struct xen_sysctl_arinc653_schedule *schedule);

int
xc_sched_arinc653_schedule_get(
    xc_interface *xch,
    uint32_t cpupool_id,
    struct xen_sysctl_arinc653_schedule *schedule);

/**
 * This function sends a trigger to a domain.
 *
 * @parm xch a handle to an open hypervisor interface
 * @parm domid the domain id to send trigger
 * @parm trigger the trigger type
 * @parm vcpu the vcpu number to send trigger 
 * return 0 on success, -1 on failure
 */
int xc_domain_send_trigger(xc_interface *xch,
                           uint32_t domid,
                           uint32_t trigger,
                           uint32_t vcpu);

/**
 * This function enables or disable debugging of a domain.
 *
 * @parm xch a handle to an open hypervisor interface
 * @parm domid the domain id to send trigger
 * @parm enable true to enable debugging
 * return 0 on success, -1 on failure
 */
int xc_domain_setdebugging(xc_interface *xch,
                           uint32_t domid,
                           unsigned int enable);

/**
 * This function audits the (top level) p2m of a domain 
 * and returns the different error counts, if any.
 *
 * @parm xch a handle to an open hypervisor interface
 * @parm domid the domain id whose top level p2m we 
 *       want to audit
 * @parm orphans count of m2p entries for valid
 *       domain pages containing an invalid value
 * @parm m2p_bad count of m2p entries mismatching the
 *       associated p2m entry for this domain
 * @parm p2m_bad count of p2m entries for this domain
 *       mismatching the associated m2p entry
 * return 0 on success, -1 on failure
 * errno values on failure include: 
 *          -ENOSYS: not implemented
 *          -EFAULT: could not copy results back to guest
 */
int xc_domain_p2m_audit(xc_interface *xch,
                        uint32_t domid,
                        uint64_t *orphans,
                        uint64_t *m2p_bad,   
                        uint64_t *p2m_bad);

/**
 * This function sets or clears the requirement that an access memory
 * event listener is required on the domain.
 *
 * @parm xch a handle to an open hypervisor interface
 * @parm domid the domain id to send trigger
 * @parm enable true to require a listener
 * return 0 on success, -1 on failure
 */
int xc_domain_set_access_required(xc_interface *xch,
				  uint32_t domid,
				  unsigned int required);
/**
 * This function sets the handler of global VIRQs sent by the hypervisor
 *
 * @parm xch a handle to an open hypervisor interface
 * @parm domid the domain id which will handle the VIRQ
 * @parm virq the virq number (VIRQ_*)
 * return 0 on success, -1 on failure
 */
int xc_domain_set_virq_handler(xc_interface *xch, uint32_t domid, int virq);

/**
 * Set the maximum event channel port a domain may bind.
 *
 * This does not affect ports that are already bound.
 *
 * @param xch a handle to an open hypervisor interface
 * @param domid the domain id
 * @param max_port maximum port number
 */
int xc_domain_set_max_evtchn(xc_interface *xch, uint32_t domid,
                             uint32_t max_port);

/**
 * Set the maximum number of grant frames and maptrack frames a domain
 * can have. Must be used at domain setup time and only then.
 *
 * @param xch a handle to an open hypervisor interface
 * @param domid the domain id
 * @param grant_frames max. number of grant frames
 * @param maptrack_frames max. number of maptrack frames
 */
int xc_domain_set_gnttab_limits(xc_interface *xch, uint32_t domid,
                                uint32_t grant_frames,
                                uint32_t maptrack_frames);

/*
 * CPUPOOL MANAGEMENT FUNCTIONS
 */

typedef struct xc_cpupoolinfo {
    uint32_t cpupool_id;
    uint32_t sched_id;
    uint32_t n_dom;
    xc_cpumap_t cpumap;
} xc_cpupoolinfo_t;

#define XC_CPUPOOL_POOLID_ANY 0xFFFFFFFF

/**
 * Create a new cpupool.
 *
 * @parm xc_handle a handle to an open hypervisor interface
 * @parm ppoolid pointer to the new cpupool id (in/out)
 * @parm sched_id id of scheduler to use for pool
 * return 0 on success, -1 on failure
 */
int xc_cpupool_create(xc_interface *xch,
                      uint32_t *ppoolid,
                      uint32_t sched_id);

/**
 * Destroy a cpupool. Pool must be unused and have no cpu assigned.
 *
 * @parm xc_handle a handle to an open hypervisor interface
 * @parm poolid id of the cpupool to destroy
 * return 0 on success, -1 on failure
 */
int xc_cpupool_destroy(xc_interface *xch,
                       uint32_t poolid);

/**
 * Get cpupool info. Returns info for up to the specified number of cpupools
 * starting at the given id.
 * @parm xc_handle a handle to an open hypervisor interface
 * @parm poolid lowest id for which info is returned
 * return cpupool info ptr (to be freed via xc_cpupool_infofree)
 */
xc_cpupoolinfo_t *xc_cpupool_getinfo(xc_interface *xch,
                       uint32_t poolid);

/**
 * Free cpupool info. Used to free info obtained via xc_cpupool_getinfo.
 * @parm xc_handle a handle to an open hypervisor interface
 * @parm info area to free
 */
void xc_cpupool_infofree(xc_interface *xch,
                         xc_cpupoolinfo_t *info);

/**
 * Add cpu to a cpupool. cpu may be -1 indicating the first unassigned.
 *
 * @parm xc_handle a handle to an open hypervisor interface
 * @parm poolid id of the cpupool
 * @parm cpu cpu number to add
 * return 0 on success, -1 on failure
 */
int xc_cpupool_addcpu(xc_interface *xch,
                      uint32_t poolid,
                      int cpu);

/**
 * Remove cpu from cpupool. cpu may be -1 indicating the last cpu of the pool.
 *
 * @parm xc_handle a handle to an open hypervisor interface
 * @parm poolid id of the cpupool
 * @parm cpu cpu number to remove
 * return 0 on success, -1 on failure
 */
int xc_cpupool_removecpu(xc_interface *xch,
                         uint32_t poolid,
                         int cpu);

/**
 * Move domain to another cpupool.
 *
 * @parm xc_handle a handle to an open hypervisor interface
 * @parm poolid id of the destination cpupool
 * @parm domid id of the domain to move
 * return 0 on success, -1 on failure
 */
int xc_cpupool_movedomain(xc_interface *xch,
                          uint32_t poolid,
                          uint32_t domid);

/**
 * Return map of cpus not in any cpupool.
 *
 * @parm xc_handle a handle to an open hypervisor interface
 * return cpumap array on success, NULL else
 */
xc_cpumap_t xc_cpupool_freeinfo(xc_interface *xch);

/*
 * EVENT CHANNEL FUNCTIONS
 *
 * None of these do any logging.
 */

/* A port identifier is guaranteed to fit in 31 bits. */
typedef int xc_evtchn_port_or_error_t;

/**
 * This function allocates an unbound port.  Ports are named endpoints used for
 * interdomain communication.  This function is most useful in opening a
 * well-known port within a domain to receive events on.
 * 
 * NOTE: If you are allocating a *local* unbound port, you probably want to
 * use xc_evtchn_bind_unbound_port(). This function is intended for allocating
 * ports *only* during domain creation.
 *
 * @parm xch a handle to an open hypervisor interface
 * @parm dom the ID of the local domain (the 'allocatee')
 * @parm remote_dom the ID of the domain who will later bind
 * @return allocated port (in @dom) on success, -1 on failure
 */
xc_evtchn_port_or_error_t
xc_evtchn_alloc_unbound(xc_interface *xch,
                        uint32_t dom,
                        uint32_t remote_dom);

int xc_evtchn_reset(xc_interface *xch,
                    uint32_t dom);

typedef struct evtchn_status xc_evtchn_status_t;
int xc_evtchn_status(xc_interface *xch, xc_evtchn_status_t *status);



int xc_physdev_pci_access_modify(xc_interface *xch,
                                 uint32_t domid,
                                 int bus,
                                 int dev,
                                 int func,
                                 int enable);

int xc_readconsolering(xc_interface *xch,
                       char *buffer,
                       unsigned int *pnr_chars,
                       int clear, int incremental, uint32_t *pindex);

int xc_send_debug_keys(xc_interface *xch, char *keys);
int xc_set_parameters(xc_interface *xch, char *params);

typedef struct xen_sysctl_physinfo xc_physinfo_t;
typedef struct xen_sysctl_cputopo xc_cputopo_t;
typedef struct xen_sysctl_numainfo xc_numainfo_t;
typedef struct xen_sysctl_meminfo xc_meminfo_t;
typedef struct xen_sysctl_pcitopoinfo xc_pcitopoinfo_t;

typedef uint32_t xc_cpu_to_node_t;
typedef uint32_t xc_cpu_to_socket_t;
typedef uint32_t xc_cpu_to_core_t;
typedef uint64_t xc_node_to_memsize_t;
typedef uint64_t xc_node_to_memfree_t;
typedef uint32_t xc_node_to_node_dist_t;

int xc_physinfo(xc_interface *xch, xc_physinfo_t *info);
int xc_cputopoinfo(xc_interface *xch, unsigned *max_cpus,
                   xc_cputopo_t *cputopo);
int xc_numainfo(xc_interface *xch, unsigned *max_nodes,
                xc_meminfo_t *meminfo, uint32_t *distance);
int xc_pcitopoinfo(xc_interface *xch, unsigned num_devs,
                   physdev_pci_device_t *devs, uint32_t *nodes);

int xc_sched_id(xc_interface *xch,
                int *sched_id);

int xc_machphys_mfn_list(xc_interface *xch,
                         unsigned long max_extents,
                         xen_pfn_t *extent_start);

typedef struct xen_sysctl_cpuinfo xc_cpuinfo_t;
int xc_getcpuinfo(xc_interface *xch, int max_cpus,
                  xc_cpuinfo_t *info, int *nr_cpus); 

int xc_domain_setmaxmem(xc_interface *xch,
                        uint32_t domid,
                        uint64_t max_memkb);

int xc_domain_set_memmap_limit(xc_interface *xch,
                               uint32_t domid,
                               unsigned long map_limitkb);

int xc_domain_setvnuma(xc_interface *xch,
                        uint32_t domid,
                        uint32_t nr_vnodes,
                        uint32_t nr_regions,
                        uint32_t nr_vcpus,
                        xen_vmemrange_t *vmemrange,
                        unsigned int *vdistance,
                        unsigned int *vcpu_to_vnode,
                        unsigned int *vnode_to_pnode);
/*
 * Retrieve vnuma configuration
 * domid: IN, target domid
 * nr_vnodes: IN/OUT, number of vnodes, not NULL
 * nr_vmemranges: IN/OUT, number of vmemranges, not NULL
 * nr_vcpus: IN/OUT, number of vcpus, not NULL
 * vmemranges: OUT, an array which has length of nr_vmemranges
 * vdistance: OUT, an array which has length of nr_vnodes * nr_vnodes
 * vcpu_to_vnode: OUT, an array which has length of nr_vcpus
 */
int xc_domain_getvnuma(xc_interface *xch,
                       uint32_t domid,
                       uint32_t *nr_vnodes,
                       uint32_t *nr_vmemranges,
                       uint32_t *nr_vcpus,
                       xen_vmemrange_t *vmemrange,
                       unsigned int *vdistance,
                       unsigned int *vcpu_to_vnode);

int xc_domain_soft_reset(xc_interface *xch,
                         uint32_t domid);

#if defined(__i386__) || defined(__x86_64__)
/*
 * PC BIOS standard E820 types and structure.
 */
#define E820_RAM          1
#define E820_RESERVED     2
#define E820_ACPI         3
#define E820_NVS          4
#define E820_UNUSABLE     5

#define E820MAX           (128)

struct e820entry {
    uint64_t addr;
    uint64_t size;
    uint32_t type;
} __attribute__((packed));
int xc_domain_set_memory_map(xc_interface *xch,
                               uint32_t domid,
                               struct e820entry entries[],
                               uint32_t nr_entries);

int xc_get_machine_memory_map(xc_interface *xch,
                              struct e820entry entries[],
                              uint32_t max_entries);
#endif

int xc_reserved_device_memory_map(xc_interface *xch,
                                  uint32_t flags,
                                  uint16_t seg,
                                  uint8_t bus,
                                  uint8_t devfn,
                                  struct xen_reserved_device_memory entries[],
                                  uint32_t *max_entries);
int xc_domain_set_time_offset(xc_interface *xch,
                              uint32_t domid,
                              int32_t time_offset_seconds);

int xc_domain_set_tsc_info(xc_interface *xch,
                           uint32_t domid,
                           uint32_t tsc_mode,
                           uint64_t elapsed_nsec,
                           uint32_t gtsc_khz,
                           uint32_t incarnation);

int xc_domain_get_tsc_info(xc_interface *xch,
                           uint32_t domid,
                           uint32_t *tsc_mode,
                           uint64_t *elapsed_nsec,
                           uint32_t *gtsc_khz,
                           uint32_t *incarnation);

int xc_domain_disable_migrate(xc_interface *xch, uint32_t domid);

int xc_domain_maximum_gpfn(xc_interface *xch, uint32_t domid, xen_pfn_t *gpfns);

int xc_domain_nr_gpfns(xc_interface *xch, uint32_t domid, xen_pfn_t *gpfns);

int xc_domain_increase_reservation(xc_interface *xch,
                                   uint32_t domid,
                                   unsigned long nr_extents,
                                   unsigned int extent_order,
                                   unsigned int mem_flags,
                                   xen_pfn_t *extent_start);

int xc_domain_increase_reservation_exact(xc_interface *xch,
                                         uint32_t domid,
                                         unsigned long nr_extents,
                                         unsigned int extent_order,
                                         unsigned int mem_flags,
                                         xen_pfn_t *extent_start);

int xc_domain_decrease_reservation(xc_interface *xch,
                                   uint32_t domid,
                                   unsigned long nr_extents,
                                   unsigned int extent_order,
                                   xen_pfn_t *extent_start);

int xc_domain_decrease_reservation_exact(xc_interface *xch,
                                         uint32_t domid,
                                         unsigned long nr_extents,
                                         unsigned int extent_order,
                                         xen_pfn_t *extent_start);

int xc_domain_add_to_physmap(xc_interface *xch,
                             uint32_t domid,
                             unsigned int space,
                             unsigned long idx,
                             xen_pfn_t gpfn);

int xc_domain_add_to_physmap_batch(xc_interface *xch,
                                   uint32_t domid,
                                   uint32_t foreign_domid,
                                   unsigned int space,
                                   unsigned int size,
                                   xen_ulong_t *idxs,
                                   xen_pfn_t *gfpns,
                                   int *errs);

int xc_domain_remove_from_physmap(xc_interface *xch,
                                  uint32_t domid,
                                  xen_pfn_t gpfn);

int xc_domain_populate_physmap(xc_interface *xch,
                               uint32_t domid,
                               unsigned long nr_extents,
                               unsigned int extent_order,
                               unsigned int mem_flags,
                               xen_pfn_t *extent_start);

int xc_domain_populate_physmap_exact(xc_interface *xch,
                                     uint32_t domid,
                                     unsigned long nr_extents,
                                     unsigned int extent_order,
                                     unsigned int mem_flags,
                                     xen_pfn_t *extent_start);

int xc_domain_claim_pages(xc_interface *xch,
                               uint32_t domid,
                               unsigned long nr_pages);

int xc_domain_memory_exchange_pages(xc_interface *xch,
                                    uint32_t domid,
                                    unsigned long nr_in_extents,
                                    unsigned int in_order,
                                    xen_pfn_t *in_extents,
                                    unsigned long nr_out_extents,
                                    unsigned int out_order,
                                    xen_pfn_t *out_extents);

int xc_domain_set_pod_target(xc_interface *xch,
                             uint32_t domid,
                             uint64_t target_pages,
                             uint64_t *tot_pages,
                             uint64_t *pod_cache_pages,
                             uint64_t *pod_entries);

int xc_domain_get_pod_target(xc_interface *xch,
                             uint32_t domid,
                             uint64_t *tot_pages,
                             uint64_t *pod_cache_pages,
                             uint64_t *pod_entries);

int xc_domain_ioport_permission(xc_interface *xch,
                                uint32_t domid,
                                uint32_t first_port,
                                uint32_t nr_ports,
                                uint32_t allow_access);

int xc_domain_irq_permission(xc_interface *xch,
                             uint32_t domid,
                             uint8_t pirq,
                             uint8_t allow_access);

int xc_domain_iomem_permission(xc_interface *xch,
                               uint32_t domid,
                               unsigned long first_mfn,
                               unsigned long nr_mfns,
                               uint8_t allow_access);

unsigned long xc_make_page_below_4G(xc_interface *xch, uint32_t domid,
                                    unsigned long mfn);

typedef xen_sysctl_perfc_desc_t xc_perfc_desc_t;
typedef xen_sysctl_perfc_val_t xc_perfc_val_t;
int xc_perfc_reset(xc_interface *xch);
int xc_perfc_query_number(xc_interface *xch,
                          int *nbr_desc,
                          int *nbr_val);
int xc_perfc_query(xc_interface *xch,
                   xc_hypercall_buffer_t *desc,
                   xc_hypercall_buffer_t *val);

typedef xen_sysctl_lockprof_data_t xc_lockprof_data_t;
int xc_lockprof_reset(xc_interface *xch);
int xc_lockprof_query_number(xc_interface *xch,
                             uint32_t *n_elems);
int xc_lockprof_query(xc_interface *xch,
                      uint32_t *n_elems,
                      uint64_t *time,
                      xc_hypercall_buffer_t *data);

void *xc_memalign(xc_interface *xch, size_t alignment, size_t size);

/**
 * Avoid using this function, as it does not work for all cases (such
 * as 4M superpages, or guests using PSE36). Only used for debugging.
 *
 * Translates a virtual address in the context of a given domain and
 * vcpu returning the GFN containing the address (that is, an MFN for 
 * PV guests, a PFN for HVM guests).  Returns 0 for failure.
 *
 * @parm xch a handle on an open hypervisor interface
 * @parm dom the domain to perform the translation in
 * @parm vcpu the vcpu to perform the translation on
 * @parm virt the virtual address to translate
 */
unsigned long xc_translate_foreign_address(xc_interface *xch, uint32_t dom,
                                           int vcpu, unsigned long long virt);


int xc_copy_to_domain_page(xc_interface *xch, uint32_t domid,
                           unsigned long dst_pfn, const char *src_page);

int xc_clear_domain_pages(xc_interface *xch, uint32_t domid,
                          unsigned long dst_pfn, int num);

static inline int xc_clear_domain_page(xc_interface *xch, uint32_t domid,
                                       unsigned long dst_pfn)
{
    return xc_clear_domain_pages(xch, domid, dst_pfn, 1);
}

int xc_mmuext_op(xc_interface *xch, struct mmuext_op *op, unsigned int nr_ops,
                 uint32_t dom);

/* System wide memory properties */
int xc_maximum_ram_page(xc_interface *xch, unsigned long *max_mfn);

/* Get current total pages allocated to a domain. */
long xc_get_tot_pages(xc_interface *xch, uint32_t domid);

/**
 * This function retrieves the the number of bytes available
 * in the heap in a specific range of address-widths and nodes.
 * 
 * @parm xch a handle to an open hypervisor interface
 * @parm domid the domain to query
 * @parm min_width the smallest address width to query (0 if don't care)
 * @parm max_width the largest address width to query (0 if don't care)
 * @parm node the node to query (-1 for all)
 * @parm *bytes caller variable to put total bytes counted
 * @return 0 on success, <0 on failure.
 */
int xc_availheap(xc_interface *xch, int min_width, int max_width, int node,
                 uint64_t *bytes);

/*
 * Trace Buffer Operations
 */

/**
 * xc_tbuf_enable - enable tracing buffers
 *
 * @parm xch a handle to an open hypervisor interface
 * @parm cnt size of tracing buffers to create (in pages)
 * @parm mfn location to store mfn of the trace buffers to
 * @parm size location to store the size (in bytes) of a trace buffer to
 *
 * Gets the machine address of the trace pointer area and the size of the
 * per CPU buffers.
 */
int xc_tbuf_enable(xc_interface *xch, unsigned long pages,
                   unsigned long *mfn, unsigned long *size);

/*
 * Disable tracing buffers.
 */
int xc_tbuf_disable(xc_interface *xch);

/**
 * This function sets the size of the trace buffers. Setting the size
 * is currently a one-shot operation that may be performed either at boot
 * time or via this interface, not both. The buffer size must be set before
 * enabling tracing.
 *
 * @parm xch a handle to an open hypervisor interface
 * @parm size the size in pages per cpu for the trace buffers
 * @return 0 on success, -1 on failure.
 */
int xc_tbuf_set_size(xc_interface *xch, unsigned long size);

/**
 * This function retrieves the current size of the trace buffers.
 * Note that the size returned is in terms of bytes, not pages.

 * @parm xch a handle to an open hypervisor interface
 * @parm size will contain the size in bytes for the trace buffers
 * @return 0 on success, -1 on failure.
 */
int xc_tbuf_get_size(xc_interface *xch, unsigned long *size);

int xc_tbuf_set_cpu_mask(xc_interface *xch, xc_cpumap_t mask);

int xc_tbuf_set_evt_mask(xc_interface *xch, uint32_t mask);

int xc_domctl(xc_interface *xch, struct xen_domctl *domctl);
int xc_sysctl(xc_interface *xch, struct xen_sysctl *sysctl);

int xc_version(xc_interface *xch, int cmd, void *arg);

int xc_flask_op(xc_interface *xch, xen_flask_op_t *op);

/*
 * Subscribe to domain suspend via evtchn.
 * Returns -1 on failure, in which case errno will be set appropriately.
 * Just calls XEN_DOMCTL_subscribe - see the caveats for that domctl
 * (in its doc comment in domctl.h).
 */
int xc_domain_subscribe_for_suspend(
    xc_interface *xch, uint32_t domid, evtchn_port_t port);

/**************************
 * GRANT TABLE OPERATIONS *
 **************************/

/*
 * These functions sometimes log messages as above, but not always.
 */


int xc_gnttab_op(xc_interface *xch, int cmd,
                 void * op, int op_size, int count);
/* Logs iff hypercall bounce fails, otherwise doesn't. */

int xc_gnttab_query_size(xc_interface *xch, struct gnttab_query_size *query);
int xc_gnttab_get_version(xc_interface *xch, uint32_t domid); /* Never logs */
grant_entry_v1_t *xc_gnttab_map_table_v1(xc_interface *xch, uint32_t domid, int *gnt_num);
grant_entry_v2_t *xc_gnttab_map_table_v2(xc_interface *xch, uint32_t domid, int *gnt_num);
/* Sometimes these don't set errno [fixme], and sometimes they don't log. */

int xc_physdev_map_pirq(xc_interface *xch,
                        uint32_t domid,
                        int index,
                        int *pirq);

int xc_physdev_map_pirq_msi(xc_interface *xch,
                            uint32_t domid,
                            int index,
                            int *pirq,
                            int devfn,
                            int bus,
                            int entry_nr,
                            uint64_t table_base);

int xc_physdev_unmap_pirq(xc_interface *xch,
                          uint32_t domid,
                          int pirq);

/*
 *  LOGGING AND ERROR REPORTING
 */


#define XC_MAX_ERROR_MSG_LEN 1024
typedef struct xc_error {
  enum xc_error_code code;
  char message[XC_MAX_ERROR_MSG_LEN];
} xc_error;


/*
 * Convert an error code or level into a text description.  Return values
 * are pointers to fixed strings and do not need to be freed.
 * Do not fail, but return pointers to generic strings if fed bogus input.
 */
const char *xc_error_code_to_desc(int code);

/*
 * Convert an errno value to a text description.
 */
const char *xc_strerror(xc_interface *xch, int errcode);


/*
 * Return a pointer to the last error with level XC_REPORT_ERROR. This
 * pointer and the data pointed to are only valid until the next call
 * to libxc in the same thread.
 */
const xc_error *xc_get_last_error(xc_interface *handle);

/*
 * Clear the last error
 */
void xc_clear_last_error(xc_interface *xch);

int xc_hvm_param_set(xc_interface *handle, uint32_t dom, uint32_t param, uint64_t value);
int xc_hvm_param_get(xc_interface *handle, uint32_t dom, uint32_t param, uint64_t *value);

/* Deprecated: use xc_hvm_param_set/get() instead. */
int xc_set_hvm_param(xc_interface *handle, uint32_t dom, int param, unsigned long value);
int xc_get_hvm_param(xc_interface *handle, uint32_t dom, int param, unsigned long *value);

/* HVM guest pass-through */
int xc_assign_device(xc_interface *xch,
                     uint32_t domid,
                     uint32_t machine_sbdf,
                     uint32_t flag);

int xc_get_device_group(xc_interface *xch,
                     uint32_t domid,
                     uint32_t machine_sbdf,
                     uint32_t max_sdevs,
                     uint32_t *num_sdevs,
                     uint32_t *sdev_array);

int xc_test_assign_device(xc_interface *xch,
                          uint32_t domid,
                          uint32_t machine_sbdf);

int xc_deassign_device(xc_interface *xch,
                     uint32_t domid,
                     uint32_t machine_sbdf);

int xc_assign_dt_device(xc_interface *xch,
                        uint32_t domid,
                        char *path);
int xc_test_assign_dt_device(xc_interface *xch,
                             uint32_t domid,
                             char *path);
int xc_deassign_dt_device(xc_interface *xch,
                          uint32_t domid,
                          char *path);

int xc_domain_memory_mapping(xc_interface *xch,
                             uint32_t domid,
                             unsigned long first_gfn,
                             unsigned long first_mfn,
                             unsigned long nr_mfns,
                             uint32_t add_mapping);

int xc_domain_ioport_mapping(xc_interface *xch,
                             uint32_t domid,
                             uint32_t first_gport,
                             uint32_t first_mport,
                             uint32_t nr_ports,
                             uint32_t add_mapping);

int xc_domain_update_msi_irq(
    xc_interface *xch,
    uint32_t domid,
    uint32_t gvec,
    uint32_t pirq,
    uint32_t gflags,
    uint64_t gtable);

int xc_domain_unbind_msi_irq(xc_interface *xch,
                             uint32_t domid,
                             uint32_t gvec,
                             uint32_t pirq,
                             uint32_t gflags);

int xc_domain_bind_pt_irq(xc_interface *xch,
                          uint32_t domid,
                          uint8_t machine_irq,
                          uint8_t irq_type,
                          uint8_t bus,
                          uint8_t device,
                          uint8_t intx,
                          uint8_t isa_irq);

int xc_domain_unbind_pt_irq(xc_interface *xch,
                          uint32_t domid,
                          uint8_t machine_irq,
                          uint8_t irq_type,
                          uint8_t bus,
                          uint8_t device,
                          uint8_t intx,
                          uint8_t isa_irq);

int xc_domain_bind_pt_pci_irq(xc_interface *xch,
                              uint32_t domid,
                              uint8_t machine_irq,
                              uint8_t bus,
                              uint8_t device,
                              uint8_t intx);

int xc_domain_bind_pt_isa_irq(xc_interface *xch,
                              uint32_t domid,
                              uint8_t machine_irq);

int xc_domain_bind_pt_spi_irq(xc_interface *xch,
                              uint32_t domid,
                              uint16_t vspi,
                              uint16_t spi);

int xc_domain_unbind_pt_spi_irq(xc_interface *xch,
                                uint32_t domid,
                                uint16_t vspi,
                                uint16_t spi);

int xc_domain_set_machine_address_size(xc_interface *xch,
				       uint32_t domid,
				       unsigned int width);
int xc_domain_get_machine_address_size(xc_interface *xch,
				       uint32_t domid);

int xc_domain_suppress_spurious_page_faults(xc_interface *xch,
					  uint32_t domid);

/* Set the target domain */
int xc_domain_set_target(xc_interface *xch,
                         uint32_t domid,
                         uint32_t target);

/* Control the domain for debug */
int xc_domain_debug_control(xc_interface *xch,
                            uint32_t domid,
                            uint32_t sop,
                            uint32_t vcpu);

#if defined(__i386__) || defined(__x86_64__)
int xc_cpuid_set(xc_interface *xch,
                 uint32_t domid,
                 const unsigned int *input,
                 const char **config,
                 char **config_transformed);
int xc_cpuid_apply_policy(xc_interface *xch,
                          uint32_t domid,
                          uint32_t *featureset,
                          unsigned int nr_features);
void xc_cpuid_to_str(const unsigned int *regs,
                     char **strs); /* some strs[] may be NULL if ENOMEM */
int xc_mca_op(xc_interface *xch, struct xen_mc *mc);
int xc_mca_op_inject_v2(xc_interface *xch, unsigned int flags,
                        xc_cpumap_t cpumap, unsigned int nr_cpus);
#endif

struct xc_px_val {
    uint64_t freq;        /* Px core frequency */
    uint64_t residency;   /* Px residency time */
    uint64_t count;       /* Px transition count */
};

struct xc_px_stat {
    uint8_t total;        /* total Px states */
    uint8_t usable;       /* usable Px states */
    uint8_t last;         /* last Px state */
    uint8_t cur;          /* current Px state */
    uint64_t *trans_pt;   /* Px transition table */
    struct xc_px_val *pt;
};

int xc_pm_get_max_px(xc_interface *xch, int cpuid, int *max_px);
int xc_pm_get_pxstat(xc_interface *xch, int cpuid, struct xc_px_stat *pxpt);
int xc_pm_reset_pxstat(xc_interface *xch, int cpuid);

struct xc_cx_stat {
    uint32_t nr;           /* entry nr in triggers[]/residencies[], incl C0 */
    uint32_t last;         /* last Cx state */
    uint64_t idle_time;    /* idle time from boot */
    uint64_t *triggers;    /* Cx trigger counts */
    uint64_t *residencies; /* Cx residencies */
    uint32_t nr_pc;        /* entry nr in pc[] */
    uint32_t nr_cc;        /* entry nr in cc[] */
    uint64_t *pc;          /* 1-biased indexing (i.e. excl C0) */
    uint64_t *cc;          /* 1-biased indexing (i.e. excl C0) */
};
typedef struct xc_cx_stat xc_cx_stat_t;

int xc_pm_get_max_cx(xc_interface *xch, int cpuid, int *max_cx);
int xc_pm_get_cxstat(xc_interface *xch, int cpuid, struct xc_cx_stat *cxpt);
int xc_pm_reset_cxstat(xc_interface *xch, int cpuid);

int xc_cpu_online(xc_interface *xch, int cpu);
int xc_cpu_offline(xc_interface *xch, int cpu);

/* 
 * cpufreq para name of this structure named 
 * same as sysfs file name of native linux
 */
typedef struct xen_userspace xc_userspace_t;
typedef struct xen_ondemand xc_ondemand_t;

struct xc_get_cpufreq_para {
    /* IN/OUT variable */
    uint32_t cpu_num;
    uint32_t freq_num;
    uint32_t gov_num;

    /* for all governors */
    /* OUT variable */
    uint32_t *affected_cpus;
    uint32_t *scaling_available_frequencies;
    char     *scaling_available_governors;
    char scaling_driver[CPUFREQ_NAME_LEN];

    uint32_t cpuinfo_cur_freq;
    uint32_t cpuinfo_max_freq;
    uint32_t cpuinfo_min_freq;
    uint32_t scaling_cur_freq;

    char scaling_governor[CPUFREQ_NAME_LEN];
    uint32_t scaling_max_freq;
    uint32_t scaling_min_freq;

    /* for specific governor */
    union {
        xc_userspace_t userspace;
        xc_ondemand_t ondemand;
    } u;

    int32_t turbo_enabled;
};

int xc_get_cpufreq_para(xc_interface *xch, int cpuid,
                        struct xc_get_cpufreq_para *user_para);
int xc_set_cpufreq_gov(xc_interface *xch, int cpuid, char *govname);
int xc_set_cpufreq_para(xc_interface *xch, int cpuid,
                        int ctrl_type, int ctrl_value);
int xc_get_cpufreq_avgfreq(xc_interface *xch, int cpuid, int *avg_freq);

int xc_set_sched_opt_smt(xc_interface *xch, uint32_t value);

int xc_get_cpuidle_max_cstate(xc_interface *xch, uint32_t *value);
int xc_set_cpuidle_max_cstate(xc_interface *xch, uint32_t value);

int xc_enable_turbo(xc_interface *xch, int cpuid);
int xc_disable_turbo(xc_interface *xch, int cpuid);
/**
 * tmem operations
 */

int xc_tmem_control_oid(xc_interface *xch, int32_t pool_id, uint32_t subop,
                        uint32_t cli_id, uint32_t len, uint32_t arg,
                        struct xen_tmem_oid oid, void *buf);
int xc_tmem_control(xc_interface *xch,
                    int32_t pool_id, uint32_t subop, uint32_t cli_id,
                    uint32_t len, uint32_t arg, void *buf);
int xc_tmem_auth(xc_interface *xch, int cli_id, char *uuid_str, int enable);
int xc_tmem_save(xc_interface *xch, uint32_t domid, int live, int fd, int field_marker);
int xc_tmem_save_extra(xc_interface *xch, uint32_t domid, int fd, int field_marker);
void xc_tmem_save_done(xc_interface *xch, uint32_t domid);
int xc_tmem_restore(xc_interface *xch, uint32_t domid, int fd);
int xc_tmem_restore_extra(xc_interface *xch, uint32_t domid, int fd);

/**
 * altp2m operations
 */

int xc_altp2m_get_domain_state(xc_interface *handle, uint32_t dom, bool *state);
int xc_altp2m_set_domain_state(xc_interface *handle, uint32_t dom, bool state);
int xc_altp2m_set_vcpu_enable_notify(xc_interface *handle, uint32_t domid,
                                     uint32_t vcpuid, xen_pfn_t gfn);
int xc_altp2m_create_view(xc_interface *handle, uint32_t domid,
                          xenmem_access_t default_access, uint16_t *view_id);
int xc_altp2m_destroy_view(xc_interface *handle, uint32_t domid,
                           uint16_t view_id);
/* Switch all vCPUs of the domain to the specified altp2m view */
int xc_altp2m_switch_to_view(xc_interface *handle, uint32_t domid,
                             uint16_t view_id);
int xc_altp2m_set_mem_access(xc_interface *handle, uint32_t domid,
                             uint16_t view_id, xen_pfn_t gfn,
                             xenmem_access_t access);
int xc_altp2m_change_gfn(xc_interface *handle, uint32_t domid,
                         uint16_t view_id, xen_pfn_t old_gfn,
                         xen_pfn_t new_gfn);

/** 
 * Mem paging operations.
 * Paging is supported only on the x86 architecture in 64 bit mode, with
 * Hardware-Assisted Paging (i.e. Intel EPT, AMD NPT). Moreover, AMD NPT
 * support is considered experimental.
 */
int xc_mem_paging_enable(xc_interface *xch, uint32_t domain_id, uint32_t *port);
int xc_mem_paging_disable(xc_interface *xch, uint32_t domain_id);
int xc_mem_paging_resume(xc_interface *xch, uint32_t domain_id);
int xc_mem_paging_nominate(xc_interface *xch, uint32_t domain_id,
                           uint64_t gfn);
int xc_mem_paging_evict(xc_interface *xch, uint32_t domain_id, uint64_t gfn);
int xc_mem_paging_prep(xc_interface *xch, uint32_t domain_id, uint64_t gfn);
int xc_mem_paging_load(xc_interface *xch, uint32_t domain_id,
                       uint64_t gfn, void *buffer);

/** 
 * Access tracking operations.
 * Supported only on Intel EPT 64 bit processors.
 */

/*
 * Set a range of memory to a specific access.
 * Allowed types are XENMEM_access_default, XENMEM_access_n, any combination of
 * XENMEM_access_ + (rwx), and XENMEM_access_rx2rw
 */
int xc_set_mem_access(xc_interface *xch, uint32_t domain_id,
                      xenmem_access_t access, uint64_t first_pfn,
                      uint32_t nr);

/*
 * Set an array of pages to their respective access in the access array.
 * The nr parameter specifies the size of the pages and access arrays.
 * The same allowed access types as for xc_set_mem_access() apply.
 */
int xc_set_mem_access_multi(xc_interface *xch, uint32_t domain_id,
                            uint8_t *access, uint64_t *pages,
                            uint32_t nr);

/*
 * Gets the mem access for the given page (returned in access on success)
 */
int xc_get_mem_access(xc_interface *xch, uint32_t domain_id,
                      uint64_t pfn, xenmem_access_t *access);

/***
 * Monitor control operations.
 *
 * Enables the VM event monitor ring and returns the mapped ring page.
 * This ring is used to deliver mem_access events, as well a set of additional
 * events that can be enabled with the xc_monitor_* functions.
 *
 * Will return NULL on error.
 * Caller has to unmap this page when done.
 */
void *xc_monitor_enable(xc_interface *xch, uint32_t domain_id, uint32_t *port);
int xc_monitor_disable(xc_interface *xch, uint32_t domain_id);
int xc_monitor_resume(xc_interface *xch, uint32_t domain_id);
/*
 * Get a bitmap of supported monitor events in the form
 * (1 << XEN_DOMCTL_MONITOR_EVENT_*).
 */
int xc_monitor_get_capabilities(xc_interface *xch, uint32_t domain_id,
                                uint32_t *capabilities);
int xc_monitor_write_ctrlreg(xc_interface *xch, uint32_t domain_id,
                             uint16_t index, bool enable, bool sync,
                             uint64_t bitmask, bool onchangeonly);
/*
 * A list of MSR indices can usually be found in /usr/include/asm/msr-index.h.
 * Please consult the Intel/AMD manuals for more information on
 * non-architectural indices.
 */
int xc_monitor_mov_to_msr(xc_interface *xch, uint32_t domain_id, uint32_t msr,
                          bool enable, bool onchangeonly);
int xc_monitor_singlestep(xc_interface *xch, uint32_t domain_id, bool enable);
int xc_monitor_software_breakpoint(xc_interface *xch, uint32_t domain_id,
                                   bool enable);
int xc_monitor_descriptor_access(xc_interface *xch, uint32_t domain_id,
                                 bool enable);
int xc_monitor_guest_request(xc_interface *xch, uint32_t domain_id,
                             bool enable, bool sync, bool allow_userspace);
int xc_monitor_debug_exceptions(xc_interface *xch, uint32_t domain_id,
                                bool enable, bool sync);
int xc_monitor_cpuid(xc_interface *xch, uint32_t domain_id, bool enable);
int xc_monitor_privileged_call(xc_interface *xch, uint32_t domain_id,
                               bool enable);
int xc_monitor_emul_unimplemented(xc_interface *xch, uint32_t domain_id,
                                  bool enable);
/**
 * This function enables / disables emulation for each REP for a
 * REP-compatible instruction.
 *
 * @parm xch a handle to an open hypervisor interface.
 * @parm domain_id the domain id one wants to get the node affinity of.
 * @parm enable if 0 optimize when possible, else emulate each REP.
 * @return 0 on success, -1 on failure.
 */
int xc_monitor_emulate_each_rep(xc_interface *xch, uint32_t domain_id,
                                bool enable);

/***
 * Memory sharing operations.
 *
 * Unles otherwise noted, these calls return 0 on succes, -1 and errno on
 * failure.
 *
 * Sharing is supported only on the x86 architecture in 64 bit mode, with
 * Hardware-Assisted Paging (i.e. Intel EPT, AMD NPT). Moreover, AMD NPT
 * support is considered experimental. 

 * Calls below return ENOSYS if not in the x86_64 architecture.
 * Calls below return ENODEV if the domain does not support HAP.
 * Calls below return ESRCH if the specified domain does not exist.
 * Calls below return EPERM if the caller is unprivileged for this domain.
 */

/* Turn on/off sharing for the domid, depending on the enable flag.
 *
 * Returns EXDEV if trying to enable and the domain has had a PCI device
 * assigned for passthrough (these two features are mutually exclusive).
 *
 * When sharing for a domain is turned off, the domain may still reference
 * shared pages. Unsharing happens lazily. */
int xc_memshr_control(xc_interface *xch,
                      uint32_t domid,
                      int enable);

/* Create a communication ring in which the hypervisor will place ENOMEM
 * notifications.
 *
 * ENOMEM happens when unsharing pages: a Copy-on-Write duplicate needs to be
 * allocated, and thus the out-of-memory error occurr.
 *
 * For complete examples on how to plumb a notification ring, look into
 * xenpaging or xen-access.
 *
 * On receipt of a notification, the helper should ensure there is memory
 * available to the domain before retrying.
 *
 * If a domain encounters an ENOMEM condition when sharing and this ring
 * has not been set up, the hypervisor will crash the domain.
 *
 * Fails with:
 *  EINVAL if port is NULL
 *  EINVAL if the sharing ring has already been enabled
 *  ENOSYS if no guest gfn has been specified to host the ring via an hvm param
 *  EINVAL if the gfn for the ring has not been populated
 *  ENOENT if the gfn for the ring is paged out, or cannot be unshared
 *  EINVAL if the gfn for the ring cannot be written to
 *  EINVAL if the domain is dying
 *  ENOSPC if an event channel cannot be allocated for the ring
 *  ENOMEM if memory cannot be allocated for internal data structures
 *  EINVAL or EACCESS if the request is denied by the security policy
 */

int xc_memshr_ring_enable(xc_interface *xch, 
                          uint32_t domid,
                          uint32_t *port);
/* Disable the ring for ENOMEM communication.
 * May fail with EINVAL if the ring was not enabled in the first place.
 */
int xc_memshr_ring_disable(xc_interface *xch, 
                           uint32_t domid);

/*
 * Calls below return EINVAL if sharing has not been enabled for the domain
 * Calls below return EINVAL if the domain is dying
 */
/* Once a reponse to an ENOMEM notification is prepared, the tool can
 * notify the hypervisor to re-schedule the faulting vcpu of the domain with an
 * event channel kick and/or this call. */
int xc_memshr_domain_resume(xc_interface *xch,
                            uint32_t domid);

/* Select a page for sharing. 
 *
 * A 64 bit opaque handle will be stored in handle.  The hypervisor ensures
 * that if the page is modified, the handle will be invalidated, and future
 * users of it will fail. If the page has already been selected and is still
 * associated to a valid handle, the existing handle will be returned.
 *
 * May fail with:
 *  EINVAL if the gfn is not populated or not sharable (mmio, etc)
 *  ENOMEM if internal data structures cannot be allocated
 *  E2BIG if the page is being referenced by other subsytems (e.g. qemu)
 *  ENOENT or EEXIST if there are internal hypervisor errors.
 */
int xc_memshr_nominate_gfn(xc_interface *xch,
                           uint32_t domid,
                           unsigned long gfn,
                           uint64_t *handle);
/* Same as above, but instead of a guest frame number, the input is a grant
 * reference provided by the guest.
 *
 * May fail with EINVAL if the grant reference is invalid.
 */
int xc_memshr_nominate_gref(xc_interface *xch,
                            uint32_t domid,
                            grant_ref_t gref,
                            uint64_t *handle);

/* The three calls below may fail with
 * 10 (or -XENMEM_SHARING_OP_S_HANDLE_INVALID) if the handle passed as source
 * is invalid.  
 * 9 (or -XENMEM_SHARING_OP_C_HANDLE_INVALID) if the handle passed as client is
 * invalid.
 */
/* Share two nominated guest pages.
 *
 * If the call succeeds, both pages will point to the same backing frame (or
 * mfn). The hypervisor will verify the handles are still valid, but it will
 * not perform any sanity checking on the contens of the pages (the selection
 * mechanism for sharing candidates is entirely up to the user-space tool).
 *
 * After successful sharing, the client handle becomes invalid. Both <domain,
 * gfn> tuples point to the same mfn with the same handle, the one specified as
 * source. Either 3-tuple can be specified later for further re-sharing. 
 */
int xc_memshr_share_gfns(xc_interface *xch,
                    uint32_t source_domain,
                    unsigned long source_gfn,
                    uint64_t source_handle,
                    uint32_t client_domain,
                    unsigned long client_gfn,
                    uint64_t client_handle);

/* Same as above, but share two grant references instead.
 *
 * May fail with EINVAL if either grant reference is invalid.
 */
int xc_memshr_share_grefs(xc_interface *xch,
                    uint32_t source_domain,
                    grant_ref_t source_gref,
                    uint64_t source_handle,
                    uint32_t client_domain,
                    grant_ref_t client_gref,
                    uint64_t client_handle);

/* Allows to add to the guest physmap of the client domain a shared frame
 * directly.
 *
 * May additionally fail with 
 *  9 (-XENMEM_SHARING_OP_C_HANDLE_INVALID) if the physmap entry for the gfn is
 *  not suitable.
 *  ENOMEM if internal data structures cannot be allocated.
 *  ENOENT if there is an internal hypervisor error.
 */
int xc_memshr_add_to_physmap(xc_interface *xch,
                    uint32_t source_domain,
                    unsigned long source_gfn,
                    uint64_t source_handle,
                    uint32_t client_domain,
                    unsigned long client_gfn);

/* Allows to deduplicate a range of memory of a client domain. Using
 * this function is equivalent of calling xc_memshr_nominate_gfn for each gfn
 * in the two domains followed by xc_memshr_share_gfns.
 *
 * May fail with -EINVAL if the source and client domain have different
 * memory size or if memory sharing is not enabled on either of the domains.
 * May also fail with -ENOMEM if there isn't enough memory available to store
 * the sharing metadata before deduplication can happen.
 */
int xc_memshr_range_share(xc_interface *xch,
                          uint32_t source_domain,
                          uint32_t client_domain,
                          uint64_t first_gfn,
                          uint64_t last_gfn);

/* Debug calls: return the number of pages referencing the shared frame backing
 * the input argument. Should be one or greater. 
 *
 * May fail with EINVAL if there is no backing shared frame for the input
 * argument.
 */
int xc_memshr_debug_gfn(xc_interface *xch,
                        uint32_t domid,
                        unsigned long gfn);
/* May additionally fail with EINVAL if the grant reference is invalid. */
int xc_memshr_debug_gref(xc_interface *xch,
                         uint32_t domid,
                         grant_ref_t gref);

/* Audits the share subsystem. 
 * 
 * Returns ENOSYS if not supported (may not be compiled into the hypervisor). 
 *
 * Returns the number of errors found during auditing otherwise. May be (should
 * be!) zero.
 *
 * If debugtrace support has been compiled into the hypervisor and is enabled,
 * verbose descriptions for the errors are available in the hypervisor console.
 */
int xc_memshr_audit(xc_interface *xch);

/* Stats reporting.
 *
 * At any point in time, the following equality should hold for a host:
 *
 *  Let dominfo(d) be the xc_dominfo_t struct filled by a call to
 *  xc_domain_getinfo(d)
 *
 *  The summation of dominfo(d)->shr_pages for all domains in the system
 *      should be equal to
 *  xc_sharing_freed_pages + xc_sharing_used_frames
 */
/*
 * This function returns the total number of pages freed by using sharing
 * on the system.  For example, if two domains contain a single entry in
 * their p2m table that points to the same shared page (and no other pages
 * in the system are shared), then this function should return 1.
 */
long xc_sharing_freed_pages(xc_interface *xch);

/*
 * This function returns the total number of frames occupied by shared
 * pages on the system.  This is independent of the number of domains
 * pointing at these frames.  For example, in the above scenario this
 * should return 1. (And dominfo(d) for each of the two domains should return 1
 * as well).
 *
 * Note that some of these sharing_used_frames may be referenced by 
 * a single domain page, and thus not realize any savings. The same
 * applies to some of the pages counted in dominfo(d)->shr_pages.
 */
long xc_sharing_used_frames(xc_interface *xch);
/*** End sharing interface ***/

int xc_flask_load(xc_interface *xc_handle, char *buf, uint32_t size);
int xc_flask_context_to_sid(xc_interface *xc_handle, char *buf, uint32_t size, uint32_t *sid);
int xc_flask_sid_to_context(xc_interface *xc_handle, int sid, char *buf, uint32_t size);
int xc_flask_getenforce(xc_interface *xc_handle);
int xc_flask_setenforce(xc_interface *xc_handle, int mode);
int xc_flask_getbool_byid(xc_interface *xc_handle, int id, char *name, uint32_t size, int *curr, int *pend);
int xc_flask_getbool_byname(xc_interface *xc_handle, char *name, int *curr, int *pend);
int xc_flask_setbool(xc_interface *xc_handle, char *name, int value, int commit);
int xc_flask_add_pirq(xc_interface *xc_handle, unsigned int pirq, char *scontext);
int xc_flask_add_ioport(xc_interface *xc_handle, unsigned long low, unsigned long high,
                      char *scontext);
int xc_flask_add_iomem(xc_interface *xc_handle, unsigned long low, unsigned long high,
                     char *scontext);
int xc_flask_add_device(xc_interface *xc_handle, unsigned long device, char *scontext);
int xc_flask_del_pirq(xc_interface *xc_handle, unsigned int pirq);
int xc_flask_del_ioport(xc_interface *xc_handle, unsigned long low, unsigned long high);
int xc_flask_del_iomem(xc_interface *xc_handle, unsigned long low, unsigned long high);
int xc_flask_del_device(xc_interface *xc_handle, unsigned long device);
int xc_flask_access(xc_interface *xc_handle, const char *scon, const char *tcon,
                  uint16_t tclass, uint32_t req,
                  uint32_t *allowed, uint32_t *decided,
                  uint32_t *auditallow, uint32_t *auditdeny,
                  uint32_t *seqno);
int xc_flask_avc_cachestats(xc_interface *xc_handle, char *buf, int size);
int xc_flask_policyvers(xc_interface *xc_handle);
int xc_flask_avc_hashstats(xc_interface *xc_handle, char *buf, int size);
int xc_flask_getavc_threshold(xc_interface *xc_handle);
int xc_flask_setavc_threshold(xc_interface *xc_handle, int threshold);
int xc_flask_relabel_domain(xc_interface *xch, uint32_t domid, uint32_t sid);

struct elf_binary;
void xc_elf_set_logfile(xc_interface *xch, struct elf_binary *elf,
                        int verbose);
/* Useful for callers who also use libelf. */

/**
 * Checkpoint Compression
 */
typedef struct compression_ctx comp_ctx;
comp_ctx *xc_compression_create_context(xc_interface *xch,
					unsigned long p2m_size);
void xc_compression_free_context(xc_interface *xch, comp_ctx *ctx);

/**
 * Add a page to compression page buffer, to be compressed later.
 *
 * returns 0 if the page was successfully added to the page buffer
 *
 * returns -1 if there is no space in buffer. In this case, the
 *  application should call xc_compression_compress_pages to compress
 *  the buffer (or atleast part of it), thereby freeing some space in
 *  the page buffer.
 *
 * returns -2 if the pfn is out of bounds, where the bound is p2m_size
 *  parameter passed during xc_compression_create_context.
 */
int xc_compression_add_page(xc_interface *xch, comp_ctx *ctx, char *page,
			    unsigned long pfn, int israw);

/**
 * Delta compress pages in the compression buffer and inserts the
 * compressed data into the supplied compression buffer compbuf, whose
 * size is compbuf_size.
 * After compression, the pages are copied to the internal LRU cache.
 *
 * This function compresses as many pages as possible into the
 * supplied compression buffer. It maintains an internal iterator to
 * keep track of pages in the input buffer that are yet to be compressed.
 *
 * returns -1 if the compression buffer has run out of space.  
 * returns 1 on success.
 * returns 0 if no more pages are left to be compressed.
 *  When the return value is non-zero, compbuf_len indicates the actual
 *  amount of data present in compbuf (<=compbuf_size).
 */
int xc_compression_compress_pages(xc_interface *xch, comp_ctx *ctx,
				  char *compbuf, unsigned long compbuf_size,
				  unsigned long *compbuf_len);

/**
 * Resets the internal page buffer that holds dirty pages before compression.
 * Also resets the iterators.
 */
void xc_compression_reset_pagebuf(xc_interface *xch, comp_ctx *ctx);

/**
 * Caller must supply the compression buffer (compbuf),
 * its size (compbuf_size) and a reference to index variable (compbuf_pos)
 * that is used internally. Each call pulls out one page from the compressed
 * chunk and copies it to dest.
 */
int xc_compression_uncompress_page(xc_interface *xch, char *compbuf,
				   unsigned long compbuf_size,
				   unsigned long *compbuf_pos, char *dest);

/*
 * Execute an image previously loaded with xc_kexec_load().
 *
 * Does not return on success.
 *
 * Fails with:
 *   ENOENT if the specified image has not been loaded.
 */
int xc_kexec_exec(xc_interface *xch, int type);

/*
 * Find the machine address and size of certain memory areas.
 *
 *   KEXEC_RANGE_MA_CRASH       crash area
 *   KEXEC_RANGE_MA_XEN         Xen itself
 *   KEXEC_RANGE_MA_CPU         CPU note for CPU number 'nr'
 *   KEXEC_RANGE_MA_XENHEAP     xenheap
 *   KEXEC_RANGE_MA_EFI_MEMMAP  EFI Memory Map
 *   KEXEC_RANGE_MA_VMCOREINFO  vmcoreinfo
 *
 * Fails with:
 *   EINVAL if the range or CPU number isn't valid.
 */
int xc_kexec_get_range(xc_interface *xch, int range,  int nr,
                       uint64_t *size, uint64_t *start);

/*
 * Load a kexec image into memory.
 *
 * The image may be of type KEXEC_TYPE_DEFAULT (executed on request)
 * or KEXEC_TYPE_CRASH (executed on a crash).
 *
 * The image architecture may be a 32-bit variant of the hypervisor
 * architecture (e.g, EM_386 on a x86-64 hypervisor).
 *
 * Fails with:
 *   ENOMEM if there is insufficient memory for the new image.
 *   EINVAL if the image does not fit into the crash area or the entry
 *          point isn't within one of segments.
 *   EBUSY  if another image is being executed.
 */
int xc_kexec_load(xc_interface *xch, uint8_t type, uint16_t arch,
                  uint64_t entry_maddr,
                  uint32_t nr_segments, xen_kexec_segment_t *segments);

/*
 * Unload a kexec image.
 *
 * This prevents a KEXEC_TYPE_DEFAULT or KEXEC_TYPE_CRASH image from
 * being executed.  The crash images are not cleared from the crash
 * region.
 */
int xc_kexec_unload(xc_interface *xch, int type);

/*
 * Find out whether the image has been succesfully loaded.
 *
 * The type can be either KEXEC_TYPE_DEFAULT or KEXEC_TYPE_CRASH.
 * If zero is returned, that means no image is loaded for the type.
 * If one is returned, that means an image is loaded for the type.
 * Otherwise, negative return value indicates error.
 */
int xc_kexec_status(xc_interface *xch, int type);

typedef xenpf_resource_entry_t xc_resource_entry_t;

/*
 * Generic resource operation which contains multiple non-preemptible
 * resource access entries that passed to xc_resource_op().
 */
struct xc_resource_op {
    uint64_t result;        /* on return, check this field first */
    uint32_t cpu;           /* which cpu to run */
    uint32_t nr_entries;    /* number of resource entries */
    xc_resource_entry_t *entries;
};

typedef struct xc_resource_op xc_resource_op_t;
int xc_resource_op(xc_interface *xch, uint32_t nr_ops, xc_resource_op_t *ops);

#if defined(__i386__) || defined(__x86_64__)
enum xc_psr_cmt_type {
    XC_PSR_CMT_L3_OCCUPANCY,
    XC_PSR_CMT_TOTAL_MEM_COUNT,
    XC_PSR_CMT_LOCAL_MEM_COUNT,
};
typedef enum xc_psr_cmt_type xc_psr_cmt_type;

enum xc_psr_type {
    XC_PSR_CAT_L3_CBM      = 1,
    XC_PSR_CAT_L3_CBM_CODE = 2,
    XC_PSR_CAT_L3_CBM_DATA = 3,
    XC_PSR_CAT_L2_CBM      = 4,
    XC_PSR_MBA_THRTL       = 5,
};
typedef enum xc_psr_type xc_psr_type;

enum xc_psr_feat_type {
    XC_PSR_CAT_L3,
    XC_PSR_CAT_L2,
    XC_PSR_MBA,
};
typedef enum xc_psr_feat_type xc_psr_feat_type;

union xc_psr_hw_info {
    struct {
        uint32_t cos_max;
        uint32_t cbm_len;
        bool     cdp_enabled;
    } cat;

    struct {
        uint32_t cos_max;
        uint32_t thrtl_max;
        bool     linear;
    } mba;
};
typedef union xc_psr_hw_info xc_psr_hw_info;

int xc_psr_cmt_attach(xc_interface *xch, uint32_t domid);
int xc_psr_cmt_detach(xc_interface *xch, uint32_t domid);
int xc_psr_cmt_get_domain_rmid(xc_interface *xch, uint32_t domid,
                               uint32_t *rmid);
int xc_psr_cmt_get_total_rmid(xc_interface *xch, uint32_t *total_rmid);
int xc_psr_cmt_get_l3_upscaling_factor(xc_interface *xch,
                                       uint32_t *upscaling_factor);
int xc_psr_cmt_get_l3_event_mask(xc_interface *xch, uint32_t *event_mask);
int xc_psr_cmt_get_l3_cache_size(xc_interface *xch, uint32_t cpu,
                                 uint32_t *l3_cache_size);
int xc_psr_cmt_get_data(xc_interface *xch, uint32_t rmid, uint32_t cpu,
                        uint32_t psr_cmt_type, uint64_t *monitor_data,
                        uint64_t *tsc);
int xc_psr_cmt_enabled(xc_interface *xch);

int xc_psr_set_domain_data(xc_interface *xch, uint32_t domid,
                           xc_psr_type type, uint32_t target,
                           uint64_t data);
int xc_psr_get_domain_data(xc_interface *xch, uint32_t domid,
                           xc_psr_type type, uint32_t target,
                           uint64_t *data);
int xc_psr_get_hw_info(xc_interface *xch, uint32_t socket,
                       xc_psr_feat_type type, xc_psr_hw_info *hw_info);

int xc_get_cpu_levelling_caps(xc_interface *xch, uint32_t *caps);
int xc_get_cpu_featureset(xc_interface *xch, uint32_t index,
                          uint32_t *nr_features, uint32_t *featureset);

uint32_t xc_get_cpu_featureset_size(void);

enum xc_static_cpu_featuremask {
    XC_FEATUREMASK_KNOWN,
    XC_FEATUREMASK_SPECIAL,
    XC_FEATUREMASK_PV,
    XC_FEATUREMASK_HVM_SHADOW,
    XC_FEATUREMASK_HVM_HAP,
    XC_FEATUREMASK_DEEP_FEATURES,
};
const uint32_t *xc_get_static_cpu_featuremask(enum xc_static_cpu_featuremask);
const uint32_t *xc_get_feature_deep_deps(uint32_t feature);

#endif

int xc_livepatch_upload(xc_interface *xch,
                        char *name, unsigned char *payload, uint32_t size);

int xc_livepatch_get(xc_interface *xch,
                     char *name,
                     xen_livepatch_status_t *status);

/*
 * The heart of this function is to get an array of xen_livepatch_status_t.
 *
 * However it is complex because it has to deal with the hypervisor
 * returning some of the requested data or data being stale
 * (another hypercall might alter the list).
 *
 * The parameters that the function expects to contain data from
 * the hypervisor are: 'info', 'name', and 'len'. The 'done' and
 * 'left' are also updated with the number of entries filled out
 * and respectively the number of entries left to get from hypervisor.
 *
 * It is expected that the caller of this function will take the
 * 'left' and use the value for 'start'. This way we have an
 * cursor in the array. Note that the 'info','name', and 'len' will
 * be updated at the subsequent calls.
 *
 * The 'max' is to be provided by the caller with the maximum
 * number of entries that 'info', 'name', and 'len' arrays can
 * be filled up with.
 *
 * Each entry in the 'name' array is expected to be of XEN_LIVEPATCH_NAME_SIZE
 * length.
 *
 * Each entry in the 'info' array is expected to be of xen_livepatch_status_t
 * structure size.
 *
 * Each entry in the 'len' array is expected to be of uint32_t size.
 *
 * The return value is zero if the hypercall completed successfully.
 * Note that the return value is _not_ the amount of entries filled
 * out - that is saved in 'done'.
 *
 * If there was an error performing the operation, the return value
 * will contain an negative -EXX type value. The 'done' and 'left'
 * will contain the number of entries that had been succesfully
 * retrieved (if any).
 */
int xc_livepatch_list(xc_interface *xch, unsigned int max, unsigned int start,
                      xen_livepatch_status_t *info, char *name,
                      uint32_t *len, unsigned int *done,
                      unsigned int *left);

/*
 * The operations are asynchronous and the hypervisor may take a while
 * to complete them. The `timeout` offers an option to expire the
 * operation if it could not be completed within the specified time
 * (in ns). Value of 0 means let hypervisor decide the best timeout.
 */
int xc_livepatch_apply(xc_interface *xch, char *name, uint32_t timeout);
int xc_livepatch_revert(xc_interface *xch, char *name, uint32_t timeout);
int xc_livepatch_unload(xc_interface *xch, char *name, uint32_t timeout);
int xc_livepatch_replace(xc_interface *xch, char *name, uint32_t timeout);

/*
 * Ensure cache coherency after memory modifications. A call to this function
 * is only required on ARM as the x86 architecture provides cache coherency
 * guarantees. Calling this function on x86 is allowed but has no effect.
 */
int xc_domain_cacheflush(xc_interface *xch, uint32_t domid,
                         xen_pfn_t start_pfn, xen_pfn_t nr_pfns);

/* Compat shims */
#include "xenctrl_compat.h"

#endif /* XENCTRL_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
