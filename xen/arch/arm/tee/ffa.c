/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * xen/arch/arm/tee/ffa.c
 *
 * Arm Firmware Framework for ARMv8-A (FF-A) mediator
 *
 * Copyright (C) 2023  Linaro Limited
 *
 * References:
 * FF-A-1.0-REL: FF-A specification version 1.0 available at
 *               https://developer.arm.com/documentation/den0077/a
 * FF-A-1.1-REL0: FF-A specification version 1.1 available at
 *                https://developer.arm.com/documentation/den0077/e
 * TEEC-1.0C: TEE Client API Specification version 1.0c available at
 *            https://globalplatform.org/specs-library/tee-client-api-specification/
 *
 * Notes on the the current implementation.
 *
 * Unsupported FF-A interfaces:
 * o FFA_MSG_POLL and FFA_MSG_SEND - deprecated in FF-A-1.1-REL0
 * o FFA_MEM_RETRIEVE_* - Used when sharing memory from an SP to a VM
 * o FFA_MEM_DONATE_* and FFA_MEM_LEND_* - Used when tranferring ownership
 *   or access of a memory region
 * o FFA_MSG_SEND2 and FFA_MSG_WAIT - Used for indirect messaging
 * o FFA_MSG_YIELD
 * o FFA_INTERRUPT - Used to report preemption
 * o FFA_RUN
 *
 * Limitations in the implemented FF-A interfaces:
 * o FFA_RXTX_MAP_*:
 *   - Maps only one 4k page as RX and TX buffers
 *   - Doesn't support forwarding this call on behalf of an endpoint
 * o FFA_MEM_SHARE_*: only supports sharing
 *   - from a VM to an SP
 *   - with one borrower
 *   - with the memory transaction descriptor in the RX/TX buffer
 *   - normal memory
 *   - at most 512 kB large memory regions
 *   - at most 32 shared memory regions per guest
 * o FFA_MSG_SEND_DIRECT_REQ:
 *   - only supported from a VM to an SP
 *
 * There are some large locked sections with ffa_tx_buffer_lock and
 * ffa_rx_buffer_lock. Especially the ffa_tx_buffer_lock spinlock used
 * around share_shm() is a very large locked section which can let one VM
 * affect another VM.
 */

#include <xen/bitops.h>
#include <xen/domain_page.h>
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <xen/sizes.h>
#include <xen/types.h>

#include <asm/event.h>
#include <asm/regs.h>
#include <asm/smccc.h>
#include <asm/tee/ffa.h>
#include <asm/tee/tee.h>

/* Error codes */
#define FFA_RET_OK                      0
#define FFA_RET_NOT_SUPPORTED           -1
#define FFA_RET_INVALID_PARAMETERS      -2
#define FFA_RET_NO_MEMORY               -3
#define FFA_RET_BUSY                    -4
#define FFA_RET_INTERRUPTED             -5
#define FFA_RET_DENIED                  -6
#define FFA_RET_RETRY                   -7
#define FFA_RET_ABORTED                 -8

/* FFA_VERSION helpers */
#define FFA_VERSION_MAJOR_SHIFT         16U
#define FFA_VERSION_MAJOR_MASK          0x7FFFU
#define FFA_VERSION_MINOR_SHIFT         0U
#define FFA_VERSION_MINOR_MASK          0xFFFFU
#define MAKE_FFA_VERSION(major, minor)  \
        ((((major) & FFA_VERSION_MAJOR_MASK) << FFA_VERSION_MAJOR_SHIFT) | \
         ((minor) & FFA_VERSION_MINOR_MASK))

#define FFA_VERSION_1_0         MAKE_FFA_VERSION(1, 0)
#define FFA_VERSION_1_1         MAKE_FFA_VERSION(1, 1)
/* The minimal FF-A version of the SPMC that can be supported */
#define FFA_MIN_SPMC_VERSION    FFA_VERSION_1_1

/*
 * This is the version we want to use in communication with guests and SPs.
 * During negotiation with a guest or a SP we may need to lower it for
 * that particular guest or SP.
 */
#define FFA_MY_VERSION_MAJOR    1U
#define FFA_MY_VERSION_MINOR    1U
#define FFA_MY_VERSION          MAKE_FFA_VERSION(FFA_MY_VERSION_MAJOR, \
                                                 FFA_MY_VERSION_MINOR)

/*
 * The FF-A specification explicitly works with 4K pages as a measure of
 * memory size, for example, FFA_RXTX_MAP takes one parameter "RX/TX page
 * count" which is the number of contiguous 4K pages allocated. Xen may use
 * a different page size depending on the configuration to avoid confusion
 * with PAGE_SIZE use a special define when it's a page size as in the FF-A
 * specification.
 */
#define FFA_PAGE_SIZE                   SZ_4K

/*
 * The number of pages used for each of the RX and TX buffers shared with
 * the SPMC.
 */
#define FFA_RXTX_PAGE_COUNT             1

/*
 * Limit the number of pages RX/TX buffers guests can map.
 * TODO support a larger number.
 */
#define FFA_MAX_RXTX_PAGE_COUNT         1

/*
 * Limit for shared buffer size. Please note that this define limits
 * number of pages.
 *
 * FF-A doesn't have any direct requirements on GlobalPlatform or vice
 * versa, but an implementation can very well use FF-A in order to provide
 * a GlobalPlatform interface on top.
 *
 * Global Platform specification for TEE requires that any TEE
 * implementation should allow to share buffers with size of at least
 * 512KB, defined in TEEC-1.0C page 24, Table 4-1,
 * TEEC_CONFIG_SHAREDMEM_MAX_SIZE.
 * Due to overhead which can be hard to predict exactly, double this number
 * to give a safe margin.
 */
#define FFA_MAX_SHM_PAGE_COUNT          (2 * SZ_512K / FFA_PAGE_SIZE)

/*
 * Limits the number of shared buffers that guest can have at once. This
 * is to prevent case, when guests trick XEN into exhausting its own
 * memory by allocating many small buffers. This value has been chosen
 * arbitrarily.
 */
#define FFA_MAX_SHM_COUNT               32

/* FF-A-1.1-REL0 section 10.9.2 Memory region handle, page 167 */
#define FFA_HANDLE_HYP_FLAG             BIT(63, ULL)
#define FFA_HANDLE_INVALID              0xffffffffffffffffULL

/*
 * Memory attributes: Normal memory, Write-Back cacheable, Inner shareable
 * Defined in FF-A-1.1-REL0 Table 10.18 at page 175.
 */
#define FFA_NORMAL_MEM_REG_ATTR         0x2fU
/*
 * Memory access permissions: Read-write
 * Defined in FF-A-1.1-REL0 Table 10.15 at page 168.
 */
#define FFA_MEM_ACC_RW                  0x2U

/* FF-A-1.1-REL0 section 10.11.4 Flags usage, page 184-187 */
/* Clear memory before mapping in receiver */
#define FFA_MEMORY_REGION_FLAG_CLEAR            BIT(0, U)
/* Relayer may time slice this operation */
#define FFA_MEMORY_REGION_FLAG_TIME_SLICE       BIT(1, U)
/* Clear memory after receiver relinquishes it */
#define FFA_MEMORY_REGION_FLAG_CLEAR_RELINQUISH BIT(2, U)
/* Share memory transaction */
#define FFA_MEMORY_REGION_TRANSACTION_TYPE_SHARE (1U << 3)

/*
 * Flags and field values used for the MSG_SEND_DIRECT_REQ/RESP:
 * BIT(31): Framework or partition message
 * BIT(7-0): Message type for frameworks messages
 */
#define FFA_MSG_FLAG_FRAMEWORK          BIT(31, U)
#define FFA_MSG_TYPE_MASK               0xFFU;
#define FFA_MSG_PSCI                    0x0U
#define FFA_MSG_SEND_VM_CREATED         0x4U
#define FFA_MSG_RESP_VM_CREATED         0x5U
#define FFA_MSG_SEND_VM_DESTROYED       0x6U
#define FFA_MSG_RESP_VM_DESTROYED       0x7U

/*
 * Flags to determine partition properties in FFA_PARTITION_INFO_GET return
 * message:
 * BIT(0): Supports receipt of direct requests
 * BIT(1): Can send direct requests
 * BIT(2): Can send and receive indirect messages
 * BIT(3): Supports receipt of notifications
 * BIT(4-5): Partition ID is a PE endpoint ID
 * BIT(6): Partition must be informed about each VM that is created by
 *         the Hypervisor
 * BIT(7): Partition must be informed about each VM that is destroyed by
 *         the Hypervisor
 * BIT(8): Partition runs in the AArch64 execution state else AArch32
 *         execution state
 */
#define FFA_PART_PROP_DIRECT_REQ_RECV   BIT(0, U)
#define FFA_PART_PROP_DIRECT_REQ_SEND   BIT(1, U)
#define FFA_PART_PROP_INDIRECT_MSGS     BIT(2, U)
#define FFA_PART_PROP_RECV_NOTIF        BIT(3, U)
#define FFA_PART_PROP_IS_TYPE_MASK      (3U << 4)
#define FFA_PART_PROP_IS_PE_ID          (0U << 4)
#define FFA_PART_PROP_IS_SEPID_INDEP    (1U << 4)
#define FFA_PART_PROP_IS_SEPID_DEP      (2U << 4)
#define FFA_PART_PROP_IS_AUX_ID         (3U << 4)
#define FFA_PART_PROP_NOTIF_CREATED     BIT(6, U)
#define FFA_PART_PROP_NOTIF_DESTROYED   BIT(7, U)
#define FFA_PART_PROP_AARCH64_STATE     BIT(8, U)

/*
 * Flag used as parameter to FFA_PARTITION_INFO_GET to return partition
 * count only.
 */
#define FFA_PARTITION_INFO_GET_COUNT_FLAG BIT(0, U)

/* Function IDs */
#define FFA_ERROR                       0x84000060U
#define FFA_SUCCESS_32                  0x84000061U
#define FFA_SUCCESS_64                  0xC4000061U
#define FFA_INTERRUPT                   0x84000062U
#define FFA_VERSION                     0x84000063U
#define FFA_FEATURES                    0x84000064U
#define FFA_RX_ACQUIRE                  0x84000084U
#define FFA_RX_RELEASE                  0x84000065U
#define FFA_RXTX_MAP_32                 0x84000066U
#define FFA_RXTX_MAP_64                 0xC4000066U
#define FFA_RXTX_UNMAP                  0x84000067U
#define FFA_PARTITION_INFO_GET          0x84000068U
#define FFA_ID_GET                      0x84000069U
#define FFA_SPM_ID_GET                  0x84000085U
#define FFA_MSG_WAIT                    0x8400006BU
#define FFA_MSG_YIELD                   0x8400006CU
#define FFA_RUN                         0x8400006DU
#define FFA_MSG_SEND2                   0x84000086U
#define FFA_MSG_SEND_DIRECT_REQ_32      0x8400006FU
#define FFA_MSG_SEND_DIRECT_REQ_64      0xC400006FU
#define FFA_MSG_SEND_DIRECT_RESP_32     0x84000070U
#define FFA_MSG_SEND_DIRECT_RESP_64     0xC4000070U
#define FFA_MEM_DONATE_32               0x84000071U
#define FFA_MEM_DONATE_64               0xC4000071U
#define FFA_MEM_LEND_32                 0x84000072U
#define FFA_MEM_LEND_64                 0xC4000072U
#define FFA_MEM_SHARE_32                0x84000073U
#define FFA_MEM_SHARE_64                0xC4000073U
#define FFA_MEM_RETRIEVE_REQ_32         0x84000074U
#define FFA_MEM_RETRIEVE_REQ_64         0xC4000074U
#define FFA_MEM_RETRIEVE_RESP           0x84000075U
#define FFA_MEM_RELINQUISH              0x84000076U
#define FFA_MEM_RECLAIM                 0x84000077U
#define FFA_MEM_FRAG_RX                 0x8400007AU
#define FFA_MEM_FRAG_TX                 0x8400007BU
#define FFA_MSG_SEND                    0x8400006EU
#define FFA_MSG_POLL                    0x8400006AU

/*
 * Structs below ending with _1_0 are defined in FF-A-1.0-REL and
 * structs ending with _1_1 are defined in FF-A-1.1-REL0.
 */

/* Partition information descriptor */
struct ffa_partition_info_1_0 {
    uint16_t id;
    uint16_t execution_context;
    uint32_t partition_properties;
};

struct ffa_partition_info_1_1 {
    uint16_t id;
    uint16_t execution_context;
    uint32_t partition_properties;
    uint8_t uuid[16];
};

/* Constituent memory region descriptor */
struct ffa_address_range {
    uint64_t address;
    uint32_t page_count;
    uint32_t reserved;
};

/* Composite memory region descriptor */
struct ffa_mem_region {
    uint32_t total_page_count;
    uint32_t address_range_count;
    uint64_t reserved;
    struct ffa_address_range address_range_array[];
};

/* Memory access permissions descriptor */
struct ffa_mem_access_perm {
    uint16_t endpoint_id;
    uint8_t perm;
    uint8_t flags;
};

/* Endpoint memory access descriptor */
struct ffa_mem_access {
    struct ffa_mem_access_perm access_perm;
    uint32_t region_offs;
    uint64_t reserved;
};

/* Lend, donate or share memory transaction descriptor */
struct ffa_mem_transaction_1_0 {
    uint16_t sender_id;
    uint8_t mem_reg_attr;
    uint8_t reserved0;
    uint32_t flags;
    uint64_t handle;
    uint64_t tag;
    uint32_t reserved1;
    uint32_t mem_access_count;
    struct ffa_mem_access mem_access_array[];
};

struct ffa_mem_transaction_1_1 {
    uint16_t sender_id;
    uint16_t mem_reg_attr;
    uint32_t flags;
    uint64_t handle;
    uint64_t tag;
    uint32_t mem_access_size;
    uint32_t mem_access_count;
    uint32_t mem_access_offs;
    uint8_t reserved[12];
};

/* Calculate offset of struct ffa_mem_access from start of buffer */
#define MEM_ACCESS_OFFSET(access_idx) \
    ( sizeof(struct ffa_mem_transaction_1_1) + \
      ( access_idx ) * sizeof(struct ffa_mem_access) )

/* Calculate offset of struct ffa_mem_region from start of buffer */
#define REGION_OFFSET(access_count, region_idx) \
    ( MEM_ACCESS_OFFSET(access_count) + \
      ( region_idx ) * sizeof(struct ffa_mem_region) )

/* Calculate offset of struct ffa_address_range from start of buffer */
#define ADDR_RANGE_OFFSET(access_count, region_count, range_idx) \
    ( REGION_OFFSET(access_count, region_count) + \
      ( range_idx ) * sizeof(struct ffa_address_range) )

/*
 * The parts needed from struct ffa_mem_transaction_1_0 or struct
 * ffa_mem_transaction_1_1, used to provide an abstraction of difference in
 * data structures between version 1.0 and 1.1. This is just an internal
 * interface and can be changed without changing any ABI.
 */
struct ffa_mem_transaction_int {
    uint16_t sender_id;
    uint8_t mem_reg_attr;
    uint8_t flags;
    uint8_t mem_access_size;
    uint8_t mem_access_count;
    uint16_t mem_access_offs;
    uint64_t handle;
    uint64_t tag;
};

/* Endpoint RX/TX descriptor */
struct ffa_endpoint_rxtx_descriptor_1_0 {
    uint16_t sender_id;
    uint16_t reserved;
    uint32_t rx_range_count;
    uint32_t tx_range_count;
};

struct ffa_endpoint_rxtx_descriptor_1_1 {
    uint16_t sender_id;
    uint16_t reserved;
    uint32_t rx_region_offs;
    uint32_t tx_region_offs;
};

struct ffa_ctx {
    void *rx;
    const void *tx;
    struct page_info *rx_pg;
    struct page_info *tx_pg;
    /* Number of 4kB pages in each of rx/rx_pg and tx/tx_pg */
    unsigned int page_count;
    /* FF-A version used by the guest */
    uint32_t guest_vers;
    /*
     * Number of SPs that we have sent a VM created signal to, used in
     * ffa_domain_teardown() to know which SPs need to be signalled.
     */
    uint16_t create_signal_count;
    bool rx_is_free;
    /* Used shared memory objects, struct ffa_shm_mem */
    struct list_head shm_list;
    /* Number of allocated shared memory object */
    unsigned int shm_count;
    /*
     * tx_lock is used to serialize access to tx
     * rx_lock is used to serialize access to rx
     * lock is used for the rest in this struct
     */
    spinlock_t tx_lock;
    spinlock_t rx_lock;
    spinlock_t lock;
};

struct ffa_shm_mem {
    struct list_head list;
    uint16_t sender_id;
    uint16_t ep_id;     /* endpoint, the one lending */
    uint64_t handle;    /* FFA_HANDLE_INVALID if not set yet */
    unsigned int page_count;
    struct page_info *pages[];
};

/* Negotiated FF-A version to use with the SPMC */
static uint32_t __ro_after_init ffa_version;

/* SPs subscribing to VM_CREATE and VM_DESTROYED events */
static uint16_t *subscr_vm_created __read_mostly;
static uint16_t subscr_vm_created_count __read_mostly;
static uint16_t *subscr_vm_destroyed __read_mostly;
static uint16_t subscr_vm_destroyed_count __read_mostly;

/*
 * Our rx/tx buffers shared with the SPMC. FFA_RXTX_PAGE_COUNT is the
 * number of pages used in each of these buffers.
 *
 * The RX buffer is protected from concurrent usage with ffa_rx_buffer_lock.
 * Note that the SPMC is also tracking the ownership of our RX buffer so
 * for calls which uses our RX buffer to deliver a result we must call
 * ffa_rx_release() to let the SPMC know that we're done with the buffer.
 */
static void *ffa_rx __read_mostly;
static void *ffa_tx __read_mostly;
static DEFINE_SPINLOCK(ffa_rx_buffer_lock);
static DEFINE_SPINLOCK(ffa_tx_buffer_lock);

static bool ffa_get_version(uint32_t *vers)
{
    const struct arm_smccc_1_2_regs arg = {
        .a0 = FFA_VERSION,
        .a1 = FFA_MY_VERSION,
    };
    struct arm_smccc_1_2_regs resp;

    arm_smccc_1_2_smc(&arg, &resp);
    if ( resp.a0 == FFA_RET_NOT_SUPPORTED )
    {
        gprintk(XENLOG_ERR, "ffa: FFA_VERSION returned not supported\n");
        return false;
    }

    *vers = resp.a0;

    return true;
}

static int32_t get_ffa_ret_code(const struct arm_smccc_1_2_regs *resp)
{
    switch ( resp->a0 )
    {
    case FFA_ERROR:
        if ( resp->a2 )
            return resp->a2;
        else
            return FFA_RET_NOT_SUPPORTED;
    case FFA_SUCCESS_32:
    case FFA_SUCCESS_64:
        return FFA_RET_OK;
    default:
        return FFA_RET_NOT_SUPPORTED;
    }
}

static int32_t ffa_simple_call(uint32_t fid, register_t a1, register_t a2,
                               register_t a3, register_t a4)
{
    const struct arm_smccc_1_2_regs arg = {
        .a0 = fid,
        .a1 = a1,
        .a2 = a2,
        .a3 = a3,
        .a4 = a4,
    };
    struct arm_smccc_1_2_regs resp;

    arm_smccc_1_2_smc(&arg, &resp);

    return get_ffa_ret_code(&resp);
}

static int32_t ffa_features(uint32_t id)
{
    return ffa_simple_call(FFA_FEATURES, id, 0, 0, 0);
}

static bool check_mandatory_feature(uint32_t id)
{
    int32_t ret = ffa_features(id);

    if ( ret )
        printk(XENLOG_ERR "ffa: mandatory feature id %#x missing: error %d\n",
               id, ret);

    return !ret;
}

static int32_t ffa_rxtx_map(paddr_t tx_addr, paddr_t rx_addr,
                            uint32_t page_count)
{
    return ffa_simple_call(FFA_RXTX_MAP_64, tx_addr, rx_addr, page_count, 0);
}

static int32_t ffa_partition_info_get(uint32_t w1, uint32_t w2, uint32_t w3,
                                      uint32_t w4, uint32_t w5,
                                      uint32_t *count)
{
    const struct arm_smccc_1_2_regs arg = {
        .a0 = FFA_PARTITION_INFO_GET,
        .a1 = w1,
        .a2 = w2,
        .a3 = w3,
        .a4 = w4,
        .a5 = w5,
    };
    struct arm_smccc_1_2_regs resp;
    uint32_t ret;

    arm_smccc_1_2_smc(&arg, &resp);

    ret = get_ffa_ret_code(&resp);
    if ( !ret )
        *count = resp.a2;

    return ret;
}

static int32_t ffa_rx_release(void)
{
    return ffa_simple_call(FFA_RX_RELEASE, 0, 0, 0, 0);
}

static int32_t ffa_mem_share(uint32_t tot_len, uint32_t frag_len,
                             register_t addr, uint32_t pg_count,
                             uint64_t *handle)
{
    struct arm_smccc_1_2_regs arg = {
        .a0 = FFA_MEM_SHARE_64,
        .a1 = tot_len,
        .a2 = frag_len,
        .a3 = addr,
        .a4 = pg_count,
    };
    struct arm_smccc_1_2_regs resp;

    arm_smccc_1_2_smc(&arg, &resp);

    switch ( resp.a0 )
    {
    case FFA_ERROR:
        if ( resp.a2 )
            return resp.a2;
        else
            return FFA_RET_NOT_SUPPORTED;
    case FFA_SUCCESS_32:
        *handle = regpair_to_uint64(resp.a3, resp.a2);
        return FFA_RET_OK;
    case FFA_MEM_FRAG_RX:
        *handle = regpair_to_uint64(resp.a2, resp.a1);
        if ( resp.a3 > INT32_MAX ) /* Impossible value */
            return FFA_RET_ABORTED;
        return resp.a3 & INT32_MAX;
    default:
        return FFA_RET_NOT_SUPPORTED;
    }
}

static int32_t ffa_mem_reclaim(uint32_t handle_lo, uint32_t handle_hi,
                               uint32_t flags)
{
    return ffa_simple_call(FFA_MEM_RECLAIM, handle_lo, handle_hi, flags, 0);
}

static int32_t ffa_direct_req_send_vm(uint16_t sp_id, uint16_t vm_id,
                                      uint8_t msg)
{
    uint32_t exp_resp = FFA_MSG_FLAG_FRAMEWORK;
    unsigned int retry_count = 0;
    int32_t res;

    if ( msg == FFA_MSG_SEND_VM_CREATED )
        exp_resp |= FFA_MSG_RESP_VM_CREATED;
    else if ( msg == FFA_MSG_SEND_VM_DESTROYED )
        exp_resp |= FFA_MSG_RESP_VM_DESTROYED;
    else
        return FFA_RET_INVALID_PARAMETERS;

    do {
        const struct arm_smccc_1_2_regs arg = {
            .a0 = FFA_MSG_SEND_DIRECT_REQ_32,
            .a1 = sp_id,
            .a2 = FFA_MSG_FLAG_FRAMEWORK | msg,
            .a5 = vm_id,
        };
        struct arm_smccc_1_2_regs resp;

        arm_smccc_1_2_smc(&arg, &resp);
        if ( resp.a0 != FFA_MSG_SEND_DIRECT_RESP_32 || resp.a2 != exp_resp )
        {
            /*
             * This is an invalid response, likely due to some error in the
             * implementation of the ABI.
             */
            return FFA_RET_INVALID_PARAMETERS;
        }
        res = resp.a3;
        if ( ++retry_count > 10 )
        {
            /*
             * TODO
             * FFA_RET_INTERRUPTED means that the SPMC has a pending
             * non-secure interrupt, we need a way of delivering that
             * non-secure interrupt.
             * FFA_RET_RETRY is the SP telling us that it's temporarily
             * blocked from handling the direct request, we need a generic
             * way to deal with this.
             * For now in both cases, give up after a few retries.
             */
            return res;
        }
    } while ( res == FFA_RET_INTERRUPTED || res == FFA_RET_RETRY );

    return res;
}

static uint16_t get_vm_id(const struct domain *d)
{
    /* +1 since 0 is reserved for the hypervisor in FF-A */
    return d->domain_id + 1;
}

static void set_regs(struct cpu_user_regs *regs, register_t v0, register_t v1,
                     register_t v2, register_t v3, register_t v4, register_t v5,
                     register_t v6, register_t v7)
{
        set_user_reg(regs, 0, v0);
        set_user_reg(regs, 1, v1);
        set_user_reg(regs, 2, v2);
        set_user_reg(regs, 3, v3);
        set_user_reg(regs, 4, v4);
        set_user_reg(regs, 5, v5);
        set_user_reg(regs, 6, v6);
        set_user_reg(regs, 7, v7);
}

static void set_regs_error(struct cpu_user_regs *regs, uint32_t error_code)
{
    set_regs(regs, FFA_ERROR, 0, error_code, 0, 0, 0, 0, 0);
}

static void set_regs_success(struct cpu_user_regs *regs, uint32_t w2,
                             uint32_t w3)
{
    set_regs(regs, FFA_SUCCESS_32, 0, w2, w3, 0, 0, 0, 0);
}

static void handle_version(struct cpu_user_regs *regs)
{
    struct domain *d = current->domain;
    struct ffa_ctx *ctx = d->arch.tee;
    uint32_t vers = get_user_reg(regs, 1);

    if ( vers < FFA_VERSION_1_1 )
        vers = FFA_VERSION_1_0;
    else
        vers = FFA_VERSION_1_1;

    ctx->guest_vers = vers;
    set_regs(regs, vers, 0, 0, 0, 0, 0, 0, 0);
}

static uint32_t handle_rxtx_map(uint32_t fid, register_t tx_addr,
                                register_t rx_addr, uint32_t page_count)
{
    uint32_t ret = FFA_RET_INVALID_PARAMETERS;
    struct domain *d = current->domain;
    struct ffa_ctx *ctx = d->arch.tee;
    struct page_info *tx_pg;
    struct page_info *rx_pg;
    p2m_type_t t;
    void *rx;
    void *tx;

    if ( !smccc_is_conv_64(fid) )
    {
        /*
         * Calls using the 32-bit calling convention must ignore the upper
         * 32 bits in the argument registers.
         */
        tx_addr &= UINT32_MAX;
        rx_addr &= UINT32_MAX;
    }

    if ( page_count > FFA_MAX_RXTX_PAGE_COUNT )
    {
        printk(XENLOG_ERR "ffa: RXTX_MAP: error: %u pages requested (limit %u)\n",
               page_count, FFA_MAX_RXTX_PAGE_COUNT);
        return FFA_RET_INVALID_PARAMETERS;
    }

    /* Already mapped */
    if ( ctx->rx )
        return FFA_RET_DENIED;

    tx_pg = get_page_from_gfn(d, gfn_x(gaddr_to_gfn(tx_addr)), &t, P2M_ALLOC);
    if ( !tx_pg )
        return FFA_RET_INVALID_PARAMETERS;

    /* Only normal RW RAM for now */
    if ( t != p2m_ram_rw )
        goto err_put_tx_pg;

    rx_pg = get_page_from_gfn(d, gfn_x(gaddr_to_gfn(rx_addr)), &t, P2M_ALLOC);
    if ( !tx_pg )
        goto err_put_tx_pg;

    /* Only normal RW RAM for now */
    if ( t != p2m_ram_rw )
        goto err_put_rx_pg;

    tx = __map_domain_page_global(tx_pg);
    if ( !tx )
        goto err_put_rx_pg;

    rx = __map_domain_page_global(rx_pg);
    if ( !rx )
        goto err_unmap_tx;

    ctx->rx = rx;
    ctx->tx = tx;
    ctx->rx_pg = rx_pg;
    ctx->tx_pg = tx_pg;
    ctx->page_count = page_count;
    ctx->rx_is_free = true;
    return FFA_RET_OK;

err_unmap_tx:
    unmap_domain_page_global(tx);
err_put_rx_pg:
    put_page(rx_pg);
err_put_tx_pg:
    put_page(tx_pg);

    return ret;
}

static void rxtx_unmap(struct ffa_ctx *ctx)
{
    unmap_domain_page_global(ctx->rx);
    unmap_domain_page_global(ctx->tx);
    put_page(ctx->rx_pg);
    put_page(ctx->tx_pg);
    ctx->rx = NULL;
    ctx->tx = NULL;
    ctx->rx_pg = NULL;
    ctx->tx_pg = NULL;
    ctx->page_count = 0;
    ctx->rx_is_free = false;
}

static uint32_t handle_rxtx_unmap(void)
{
    struct domain *d = current->domain;
    struct ffa_ctx *ctx = d->arch.tee;

    if ( !ctx->rx )
        return FFA_RET_INVALID_PARAMETERS;

    rxtx_unmap(ctx);

    return FFA_RET_OK;
}

static int32_t handle_partition_info_get(uint32_t w1, uint32_t w2, uint32_t w3,
                                         uint32_t w4, uint32_t w5,
                                         uint32_t *count)
{
    int32_t ret = FFA_RET_DENIED;
    struct domain *d = current->domain;
    struct ffa_ctx *ctx = d->arch.tee;

    /*
     * FF-A v1.0 has w5 MBZ while v1.1 allows
     * FFA_PARTITION_INFO_GET_COUNT_FLAG to be non-zero.
     *
     * FFA_PARTITION_INFO_GET_COUNT is only using registers and not the
     * rxtx buffer so do the partition_info_get directly.
     */
    if ( w5 == FFA_PARTITION_INFO_GET_COUNT_FLAG &&
         ctx->guest_vers == FFA_VERSION_1_1 )
        return ffa_partition_info_get(w1, w2, w3, w4, w5, count);
    if ( w5 )
        return FFA_RET_INVALID_PARAMETERS;

    if ( !ffa_rx )
        return FFA_RET_DENIED;

    if ( !spin_trylock(&ctx->rx_lock) )
        return FFA_RET_BUSY;

    if ( !ctx->page_count || !ctx->rx_is_free )
        goto out;
    spin_lock(&ffa_rx_buffer_lock);
    ret = ffa_partition_info_get(w1, w2, w3, w4, w5, count);
    if ( ret )
        goto out_rx_buf_unlock;
    /*
     * ffa_partition_info_get() succeeded so we now own the RX buffer we
     * share with the SPMC. We must give it back using ffa_rx_release()
     * once we've copied the content.
     */

    if ( ctx->guest_vers == FFA_VERSION_1_0 )
    {
        size_t n;
        struct ffa_partition_info_1_1 *src = ffa_rx;
        struct ffa_partition_info_1_0 *dst = ctx->rx;

        if ( ctx->page_count * FFA_PAGE_SIZE < *count * sizeof(*dst) )
        {
            ret = FFA_RET_NO_MEMORY;
            goto out_rx_release;
        }

        for ( n = 0; n < *count; n++ )
        {
            dst[n].id = src[n].id;
            dst[n].execution_context = src[n].execution_context;
            dst[n].partition_properties = src[n].partition_properties;
        }
    }
    else
    {
        size_t sz = *count * sizeof(struct ffa_partition_info_1_1);

        if ( ctx->page_count * FFA_PAGE_SIZE < sz )
        {
            ret = FFA_RET_NO_MEMORY;
            goto out_rx_release;
        }


        memcpy(ctx->rx, ffa_rx, sz);
    }
    ctx->rx_is_free = false;
out_rx_release:
    ffa_rx_release();
out_rx_buf_unlock:
    spin_unlock(&ffa_rx_buffer_lock);
out:
    spin_unlock(&ctx->rx_lock);

    return ret;
}

static int32_t handle_rx_release(void)
{
    int32_t ret = FFA_RET_DENIED;
    struct domain *d = current->domain;
    struct ffa_ctx *ctx = d->arch.tee;

    if ( !spin_trylock(&ctx->rx_lock) )
        return FFA_RET_BUSY;

    if ( !ctx->page_count || ctx->rx_is_free )
        goto out;
    ret = FFA_RET_OK;
    ctx->rx_is_free = true;
out:
    spin_unlock(&ctx->rx_lock);

    return ret;
}

static void handle_msg_send_direct_req(struct cpu_user_regs *regs, uint32_t fid)
{
    struct arm_smccc_1_2_regs arg = { .a0 = fid, };
    struct arm_smccc_1_2_regs resp = { };
    struct domain *d = current->domain;
    uint32_t src_dst;
    uint64_t mask;

    if ( smccc_is_conv_64(fid) )
        mask = GENMASK_ULL(63, 0);
    else
        mask = GENMASK_ULL(31, 0);

    src_dst = get_user_reg(regs, 1);
    if ( (src_dst >> 16) != get_vm_id(d) )
    {
        resp.a0 = FFA_ERROR;
        resp.a2 = FFA_RET_INVALID_PARAMETERS;
        goto out;
    }

    arg.a1 = src_dst;
    arg.a2 = get_user_reg(regs, 2) & mask;
    arg.a3 = get_user_reg(regs, 3) & mask;
    arg.a4 = get_user_reg(regs, 4) & mask;
    arg.a5 = get_user_reg(regs, 5) & mask;
    arg.a6 = get_user_reg(regs, 6) & mask;
    arg.a7 = get_user_reg(regs, 7) & mask;

    arm_smccc_1_2_smc(&arg, &resp);
    switch ( resp.a0 )
    {
    case FFA_ERROR:
    case FFA_SUCCESS_32:
    case FFA_SUCCESS_64:
    case FFA_MSG_SEND_DIRECT_RESP_32:
    case FFA_MSG_SEND_DIRECT_RESP_64:
        break;
    default:
        /* Bad fid, report back to the caller. */
        memset(&resp, 0, sizeof(resp));
        resp.a0 = FFA_ERROR;
        resp.a1 = src_dst;
        resp.a2 = FFA_RET_ABORTED;
    }

out:
    set_regs(regs, resp.a0, resp.a1 & mask, resp.a2 & mask, resp.a3 & mask,
             resp.a4 & mask, resp.a5 & mask, resp.a6 & mask, resp.a7 & mask);
}

/*
 * Gets all page and assigns them to the supplied shared memory object. If
 * this function fails then the caller is still expected to call
 * put_shm_pages() as a cleanup.
 */
static int get_shm_pages(struct domain *d, struct ffa_shm_mem *shm,
                         const struct ffa_address_range *range,
                         uint32_t range_count, unsigned int start_page_idx,
                         unsigned int *last_page_idx)
{
    unsigned int pg_idx = start_page_idx;
    gfn_t gfn;
    unsigned int n;
    unsigned int m;
    p2m_type_t t;
    uint64_t addr;
    uint64_t page_count;

    for ( n = 0; n < range_count; n++ )
    {
        page_count = read_atomic(&range[n].page_count);
        addr = read_atomic(&range[n].address);
        for ( m = 0; m < page_count; m++ )
        {
            if ( pg_idx >= shm->page_count )
                return FFA_RET_INVALID_PARAMETERS;

            gfn = gaddr_to_gfn(addr + m * FFA_PAGE_SIZE);
            shm->pages[pg_idx] = get_page_from_gfn(d, gfn_x(gfn), &t,
						   P2M_ALLOC);
            if ( !shm->pages[pg_idx] )
                return FFA_RET_DENIED;
            /* Only normal RW RAM for now */
            if ( t != p2m_ram_rw )
                return FFA_RET_DENIED;
            pg_idx++;
        }
    }

    *last_page_idx = pg_idx;

    return FFA_RET_OK;
}

static void put_shm_pages(struct ffa_shm_mem *shm)
{
    unsigned int n;

    for ( n = 0; n < shm->page_count && shm->pages[n]; n++ )
    {
        put_page(shm->pages[n]);
        shm->pages[n] = NULL;
    }
}

static bool inc_ctx_shm_count(struct ffa_ctx *ctx)
{
    bool ret = true;

    spin_lock(&ctx->lock);
    if (ctx->shm_count >= FFA_MAX_SHM_COUNT)
        ret = false;
    else
        ctx->shm_count++;
    spin_unlock(&ctx->lock);

    return ret;
}

static void dec_ctx_shm_count(struct ffa_ctx *ctx)
{
    spin_lock(&ctx->lock);
    ASSERT(ctx->shm_count > 0);
    ctx->shm_count--;
    spin_unlock(&ctx->lock);
}

static struct ffa_shm_mem *alloc_ffa_shm_mem(struct ffa_ctx *ctx,
                                             unsigned int page_count)
{
    struct ffa_shm_mem *shm;

    if ( page_count >= FFA_MAX_SHM_PAGE_COUNT )
        return NULL;
    if ( !inc_ctx_shm_count(ctx) )
        return NULL;

    shm = xzalloc_flex_struct(struct ffa_shm_mem, pages, page_count);
    if ( shm )
        shm->page_count = page_count;
    else
        dec_ctx_shm_count(ctx);

    return shm;
}

static void free_ffa_shm_mem(struct ffa_ctx *ctx, struct ffa_shm_mem *shm)
{
    if ( !shm )
        return;

    dec_ctx_shm_count(ctx);
    put_shm_pages(shm);
    xfree(shm);
}

static void init_range(struct ffa_address_range *addr_range,
                       paddr_t pa)
{
    memset(addr_range, 0, sizeof(*addr_range));
    addr_range->address = pa;
    addr_range->page_count = 1;
}

/*
 * This function uses the ffa_tx buffer to transmit the memory transaction
 * descriptor. The function depends ffa_tx_buffer_lock to be used to guard
 * the buffer from concurrent use.
 */
static int share_shm(struct ffa_shm_mem *shm)
{
    const uint32_t max_frag_len = FFA_RXTX_PAGE_COUNT * FFA_PAGE_SIZE;
    struct ffa_mem_access *mem_access_array;
    struct ffa_mem_transaction_1_1 *descr;
    struct ffa_address_range *addr_range;
    struct ffa_mem_region *region_descr;
    const unsigned int region_count = 1;
    void *buf = ffa_tx;
    uint32_t frag_len;
    uint32_t tot_len;
    paddr_t last_pa;
    unsigned int n;
    paddr_t pa;

    ASSERT(spin_is_locked(&ffa_tx_buffer_lock));
    ASSERT(shm->page_count);

    descr = buf;
    memset(descr, 0, sizeof(*descr));
    descr->sender_id = shm->sender_id;
    descr->handle = shm->handle;
    descr->mem_reg_attr = FFA_NORMAL_MEM_REG_ATTR;
    descr->mem_access_count = 1;
    descr->mem_access_size = sizeof(*mem_access_array);
    descr->mem_access_offs = MEM_ACCESS_OFFSET(0);

    mem_access_array = buf + descr->mem_access_offs;
    memset(mem_access_array, 0, sizeof(*mem_access_array));
    mem_access_array[0].access_perm.endpoint_id = shm->ep_id;
    mem_access_array[0].access_perm.perm = FFA_MEM_ACC_RW;
    mem_access_array[0].region_offs = REGION_OFFSET(descr->mem_access_count, 0);

    region_descr = buf + mem_access_array[0].region_offs;
    memset(region_descr, 0, sizeof(*region_descr));
    region_descr->total_page_count = shm->page_count;

    region_descr->address_range_count = 1;
    last_pa = page_to_maddr(shm->pages[0]);
    for ( n = 1; n < shm->page_count; last_pa = pa, n++ )
    {
        pa = page_to_maddr(shm->pages[n]);
        if ( last_pa + FFA_PAGE_SIZE == pa )
            continue;
        region_descr->address_range_count++;
    }

    tot_len = ADDR_RANGE_OFFSET(descr->mem_access_count, region_count,
                                region_descr->address_range_count);
    if ( tot_len > max_frag_len )
        return FFA_RET_NOT_SUPPORTED;

    addr_range = region_descr->address_range_array;
    frag_len = ADDR_RANGE_OFFSET(descr->mem_access_count, region_count, 1);
    last_pa = page_to_maddr(shm->pages[0]);
    init_range(addr_range, last_pa);
    for ( n = 1; n < shm->page_count; last_pa = pa, n++ )
    {
        pa = page_to_maddr(shm->pages[n]);
        if ( last_pa + FFA_PAGE_SIZE == pa )
        {
            addr_range->page_count++;
            continue;
        }

        frag_len += sizeof(*addr_range);
        addr_range++;
        init_range(addr_range, pa);
    }

    return ffa_mem_share(tot_len, frag_len, 0, 0, &shm->handle);
}

static int read_mem_transaction(uint32_t ffa_vers, const void *buf, size_t blen,
                                struct ffa_mem_transaction_int *trans)
{
    uint16_t mem_reg_attr;
    uint32_t flags;
    uint32_t count;
    uint32_t offs;
    uint32_t size;

    if ( ffa_vers >= FFA_VERSION_1_1 )
    {
        const struct ffa_mem_transaction_1_1 *descr;

        if ( blen < sizeof(*descr) )
            return FFA_RET_INVALID_PARAMETERS;

        descr = buf;
        trans->sender_id = descr->sender_id;
        mem_reg_attr = descr->mem_reg_attr;
        flags = descr->flags;
        trans->handle = descr->handle;
        trans->tag = descr->tag;

        count = descr->mem_access_count;
        size = descr->mem_access_size;
        offs = descr->mem_access_offs;
    }
    else
    {
        const struct ffa_mem_transaction_1_0 *descr;

        if ( blen < sizeof(*descr) )
            return FFA_RET_INVALID_PARAMETERS;

        descr = buf;
        trans->sender_id = descr->sender_id;
        mem_reg_attr = descr->mem_reg_attr;
        flags = descr->flags;
        trans->handle = descr->handle;
        trans->tag = descr->tag;

        count = descr->mem_access_count;
        size = sizeof(struct ffa_mem_access);
        offs = offsetof(struct ffa_mem_transaction_1_0, mem_access_array);
    }
    /*
     * Make sure that "descr" which is shared with the guest isn't accessed
     * again after this point.
     */
    barrier();

    /*
     * We're doing a rough check to see that no information is lost when
     * tranfering the values into a struct ffa_mem_transaction_int below.
     * The fields in struct ffa_mem_transaction_int are wide enough to hold
     * any valid value so being out of range means that something is wrong.
     */
    if ( mem_reg_attr > UINT8_MAX || flags > UINT8_MAX || size > UINT8_MAX ||
        count > UINT8_MAX || offs > UINT16_MAX )
        return FFA_RET_INVALID_PARAMETERS;

    /* Check that the endpoint memory access descriptor array fits */
    if ( size * count + offs > blen )
        return FFA_RET_INVALID_PARAMETERS;

    trans->mem_reg_attr = mem_reg_attr;
    trans->flags = flags;
    trans->mem_access_size = size;
    trans->mem_access_count = count;
    trans->mem_access_offs = offs;

    return 0;
}

static void handle_mem_share(struct cpu_user_regs *regs)
{
    uint32_t tot_len = get_user_reg(regs, 1);
    uint32_t frag_len = get_user_reg(regs, 2);
    uint64_t addr = get_user_reg(regs, 3);
    uint32_t page_count = get_user_reg(regs, 4);
    const struct ffa_mem_region *region_descr;
    const struct ffa_mem_access *mem_access;
    struct ffa_mem_transaction_int trans;
    struct domain *d = current->domain;
    struct ffa_ctx *ctx = d->arch.tee;
    struct ffa_shm_mem *shm = NULL;
    unsigned int last_page_idx = 0;
    register_t handle_hi = 0;
    register_t handle_lo = 0;
    int ret = FFA_RET_DENIED;
    uint32_t range_count;
    uint32_t region_offs;

    /*
     * We're only accepting memory transaction descriptors via the rx/tx
     * buffer.
     */
    if ( addr )
    {
        ret = FFA_RET_NOT_SUPPORTED;
        goto out_set_ret;
    }

    /* Check that fragment length doesn't exceed total length */
    if ( frag_len > tot_len )
    {
        ret = FFA_RET_INVALID_PARAMETERS;
        goto out_set_ret;
    }

    /* We currently only support a single fragment */
    if ( frag_len != tot_len )
    {
        ret = FFA_RET_NOT_SUPPORTED;
        goto out_set_ret;
    }

    if ( !spin_trylock(&ctx->tx_lock) )
    {
        ret = FFA_RET_BUSY;
        goto out_set_ret;
    }

    if ( frag_len > ctx->page_count * FFA_PAGE_SIZE )
        goto out_unlock;

    ret = read_mem_transaction(ctx->guest_vers, ctx->tx, frag_len, &trans);
    if ( ret )
        goto out_unlock;

    if ( trans.mem_reg_attr != FFA_NORMAL_MEM_REG_ATTR )
    {
        ret = FFA_RET_NOT_SUPPORTED;
        goto out_unlock;
    }

    /* Only supports sharing it with one SP for now */
    if ( trans.mem_access_count != 1 )
    {
        ret = FFA_RET_NOT_SUPPORTED;
        goto out_unlock;
    }

    if ( trans.sender_id != get_vm_id(d) )
    {
        ret = FFA_RET_INVALID_PARAMETERS;
        goto out_unlock;
    }

    /* Check that it fits in the supplied data */
    if ( trans.mem_access_offs + trans.mem_access_size > frag_len )
        goto out_unlock;

    mem_access = ctx->tx + trans.mem_access_offs;
    if ( read_atomic(&mem_access->access_perm.perm) != FFA_MEM_ACC_RW )
    {
        ret = FFA_RET_NOT_SUPPORTED;
        goto out_unlock;
    }

    region_offs = read_atomic(&mem_access->region_offs);
    if ( sizeof(*region_descr) + region_offs > frag_len )
    {
        ret = FFA_RET_NOT_SUPPORTED;
        goto out_unlock;
    }

    region_descr = ctx->tx + region_offs;
    range_count = read_atomic(&region_descr->address_range_count);
    page_count = read_atomic(&region_descr->total_page_count);

    if ( !page_count )
    {
        ret = FFA_RET_INVALID_PARAMETERS;
        goto out_unlock;
    }

    shm = alloc_ffa_shm_mem(ctx, page_count);
    if ( !shm )
    {
        ret = FFA_RET_NO_MEMORY;
        goto out_unlock;
    }
    shm->sender_id = trans.sender_id;
    shm->ep_id = read_atomic(&mem_access->access_perm.endpoint_id);

    /*
     * Check that the Composite memory region descriptor fits.
     */
    if ( sizeof(*region_descr) + region_offs +
         range_count * sizeof(struct ffa_address_range) > frag_len )
    {
        ret = FFA_RET_INVALID_PARAMETERS;
        goto out;
    }

    ret = get_shm_pages(d, shm, region_descr->address_range_array, range_count,
                        0, &last_page_idx);
    if ( ret )
        goto out;
    if ( last_page_idx != shm->page_count )
    {
        ret = FFA_RET_INVALID_PARAMETERS;
        goto out;
    }

    /* Note that share_shm() uses our tx buffer */
    spin_lock(&ffa_tx_buffer_lock);
    ret = share_shm(shm);
    spin_unlock(&ffa_tx_buffer_lock);
    if ( ret )
        goto out;

    spin_lock(&ctx->lock);
    list_add_tail(&shm->list, &ctx->shm_list);
    spin_unlock(&ctx->lock);

    uint64_to_regpair(&handle_hi, &handle_lo, shm->handle);

out:
    if ( ret )
        free_ffa_shm_mem(ctx, shm);
out_unlock:
    spin_unlock(&ctx->tx_lock);

out_set_ret:
    if ( ret == 0)
            set_regs_success(regs, handle_lo, handle_hi);
    else
            set_regs_error(regs, ret);
}

/* Must only be called with ctx->lock held */
static struct ffa_shm_mem *find_shm_mem(struct ffa_ctx *ctx, uint64_t handle)
{
    struct ffa_shm_mem *shm;

    list_for_each_entry(shm, &ctx->shm_list, list)
        if ( shm->handle == handle )
            return shm;

    return NULL;
}

static int handle_mem_reclaim(uint64_t handle, uint32_t flags)
{
    struct domain *d = current->domain;
    struct ffa_ctx *ctx = d->arch.tee;
    struct ffa_shm_mem *shm;
    register_t handle_hi;
    register_t handle_lo;
    int ret;

    spin_lock(&ctx->lock);
    shm = find_shm_mem(ctx, handle);
    if ( shm )
        list_del(&shm->list);
    spin_unlock(&ctx->lock);
    if ( !shm )
        return FFA_RET_INVALID_PARAMETERS;

    uint64_to_regpair(&handle_hi, &handle_lo, handle);
    ret = ffa_mem_reclaim(handle_lo, handle_hi, flags);

    if ( ret )
    {
        spin_lock(&ctx->lock);
        list_add_tail(&shm->list, &ctx->shm_list);
        spin_unlock(&ctx->lock);
    }
    else
    {
        free_ffa_shm_mem(ctx, shm);
    }

    return ret;
}

static bool ffa_handle_call(struct cpu_user_regs *regs)
{
    uint32_t fid = get_user_reg(regs, 0);
    struct domain *d = current->domain;
    struct ffa_ctx *ctx = d->arch.tee;
    uint32_t count;
    int e;

    if ( !ctx )
        return false;

    switch ( fid )
    {
    case FFA_VERSION:
        handle_version(regs);
        return true;
    case FFA_ID_GET:
        set_regs_success(regs, get_vm_id(d), 0);
        return true;
    case FFA_RXTX_MAP_32:
    case FFA_RXTX_MAP_64:
        e = handle_rxtx_map(fid, get_user_reg(regs, 1), get_user_reg(regs, 2),
                            get_user_reg(regs, 3));
        if ( e )
            set_regs_error(regs, e);
        else
            set_regs_success(regs, 0, 0);
        return true;
    case FFA_RXTX_UNMAP:
        e = handle_rxtx_unmap();
        if ( e )
            set_regs_error(regs, e);
        else
            set_regs_success(regs, 0, 0);
        return true;
    case FFA_PARTITION_INFO_GET:
        e = handle_partition_info_get(get_user_reg(regs, 1),
                                      get_user_reg(regs, 2),
                                      get_user_reg(regs, 3),
                                      get_user_reg(regs, 4),
                                      get_user_reg(regs, 5), &count);
        if ( e )
            set_regs_error(regs, e);
        else
            set_regs_success(regs, count, 0);
        return true;
    case FFA_RX_RELEASE:
        e = handle_rx_release();
        if ( e )
            set_regs_error(regs, e);
        else
            set_regs_success(regs, 0, 0);
        return true;
    case FFA_MSG_SEND_DIRECT_REQ_32:
    case FFA_MSG_SEND_DIRECT_REQ_64:
        handle_msg_send_direct_req(regs, fid);
        return true;
    case FFA_MEM_SHARE_32:
    case FFA_MEM_SHARE_64:
        handle_mem_share(regs);
        return true;
    case FFA_MEM_RECLAIM:
        e = handle_mem_reclaim(regpair_to_uint64(get_user_reg(regs, 2),
                                                 get_user_reg(regs, 1)),
                               get_user_reg(regs, 3));
        if ( e )
            set_regs_error(regs, e);
        else
            set_regs_success(regs, 0, 0);
        return true;

    default:
        gprintk(XENLOG_ERR, "ffa: unhandled fid 0x%x\n", fid);
        return false;
    }
}

static int ffa_domain_init(struct domain *d)
{
    struct ffa_ctx *ctx;
    unsigned int n;
    int32_t res;

    if ( !ffa_version )
        return -ENODEV;
     /*
      * We can't use that last possible domain ID or get_vm_id() would cause
      * an overflow.
      */
    if ( d->domain_id >= UINT16_MAX)
        return -ERANGE;

    ctx = xzalloc(struct ffa_ctx);
    if ( !ctx )
        return -ENOMEM;

    d->arch.tee = ctx;

    for ( n = 0; n < subscr_vm_created_count; n++ )
    {
        res = ffa_direct_req_send_vm(subscr_vm_created[n], get_vm_id(d),
                                     FFA_MSG_SEND_VM_CREATED);
        if ( res )
        {
            printk(XENLOG_ERR "ffa: Failed to report creation of vm_id %u to  %u: res %d\n",
                   get_vm_id(d), subscr_vm_created[n], res);
            ctx->create_signal_count = n;
            return -EIO;
        }
    }
    ctx->create_signal_count = subscr_vm_created_count;

    INIT_LIST_HEAD(&ctx->shm_list);

    return 0;
}

static bool is_in_subscr_list(const uint16_t *subscr, uint16_t start,
                              uint16_t end, uint16_t sp_id)
{
    unsigned int n;

    for ( n = start; n < end; n++ )
    {
        if ( subscr[n] == sp_id )
            return true;
    }

    return false;
}

/* This function is supposed to undo what ffa_domain_init() has done */
static int ffa_domain_teardown(struct domain *d)
{
    struct ffa_ctx *ctx = d->arch.tee;
    unsigned int n;
    int32_t res;

    if ( !ctx )
        return 0;

    for ( n = 0; n < subscr_vm_destroyed_count; n++ )
    {
        /*
         * Skip SPs subscribed to the VM created event that never was
         * notified of the VM creation due to an error during
         * ffa_domain_init().
         */
        if ( is_in_subscr_list(subscr_vm_created, ctx->create_signal_count,
                               subscr_vm_created_count,
                               subscr_vm_destroyed[n]) )
            continue;

        res = ffa_direct_req_send_vm(subscr_vm_destroyed[n], get_vm_id(d),
                                     FFA_MSG_SEND_VM_DESTROYED);

        if ( res )
            printk(XENLOG_ERR "ffa: Failed to report destruction of vm_id %u to  %u: res %d\n",
                   get_vm_id(d), subscr_vm_destroyed[n], res);
    }

    if ( ctx->rx )
        rxtx_unmap(ctx);

    XFREE(d->arch.tee);

    return 0;
}

static int ffa_relinquish_resources(struct domain *d)
{
    return 0;
}

static void uninit_subscribers(void)
{
        subscr_vm_created_count = 0;
        subscr_vm_destroyed_count = 0;
        XFREE(subscr_vm_created);
        XFREE(subscr_vm_destroyed);
}

static bool init_subscribers(struct ffa_partition_info_1_1 *fpi, uint16_t count)
{
    uint16_t n;
    uint16_t c_pos;
    uint16_t d_pos;

    subscr_vm_created_count = 0;
    subscr_vm_destroyed_count = 0;
    for ( n = 0; n < count; n++ )
    {
        if ( fpi[n].partition_properties & FFA_PART_PROP_NOTIF_CREATED )
            subscr_vm_created_count++;
        if ( fpi[n].partition_properties & FFA_PART_PROP_NOTIF_DESTROYED )
            subscr_vm_destroyed_count++;
    }

    if ( subscr_vm_created_count )
        subscr_vm_created = xzalloc_array(uint16_t, subscr_vm_created_count);
    if ( subscr_vm_destroyed_count )
        subscr_vm_destroyed = xzalloc_array(uint16_t,
                                            subscr_vm_destroyed_count);
    if ( (subscr_vm_created_count && !subscr_vm_created) ||
         (subscr_vm_destroyed_count && !subscr_vm_destroyed) )
    {
        printk(XENLOG_ERR "ffa: Failed to allocate subscription lists\n");
        uninit_subscribers();
        return false;
    }

    for ( c_pos = 0, d_pos = 0, n = 0; n < count; n++ )
    {
        if ( fpi[n].partition_properties & FFA_PART_PROP_NOTIF_CREATED )
            subscr_vm_created[c_pos++] = fpi[n].id;
        if ( fpi[n].partition_properties & FFA_PART_PROP_NOTIF_DESTROYED )
            subscr_vm_destroyed[d_pos++] = fpi[n].id;
    }

    return true;
}

static bool init_sps(void)
{
    bool ret = false;
    uint32_t count;
    int e;

    e = ffa_partition_info_get(0, 0, 0, 0, 0, &count);
    if ( e )
    {
        printk(XENLOG_ERR "ffa: Failed to get list of SPs: %d\n", e);
        goto out;
    }

    if ( count >= UINT16_MAX )
    {
        printk(XENLOG_ERR "ffa: Impossible number of SPs: %u\n", count);
        goto out;
    }

    ret = init_subscribers(ffa_rx, count);

out:
    ffa_rx_release();

    return ret;
}

static bool ffa_probe(void)
{
    uint32_t vers;
    int e;
    unsigned int major_vers;
    unsigned int minor_vers;

    /*
     * FF-A often works in units of 4K pages and currently it's assumed
     * that we can map memory using that granularity. See also the comment
     * above the FFA_PAGE_SIZE define.
     *
     * It is possible to support a PAGE_SIZE larger than 4K in Xen, but
     * until that is fully handled in this code make sure that we only use
     * 4K page sizes.
     */
    BUILD_BUG_ON(PAGE_SIZE != FFA_PAGE_SIZE);

    /*
     * psci_init_smccc() updates this value with what's reported by EL-3
     * or secure world.
     */
    if ( smccc_ver < ARM_SMCCC_VERSION_1_2 )
    {
        printk(XENLOG_ERR
               "ffa: unsupported SMCCC version %#x (need at least %#x)\n",
               smccc_ver, ARM_SMCCC_VERSION_1_2);
        return false;
    }

    if ( !ffa_get_version(&vers) )
        return false;

    if ( vers < FFA_MIN_SPMC_VERSION || vers > FFA_MY_VERSION )
    {
        printk(XENLOG_ERR "ffa: Incompatible version %#x found\n", vers);
        return false;
    }

    major_vers = (vers >> FFA_VERSION_MAJOR_SHIFT) & FFA_VERSION_MAJOR_MASK;
    minor_vers = vers & FFA_VERSION_MINOR_MASK;
    printk(XENLOG_INFO "ARM FF-A Mediator version %u.%u\n",
           FFA_MY_VERSION_MAJOR, FFA_MY_VERSION_MINOR);
    printk(XENLOG_INFO "ARM FF-A Firmware version %u.%u\n",
           major_vers, minor_vers);

    /*
     * At the moment domains must support the same features used by Xen.
     * TODO: Rework the code to allow domain to use a subset of the
     * features supported.
     */
    if ( !check_mandatory_feature(FFA_PARTITION_INFO_GET) ||
         !check_mandatory_feature(FFA_RX_RELEASE) ||
         !check_mandatory_feature(FFA_RXTX_MAP_64) ||
         !check_mandatory_feature(FFA_MEM_SHARE_64) ||
         !check_mandatory_feature(FFA_RXTX_UNMAP) ||
         !check_mandatory_feature(FFA_MEM_SHARE_32) ||
         !check_mandatory_feature(FFA_MEM_RECLAIM) ||
         !check_mandatory_feature(FFA_MSG_SEND_DIRECT_REQ_32) )
        return false;

    ffa_rx = alloc_xenheap_pages(get_order_from_pages(FFA_RXTX_PAGE_COUNT), 0);
    if ( !ffa_rx )
        return false;

    ffa_tx = alloc_xenheap_pages(get_order_from_pages(FFA_RXTX_PAGE_COUNT), 0);
    if ( !ffa_tx )
        goto err_free_ffa_rx;

    e = ffa_rxtx_map(__pa(ffa_tx), __pa(ffa_rx), FFA_RXTX_PAGE_COUNT);
    if ( e )
    {
        printk(XENLOG_ERR "ffa: Failed to map rxtx: error %d\n", e);
        goto err_free_ffa_tx;
    }
    ffa_version = vers;

    if ( !init_sps() )
        goto err_free_ffa_tx;

    return true;

err_free_ffa_tx:
    free_xenheap_pages(ffa_tx, 0);
    ffa_tx = NULL;
err_free_ffa_rx:
    free_xenheap_pages(ffa_rx, 0);
    ffa_rx = NULL;
    ffa_version = 0;

    return false;
}

static const struct tee_mediator_ops ffa_ops =
{
    .probe = ffa_probe,
    .domain_init = ffa_domain_init,
    .domain_teardown = ffa_domain_teardown,
    .relinquish_resources = ffa_relinquish_resources,
    .handle_call = ffa_handle_call,
};

REGISTER_TEE_MEDIATOR(ffa, "FF-A", XEN_DOMCTL_CONFIG_TEE_FFA, &ffa_ops);
