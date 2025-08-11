/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2023  Linaro Limited
 */

#ifndef __FFA_PRIVATE_H__
#define __FFA_PRIVATE_H__

#include <xen/bitmap.h>
#include <xen/const.h>
#include <xen/list.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <xen/sizes.h>
#include <xen/spinlock.h>
#include <xen/time.h>
#include <xen/types.h>

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
#define FFA_RET_NO_DATA                 -9

/* FFA_VERSION helpers */
#define FFA_VERSION_MAJOR_SHIFT         16U
#define FFA_VERSION_MAJOR_MASK          0x7FFFU
#define FFA_VERSION_MINOR_SHIFT         0U
#define FFA_VERSION_MINOR_MASK          0xFFFFU
#define MAKE_FFA_VERSION(major, minor)  \
        ((((major) & FFA_VERSION_MAJOR_MASK) << FFA_VERSION_MAJOR_SHIFT) | \
         ((minor) & FFA_VERSION_MINOR_MASK))
#define FFA_VERSION_MAJOR(vers) (((vers) >> FFA_VERSION_MAJOR_SHIFT) & \
                                 FFA_VERSION_MAJOR_MASK)
#define FFA_VERSION_MINOR(vers) ((vers) & FFA_VERSION_MINOR_MASK)

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

/*
 * The time we wait until trying to tear down a domain again if it was
 * blocked initially.
 */
#define FFA_CTX_TEARDOWN_DELAY          SECONDS(1)

/*
 * The maximum number of Secure partitions we support for partinfo_get.
 * This prevents holding the CPU during potentially to long time during
 * a partinfo_get call. Value choosen seems realistic for any configuration
 * but can be incremented here if needed.
 */
#define FFA_MAX_NUM_SP                  64

/*
 * We rely on the convention suggested but not mandated by the FF-A
 * specification that secure world endpoint identifiers have the bit 15
 * set and normal world have it set to 0.
 */
#define FFA_ID_IS_SECURE(id)    ((id) & BIT(15, U))

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

/*
 * Partition properties we give for a normal world VM:
 * - can send direct message but not receive them
 * - can handle indirect messages
 * - can receive notifications
 * 32/64 bit flag is set depending on the VM
 */
#define FFA_PART_VM_PROP    (FFA_PART_PROP_DIRECT_REQ_SEND | \
                             FFA_PART_PROP_INDIRECT_MSGS | \
                             FFA_PART_PROP_RECV_NOTIF | \
                             FFA_PART_PROP_IS_PE_ID)

/* Flags used in calls to FFA_NOTIFICATION_GET interface  */
#define FFA_NOTIF_FLAG_BITMAP_SP        BIT(0, U)
#define FFA_NOTIF_FLAG_BITMAP_VM        BIT(1, U)
#define FFA_NOTIF_FLAG_BITMAP_SPM       BIT(2, U)
#define FFA_NOTIF_FLAG_BITMAP_HYP       BIT(3, U)

#define FFA_NOTIF_INFO_GET_MORE_FLAG        BIT(0, U)
#define FFA_NOTIF_INFO_GET_ID_LIST_SHIFT    12
#define FFA_NOTIF_INFO_GET_ID_COUNT_SHIFT   7
#define FFA_NOTIF_INFO_GET_ID_COUNT_MASK    0x1F

#define FFA_NOTIF_RX_BUFFER_FULL        BIT(0, U)

/* Feature IDs used with FFA_FEATURES */
#define FFA_FEATURE_NOTIF_PEND_INTR     0x1U
#define FFA_FEATURE_SCHEDULE_RECV_INTR  0x2U

/* Function IDs */
#define FFA_ERROR                       0x84000060U
#define FFA_SUCCESS_32                  0x84000061U
#define FFA_SUCCESS_64                  0xC4000061U
#define FFA_INTERRUPT                   0x84000062U
#define FFA_VERSION                     0x84000063U
#define FFA_FEATURES                    0x84000064U
#define FFA_RX_RELEASE                  0x84000065U
#define FFA_RXTX_MAP_32                 0x84000066U
#define FFA_RXTX_MAP_64                 0xC4000066U
#define FFA_RXTX_UNMAP                  0x84000067U
#define FFA_PARTITION_INFO_GET          0x84000068U
#define FFA_ID_GET                      0x84000069U
#define FFA_MSG_POLL                    0x8400006AU
#define FFA_MSG_WAIT                    0x8400006BU
#define FFA_MSG_YIELD                   0x8400006CU
#define FFA_RUN                         0x8400006DU
#define FFA_MSG_SEND                    0x8400006EU
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
#define FFA_NOTIFICATION_BITMAP_CREATE  0x8400007DU
#define FFA_NOTIFICATION_BITMAP_DESTROY 0x8400007EU
#define FFA_NOTIFICATION_BIND           0x8400007FU
#define FFA_NOTIFICATION_UNBIND         0x84000080U
#define FFA_NOTIFICATION_SET            0x84000081U
#define FFA_NOTIFICATION_GET            0x84000082U
#define FFA_NOTIFICATION_INFO_GET_32    0x84000083U
#define FFA_NOTIFICATION_INFO_GET_64    0xC4000083U
#define FFA_RX_ACQUIRE                  0x84000084U
#define FFA_SPM_ID_GET                  0x84000085U
#define FFA_MSG_SEND2                   0x84000086U

/**
 * Encoding of features supported or not by the fw in a bitmap:
 * - Function IDs are going from 0x60 to 0xFF
 * - A function can be supported in 32 and/or 64bit
 * The bitmap has one bit for each function in 32 and 64 bit.
 */
#define FFA_ABI_ID(id)        ((id) & ARM_SMCCC_FUNC_MASK)
#define FFA_ABI_CONV(id)      (((id) >> ARM_SMCCC_CONV_SHIFT) & BIT(0,U))

#define FFA_ABI_MIN           FFA_ABI_ID(FFA_ERROR)
#define FFA_ABI_MAX           FFA_ABI_ID(FFA_MSG_SEND2)

#define FFA_ABI_BITMAP_SIZE   (2 * (FFA_ABI_MAX - FFA_ABI_MIN + 1))
#define FFA_ABI_BITNUM(id)    ((FFA_ABI_ID(id) - FFA_ABI_MIN) << 1 | \
                               FFA_ABI_CONV(id))

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

struct ffa_ctx_notif {
    /*
     * True if domain is reported by FFA_NOTIFICATION_INFO_GET to have
     * pending notifications from the secure world.
     */
    bool secure_pending;

    /*
     * True if domain is reported by FFA_NOTIFICATION_INFO_GET to have
     * pending notifications from VMs (including framework ones).
     */
    bool vm_pending;

    /*
     * True if domain has buffer full notification pending
     */
    bool buff_full_pending;
};

struct ffa_ctx {
    /*
     * Chain list of all FF-A contexts.
     * As we might have several read from the list of context through parallel
     * partinfo_get but fewer additions/removal as those happen only during a
     * version negotiation or guest shutdown, access to this list is protected
     * through a rwlock (addition/removal with write lock, reading through a
     * read lock).
     */
    struct list_head ctx_list; /* chain list of all FF-A contexts */

    /*
     * Data access unlocked (mainly for part_info_get in VM to VM).
     * Those should be set before the ctx is added in the list.
     */
    /* FF-A Endpoint ID */
    uint16_t ffa_id;
    uint16_t num_vcpus;
    bool is_64bit;

    /*
     * Global data accessed atomically or using ACCES_ONCE.
     */
    struct ffa_ctx_notif notif;

    /*
     * Global data accessed with lock locked.
     */
    spinlock_t lock;
    /*
     * FF-A version negotiated by the guest, only modifications to
     * this field are done with the lock held as this is expected to
     * be done once at init by a guest.
     */
    uint32_t guest_vers;
    /* Number of 4kB pages in each of rx/rx_pg and tx/tx_pg */
    unsigned int page_count;
    /* Number of allocated shared memory object */
    unsigned int shm_count;
    /* Used shared memory objects, struct ffa_shm_mem */
    struct list_head shm_list;

    /*
     * Rx buffer, accessed with rx_lock locked.
     * rx_is_free is used to serialize access.
     */
    spinlock_t rx_lock;
    bool rx_is_free;
    void *rx;
    struct page_info *rx_pg;

    /*
     * Tx buffer, access with tx_lock locked.
     */
    spinlock_t tx_lock;
    const void *tx;
    struct page_info *tx_pg;


    /*
     * Domain teardown handling if data shared or used by other domains
     * do not allow to teardown the domain immediately.
     */
    struct domain *teardown_d;
    struct list_head teardown_list;
    s_time_t teardown_expire;
    /* Keep track of SPs that should be notified of VM destruction */
    unsigned long *vm_destroy_bitmap;
};

extern void *ffa_rx;
extern void *ffa_tx;
extern spinlock_t ffa_rx_buffer_lock;
extern spinlock_t ffa_tx_buffer_lock;
extern DECLARE_BITMAP(ffa_fw_abi_supported, FFA_ABI_BITMAP_SIZE);

extern struct list_head ffa_ctx_head;
extern rwlock_t ffa_ctx_list_rwlock;
#ifdef CONFIG_FFA_VM_TO_VM
extern atomic_t ffa_vm_count;
#endif

bool ffa_shm_domain_destroy(struct domain *d);
void ffa_handle_mem_share(struct cpu_user_regs *regs);
int ffa_handle_mem_reclaim(uint64_t handle, uint32_t flags);

bool ffa_partinfo_init(void);
int ffa_partinfo_domain_init(struct domain *d);
bool ffa_partinfo_domain_destroy(struct domain *d);
void ffa_handle_partition_info_get(struct cpu_user_regs *regs);

bool ffa_rxtx_init(void);
void ffa_rxtx_destroy(void);
void ffa_rxtx_domain_destroy(struct domain *d);
uint32_t ffa_handle_rxtx_map(uint32_t fid, register_t tx_addr,
			     register_t rx_addr, uint32_t page_count);
uint32_t ffa_handle_rxtx_unmap(void);
int32_t ffa_rx_acquire(struct domain *d);
int32_t ffa_rx_release(struct domain *d);

void ffa_notif_init(void);
void ffa_notif_init_interrupt(void);
int ffa_notif_domain_init(struct domain *d);
void ffa_notif_domain_destroy(struct domain *d);

int ffa_handle_notification_bind(struct cpu_user_regs *regs);
int ffa_handle_notification_unbind(struct cpu_user_regs *regs);
void ffa_handle_notification_info_get(struct cpu_user_regs *regs);
void ffa_handle_notification_get(struct cpu_user_regs *regs);
int ffa_handle_notification_set(struct cpu_user_regs *regs);

#ifdef CONFIG_FFA_VM_TO_VM
void ffa_raise_rx_buffer_full(struct domain *d);
#else
static inline void ffa_raise_rx_buffer_full(struct domain *d)
{
}
#endif

void ffa_handle_msg_send_direct_req(struct cpu_user_regs *regs, uint32_t fid);
int32_t ffa_handle_msg_send2(struct cpu_user_regs *regs);

#ifdef CONFIG_FFA_VM_TO_VM
static inline uint16_t get_ffa_vm_count(void)
{
    return atomic_read(&ffa_vm_count);
}

static inline void inc_ffa_vm_count(void)
{
    atomic_inc(&ffa_vm_count);
}

static inline void dec_ffa_vm_count(void)
{
    ASSERT(atomic_read(&ffa_vm_count) > 0);
    atomic_dec(&ffa_vm_count);
}
#else
/* Only count the caller VM */
#define get_ffa_vm_count()  ((uint16_t)1UL)
#define inc_ffa_vm_count()  do {} while(0)
#define dec_ffa_vm_count()  do {} while(0)
#endif

static inline uint16_t ffa_get_vm_id(const struct domain *d)
{
    /* +1 since 0 is reserved for the hypervisor in FF-A */
    return d->domain_id + 1;
}

static inline struct domain *ffa_rcu_lock_domain_by_vm_id(uint16_t vm_id)
{
    ASSERT(vm_id);

    /* -1 to match ffa_get_vm_id() */
    return rcu_lock_domain_by_id(vm_id - 1);
}

static inline void ffa_set_regs(struct cpu_user_regs *regs, register_t v0,
                                register_t v1, register_t v2, register_t v3,
                                register_t v4, register_t v5, register_t v6,
                                register_t v7)
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

static inline void ffa_set_regs_error(struct cpu_user_regs *regs,
                                      uint32_t error_code)
{
    ffa_set_regs(regs, FFA_ERROR, 0, error_code, 0, 0, 0, 0, 0);
}

static inline void ffa_set_regs_success(struct cpu_user_regs *regs,
                                        uint32_t w2, uint32_t w3)
{
    ffa_set_regs(regs, FFA_SUCCESS_32, 0, w2, w3, 0, 0, 0, 0);
}

static inline int32_t ffa_get_ret_code(const struct arm_smccc_1_2_regs *resp)
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

static inline int32_t ffa_simple_call(uint32_t fid, register_t a1,
                                      register_t a2, register_t a3,
                                      register_t a4)
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

    return ffa_get_ret_code(&resp);
}

static inline int32_t ffa_hyp_rx_release(void)
{
    return ffa_simple_call(FFA_RX_RELEASE, 0, 0, 0, 0);
}

static inline bool ffa_fw_supports_fid(uint32_t fid)
{
    BUILD_BUG_ON(FFA_ABI_MIN > FFA_ABI_MAX);

    if ( FFA_ABI_BITNUM(fid) > FFA_ABI_BITMAP_SIZE)
        return false;
    return test_bit(FFA_ABI_BITNUM(fid), ffa_fw_abi_supported);
}

#endif /*__FFA_PRIVATE_H__*/
