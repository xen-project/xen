/*
 * Copyright (C) 2011 Advanced Micro Devices, Inc.
 * Author: Wei Wang <wei.wang2@amd.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/sched.h>
#include <asm/p2m.h>
#include <asm/amd-iommu.h>
#include <asm/hvm/svm/amd-iommu-proto.h>


#define IOMMU_MMIO_SIZE                         0x8000
#define IOMMU_MMIO_PAGE_NR                      0x8
#define RING_BF_LENGTH_MASK                     0x0F000000
#define RING_BF_LENGTH_SHIFT                    24

#define PASMAX_9_bit                            0x8
#define GUEST_CR3_1_LEVEL                       0x0
#define GUEST_ADDRESS_SIZE_6_LEVEL              0x2
#define HOST_ADDRESS_SIZE_6_LEVEL               0x2

#define guest_iommu_set_status(iommu, bit) \
        iommu_set_bit(&((iommu)->reg_status.lo), bit)

#define guest_iommu_clear_status(iommu, bit) \
        iommu_clear_bit(&((iommu)->reg_status.lo), bit)

#define reg_to_u64(reg) (((uint64_t)reg.hi << 32) | reg.lo )
#define u64_to_reg(reg, val) \
    do \
    { \
        (reg)->lo = (u32)(val); \
        (reg)->hi = (val) >> 32; \
    } while (0)

static unsigned int machine_bdf(struct domain *d, uint16_t guest_bdf)
{
    return guest_bdf;
}

static uint16_t guest_bdf(struct domain *d, uint16_t machine_bdf)
{
    return machine_bdf;
}

static inline struct guest_iommu *domain_iommu(struct domain *d)
{
    return dom_iommu(d)->arch.g_iommu;
}

static inline struct guest_iommu *vcpu_iommu(struct vcpu *v)
{
    return dom_iommu(v->domain)->arch.g_iommu;
}

static void guest_iommu_enable(struct guest_iommu *iommu)
{
    iommu->enabled = 1;
}

static void guest_iommu_disable(struct guest_iommu *iommu)
{
    iommu->enabled = 0;
}

static uint64_t get_guest_cr3_from_dte(dev_entry_t *dte)
{
    uint64_t gcr3_1, gcr3_2, gcr3_3;

    gcr3_1 = get_field_from_reg_u32(dte->data[1],
                                    IOMMU_DEV_TABLE_GCR3_1_MASK,
                                    IOMMU_DEV_TABLE_GCR3_1_SHIFT);
    gcr3_2 = get_field_from_reg_u32(dte->data[2],
                                    IOMMU_DEV_TABLE_GCR3_2_MASK,
                                    IOMMU_DEV_TABLE_GCR3_2_SHIFT);
    gcr3_3 = get_field_from_reg_u32(dte->data[3],
                                    IOMMU_DEV_TABLE_GCR3_3_MASK,
                                    IOMMU_DEV_TABLE_GCR3_3_SHIFT);

    return ((gcr3_3 << 31) | (gcr3_2 << 15 ) | (gcr3_1 << 12)) >> PAGE_SHIFT;
}

static uint16_t get_domid_from_dte(dev_entry_t *dte)
{
    return get_field_from_reg_u32(dte->data[2], IOMMU_DEV_TABLE_DOMAIN_ID_MASK,
                                  IOMMU_DEV_TABLE_DOMAIN_ID_SHIFT);
}

static uint16_t get_glx_from_dte(dev_entry_t *dte)
{
    return get_field_from_reg_u32(dte->data[1], IOMMU_DEV_TABLE_GLX_MASK,
                                  IOMMU_DEV_TABLE_GLX_SHIFT);
}

static uint16_t get_gv_from_dte(dev_entry_t *dte)
{
    return get_field_from_reg_u32(dte->data[1],IOMMU_DEV_TABLE_GV_MASK,
                                  IOMMU_DEV_TABLE_GV_SHIFT);
}

static unsigned int host_domid(struct domain *d, uint64_t g_domid)
{
    /* Only support one PPR device in guest for now */
    return d->domain_id;
}

static unsigned long get_gfn_from_base_reg(uint64_t base_raw)
{
    base_raw &= PADDR_MASK;
    ASSERT ( base_raw != 0 );
    return base_raw >> PAGE_SHIFT;
}

static void guest_iommu_deliver_msi(struct domain *d)
{
    uint8_t vector, dest, dest_mode, delivery_mode, trig_mode;
    struct guest_iommu *iommu = domain_iommu(d);

    vector = iommu->msi.vector;
    dest = iommu->msi.dest;
    dest_mode = iommu->msi.dest_mode;
    delivery_mode = iommu->msi.delivery_mode;
    trig_mode = iommu->msi.trig_mode;

    vmsi_deliver(d, vector, dest, dest_mode, delivery_mode, trig_mode);
}

static unsigned long guest_iommu_get_table_mfn(struct domain *d,
                                               uint64_t base_raw,
                                               unsigned int entry_size,
                                               unsigned int pos)
{
    unsigned long idx, gfn, mfn;
    p2m_type_t p2mt;

    gfn = get_gfn_from_base_reg(base_raw);
    idx = (pos * entry_size) >> PAGE_SHIFT;

    mfn = mfn_x(get_gfn(d, gfn + idx, &p2mt));
    put_gfn(d, gfn);

    return mfn;
}

static void guest_iommu_enable_dev_table(struct guest_iommu *iommu)
{
    uint32_t length_raw = get_field_from_reg_u32(iommu->dev_table.reg_base.lo,
                                                 IOMMU_DEV_TABLE_SIZE_MASK,
                                                 IOMMU_DEV_TABLE_SIZE_SHIFT);
    iommu->dev_table.size = (length_raw + 1) * PAGE_SIZE;
}

static void guest_iommu_enable_ring_buffer(struct guest_iommu *iommu,
                                           struct guest_buffer *buffer,
                                           uint32_t entry_size)
{
    uint32_t length_raw = get_field_from_reg_u32(buffer->reg_base.hi,
                                                 RING_BF_LENGTH_MASK,
                                                 RING_BF_LENGTH_SHIFT);
    buffer->entries = 1 << length_raw;
}

void guest_iommu_add_ppr_log(struct domain *d, u32 entry[])
{
    uint16_t gdev_id;
    unsigned long mfn, tail, head;
    ppr_entry_t *log, *log_base;
    struct guest_iommu *iommu;

    if ( !is_hvm_domain(d) )
        return;

    iommu = domain_iommu(d);
    if ( !iommu )
        return;

    tail = iommu_get_rb_pointer(iommu->ppr_log.reg_tail.lo);
    head = iommu_get_rb_pointer(iommu->ppr_log.reg_head.lo);

    if ( tail >= iommu->ppr_log.entries || head >= iommu->ppr_log.entries )
    {
        AMD_IOMMU_DEBUG("Error: guest iommu ppr log overflows\n");
        guest_iommu_disable(iommu);
        return;
    }

    mfn = guest_iommu_get_table_mfn(d, reg_to_u64(iommu->ppr_log.reg_base),
                                    sizeof(ppr_entry_t), tail);
    ASSERT(mfn_valid(_mfn(mfn)));

    log_base = map_domain_page(_mfn(mfn));
    log = log_base + tail % (PAGE_SIZE / sizeof(ppr_entry_t));

    /* Convert physical device id back into virtual device id */
    gdev_id = guest_bdf(d, iommu_get_devid_from_cmd(entry[0]));
    iommu_set_devid_to_cmd(&entry[0], gdev_id);

    memcpy(log, entry, sizeof(ppr_entry_t));

    /* Now shift ppr log tail pointer */
    if ( ++tail >= iommu->ppr_log.entries )
    {
        tail = 0;
        guest_iommu_set_status(iommu, IOMMU_STATUS_PPR_LOG_OVERFLOW_SHIFT);
    }
    iommu_set_rb_pointer(&iommu->ppr_log.reg_tail.lo, tail);
    unmap_domain_page(log_base);

    guest_iommu_deliver_msi(d);
}

void guest_iommu_add_event_log(struct domain *d, u32 entry[])
{
    uint16_t dev_id;
    unsigned long mfn, tail, head;
    event_entry_t *log, *log_base;
    struct guest_iommu *iommu;

    if ( !is_hvm_domain(d) )
        return;

    iommu = domain_iommu(d);
    if ( !iommu )
        return;

    tail = iommu_get_rb_pointer(iommu->event_log.reg_tail.lo);
    head = iommu_get_rb_pointer(iommu->event_log.reg_head.lo);

    if ( tail >= iommu->event_log.entries || head >= iommu->event_log.entries )
    {
        AMD_IOMMU_DEBUG("Error: guest iommu event overflows\n");
        guest_iommu_disable(iommu);
        return;
    }

    mfn = guest_iommu_get_table_mfn(d, reg_to_u64(iommu->event_log.reg_base),
                                    sizeof(event_entry_t), tail);
    ASSERT(mfn_valid(_mfn(mfn)));

    log_base = map_domain_page(_mfn(mfn));
    log = log_base + tail % (PAGE_SIZE / sizeof(event_entry_t));

    /* re-write physical device id into virtual device id */
    dev_id = guest_bdf(d, iommu_get_devid_from_cmd(entry[0]));
    iommu_set_devid_to_cmd(&entry[0], dev_id);
    memcpy(log, entry, sizeof(event_entry_t));

    /* Now shift event log tail pointer */
    if ( ++tail >= iommu->event_log.entries )
    {
        tail = 0;
        guest_iommu_set_status(iommu, IOMMU_STATUS_EVENT_OVERFLOW_SHIFT);
    }

    iommu_set_rb_pointer(&iommu->event_log.reg_tail.lo, tail);
    unmap_domain_page(log_base);

    guest_iommu_deliver_msi(d);
}

static int do_complete_ppr_request(struct domain *d, cmd_entry_t *cmd)
{
    uint16_t dev_id;
    struct amd_iommu *iommu;

    dev_id = machine_bdf(d, iommu_get_devid_from_cmd(cmd->data[0]));
    iommu = find_iommu_for_device(0, dev_id);

    if ( !iommu )
    {
        AMD_IOMMU_DEBUG("%s: Fail to find iommu for bdf %x\n",
                        __func__, dev_id);
        return -ENODEV;
    }

    /* replace virtual device id into physical */
    iommu_set_devid_to_cmd(&cmd->data[0], dev_id);
    amd_iommu_send_guest_cmd(iommu, cmd->data);

    return 0;
}

static int do_invalidate_pages(struct domain *d, cmd_entry_t *cmd)
{
    uint16_t gdom_id, hdom_id;
    struct amd_iommu *iommu = NULL;

    gdom_id = get_field_from_reg_u32(cmd->data[1],
                                    IOMMU_INV_IOMMU_PAGES_DOMAIN_ID_MASK,
                                    IOMMU_INV_IOMMU_PAGES_DOMAIN_ID_SHIFT);

    hdom_id = host_domid(d, gdom_id);
    set_field_in_reg_u32(hdom_id, cmd->data[1],
                         IOMMU_INV_IOMMU_PAGES_DOMAIN_ID_MASK,
                         IOMMU_INV_IOMMU_PAGES_DOMAIN_ID_SHIFT, &cmd->data[1]);

    for_each_amd_iommu ( iommu )
        amd_iommu_send_guest_cmd(iommu, cmd->data);

    return 0;
}

static int do_invalidate_all(struct domain *d, cmd_entry_t *cmd)
{
    struct amd_iommu *iommu = NULL;

    for_each_amd_iommu ( iommu )
        amd_iommu_flush_all_pages(d);

    return 0;
}

static int do_invalidate_iotlb_pages(struct domain *d, cmd_entry_t *cmd)
{
    struct amd_iommu *iommu;
    uint16_t dev_id;

    dev_id = machine_bdf(d, iommu_get_devid_from_cmd(cmd->data[0]));

    iommu = find_iommu_for_device(0, dev_id);
    if ( !iommu )
    {
        AMD_IOMMU_DEBUG("%s: Fail to find iommu for bdf %x\n",
                         __func__, dev_id);
        return -ENODEV;
    }

    iommu_set_devid_to_cmd(&cmd->data[0], dev_id);
    amd_iommu_send_guest_cmd(iommu, cmd->data);

    return 0;
}

static int do_completion_wait(struct domain *d, cmd_entry_t *cmd)
{
    bool_t com_wait_int_en, com_wait_int, i, s;
    struct guest_iommu *iommu;
    unsigned long gfn;
    p2m_type_t p2mt;

    iommu = domain_iommu(d);

    i = iommu_get_bit(cmd->data[0], IOMMU_COMP_WAIT_I_FLAG_SHIFT);
    s = iommu_get_bit(cmd->data[0], IOMMU_COMP_WAIT_S_FLAG_SHIFT);

    if ( i )
        guest_iommu_set_status(iommu, IOMMU_STATUS_COMP_WAIT_INT_SHIFT);

    if ( s )
    {
        uint64_t gaddr_lo, gaddr_hi, gaddr_64, data;
        void *vaddr;

        data = (uint64_t)cmd->data[3] << 32 | cmd->data[2];
        gaddr_lo = get_field_from_reg_u32(cmd->data[0],
                                          IOMMU_COMP_WAIT_ADDR_LOW_MASK,
                                          IOMMU_COMP_WAIT_ADDR_LOW_SHIFT);
        gaddr_hi = get_field_from_reg_u32(cmd->data[1],
                                          IOMMU_COMP_WAIT_ADDR_HIGH_MASK,
                                          IOMMU_COMP_WAIT_ADDR_HIGH_SHIFT);

        gaddr_64 = (gaddr_hi << 32) | (gaddr_lo << 3);

        gfn = gaddr_64 >> PAGE_SHIFT;
        vaddr = map_domain_page(get_gfn(d, gfn ,&p2mt));
        put_gfn(d, gfn);

        write_u64_atomic((uint64_t *)(vaddr + (gaddr_64 & (PAGE_SIZE-1))),
                         data);
        unmap_domain_page(vaddr);
    }

    com_wait_int_en = iommu_get_bit(iommu->reg_ctrl.lo,
                                    IOMMU_CONTROL_COMP_WAIT_INT_SHIFT);
    com_wait_int = iommu_get_bit(iommu->reg_status.lo,
                                 IOMMU_STATUS_COMP_WAIT_INT_SHIFT);

    if ( com_wait_int_en && com_wait_int )
        guest_iommu_deliver_msi(d);

    return 0;
}

static int do_invalidate_dte(struct domain *d, cmd_entry_t *cmd)
{
    uint16_t gbdf, mbdf, req_id, gdom_id, hdom_id;
    dev_entry_t *gdte, *mdte, *dte_base;
    struct amd_iommu *iommu = NULL;
    struct guest_iommu *g_iommu;
    uint64_t gcr3_gfn, gcr3_mfn;
    uint8_t glx, gv;
    unsigned long dte_mfn, flags;
    p2m_type_t p2mt;

    g_iommu = domain_iommu(d);
    gbdf = iommu_get_devid_from_cmd(cmd->data[0]);
    mbdf = machine_bdf(d, gbdf);

    /* Guest can only update DTEs for its passthru devices */
    if ( mbdf == 0 || gbdf == 0 )
        return 0;

    /* Sometimes guest invalidates devices from non-exists dtes */
    if ( (gbdf * sizeof(dev_entry_t)) > g_iommu->dev_table.size )
        return 0;

    dte_mfn = guest_iommu_get_table_mfn(d,
                                        reg_to_u64(g_iommu->dev_table.reg_base),
                                        sizeof(dev_entry_t), gbdf);
    ASSERT(mfn_valid(_mfn(dte_mfn)));

    /* Read guest dte information */
    dte_base = map_domain_page(_mfn(dte_mfn));

    gdte = dte_base + gbdf % (PAGE_SIZE / sizeof(dev_entry_t));

    gdom_id  = get_domid_from_dte(gdte);
    gcr3_gfn = get_guest_cr3_from_dte(gdte);
    glx      = get_glx_from_dte(gdte);
    gv       = get_gv_from_dte(gdte);

    unmap_domain_page(dte_base);

    /* Do not update host dte before gcr3 has been set */
    if ( gcr3_gfn == 0 )
        return 0;

    gcr3_mfn = mfn_x(get_gfn(d, gcr3_gfn, &p2mt));
    put_gfn(d, gcr3_gfn);

    ASSERT(mfn_valid(_mfn(gcr3_mfn)));

    iommu = find_iommu_for_device(0, mbdf);
    if ( !iommu )
    {
        AMD_IOMMU_DEBUG("%s: Fail to find iommu for bdf %x!\n",
                        __func__, mbdf);
        return -ENODEV;
    }

    /* Setup host device entry */
    hdom_id = host_domid(d, gdom_id);
    req_id = get_dma_requestor_id(iommu->seg, mbdf);
    mdte = iommu->dev_table.buffer + (req_id * sizeof(dev_entry_t));

    spin_lock_irqsave(&iommu->lock, flags);
    iommu_dte_set_guest_cr3((u32 *)mdte, hdom_id,
                            gcr3_mfn << PAGE_SHIFT, gv, glx);

    amd_iommu_flush_device(iommu, req_id);
    spin_unlock_irqrestore(&iommu->lock, flags);

    return 0;
}

static void guest_iommu_process_command(unsigned long _d)
{
    unsigned long opcode, tail, head, entries_per_page, cmd_mfn;
    cmd_entry_t *cmd, *cmd_base;
    struct domain *d = (struct domain *)_d;
    struct guest_iommu *iommu;

    iommu = domain_iommu(d);

    if ( !iommu->enabled )
        return;

    head = iommu_get_rb_pointer(iommu->cmd_buffer.reg_head.lo);
    tail = iommu_get_rb_pointer(iommu->cmd_buffer.reg_tail.lo);

    /* Tail pointer is rolled over by guest driver, value outside
     * cmd_buffer_entries cause iommu disabled
     */

    if ( tail >= iommu->cmd_buffer.entries ||
         head >= iommu->cmd_buffer.entries )
    {
        AMD_IOMMU_DEBUG("Error: guest iommu cmd buffer overflows\n");
        guest_iommu_disable(iommu);
        return;
    }

    entries_per_page = PAGE_SIZE / sizeof(cmd_entry_t);

    while ( head != tail )
    {
        int ret = 0;

        cmd_mfn = guest_iommu_get_table_mfn(d,
                                            reg_to_u64(iommu->cmd_buffer.reg_base),
                                            sizeof(cmd_entry_t), head);
        ASSERT(mfn_valid(_mfn(cmd_mfn)));

        cmd_base = map_domain_page(_mfn(cmd_mfn));
        cmd = cmd_base + head % entries_per_page;

        opcode = get_field_from_reg_u32(cmd->data[1],
                                        IOMMU_CMD_OPCODE_MASK,
                                        IOMMU_CMD_OPCODE_SHIFT);
        switch ( opcode )
        {
        case IOMMU_CMD_COMPLETION_WAIT:
            ret = do_completion_wait(d, cmd);
            break;
        case IOMMU_CMD_INVALIDATE_DEVTAB_ENTRY:
            ret = do_invalidate_dte(d, cmd);
            break;
        case IOMMU_CMD_INVALIDATE_IOMMU_PAGES:
            ret = do_invalidate_pages(d, cmd);
            break;
        case IOMMU_CMD_INVALIDATE_IOTLB_PAGES:
            ret = do_invalidate_iotlb_pages(d, cmd);
            break;
        case IOMMU_CMD_INVALIDATE_INT_TABLE:
            break;
        case IOMMU_CMD_COMPLETE_PPR_REQUEST:
            ret = do_complete_ppr_request(d, cmd);
            break;
        case IOMMU_CMD_INVALIDATE_IOMMU_ALL:
            ret = do_invalidate_all(d, cmd);
            break;
        default:
            AMD_IOMMU_DEBUG("CMD: Unknown command cmd_type = %lx "
                            "head = %ld\n", opcode, head);
            break;
        }

        unmap_domain_page(cmd_base);
        if ( ++head >= iommu->cmd_buffer.entries )
            head = 0;
        if ( ret )
            guest_iommu_disable(iommu);
    }

    /* Now shift cmd buffer head pointer */
    iommu_set_rb_pointer(&iommu->cmd_buffer.reg_head.lo, head);
    return;
}

static int guest_iommu_write_ctrl(struct guest_iommu *iommu, uint64_t newctrl)
{
    bool_t cmd_en, event_en, iommu_en, ppr_en, ppr_log_en;
    bool_t cmd_en_old, event_en_old, iommu_en_old;
    bool_t cmd_run;

    iommu_en = iommu_get_bit(newctrl,
                             IOMMU_CONTROL_TRANSLATION_ENABLE_SHIFT);
    iommu_en_old = iommu_get_bit(iommu->reg_ctrl.lo,
                                 IOMMU_CONTROL_TRANSLATION_ENABLE_SHIFT);

    cmd_en = iommu_get_bit(newctrl,
                           IOMMU_CONTROL_COMMAND_BUFFER_ENABLE_SHIFT);
    cmd_en_old = iommu_get_bit(iommu->reg_ctrl.lo,
                               IOMMU_CONTROL_COMMAND_BUFFER_ENABLE_SHIFT);
    cmd_run = iommu_get_bit(iommu->reg_status.lo,
                            IOMMU_STATUS_CMD_BUFFER_RUN_SHIFT);
    event_en = iommu_get_bit(newctrl,
                             IOMMU_CONTROL_EVENT_LOG_ENABLE_SHIFT);
    event_en_old = iommu_get_bit(iommu->reg_ctrl.lo,
                                 IOMMU_CONTROL_EVENT_LOG_ENABLE_SHIFT);

    ppr_en = iommu_get_bit(newctrl,
                           IOMMU_CONTROL_PPR_ENABLE_SHIFT);
    ppr_log_en = iommu_get_bit(newctrl,
                               IOMMU_CONTROL_PPR_LOG_ENABLE_SHIFT);

    if ( iommu_en )
    {
        guest_iommu_enable(iommu);
        guest_iommu_enable_dev_table(iommu);
    }

    if ( iommu_en && cmd_en )
    {
        guest_iommu_enable_ring_buffer(iommu, &iommu->cmd_buffer,
                                       sizeof(cmd_entry_t));
        /* Enable iommu command processing */
        tasklet_schedule(&iommu->cmd_buffer_tasklet);
    }

    if ( iommu_en && event_en )
    {
        guest_iommu_enable_ring_buffer(iommu, &iommu->event_log,
                                       sizeof(event_entry_t));
        guest_iommu_set_status(iommu, IOMMU_STATUS_EVENT_LOG_RUN_SHIFT);
        guest_iommu_clear_status(iommu, IOMMU_STATUS_EVENT_OVERFLOW_SHIFT);
    }

    if ( iommu_en && ppr_en && ppr_log_en )
    {
        guest_iommu_enable_ring_buffer(iommu, &iommu->ppr_log,
                                       sizeof(ppr_entry_t));
        guest_iommu_set_status(iommu, IOMMU_STATUS_PPR_LOG_RUN_SHIFT);
        guest_iommu_clear_status(iommu, IOMMU_STATUS_PPR_LOG_OVERFLOW_SHIFT);
    }

    if ( iommu_en && cmd_en_old && !cmd_en )
    {
        /* Disable iommu command processing */
        tasklet_kill(&iommu->cmd_buffer_tasklet);
    }

    if ( event_en_old && !event_en )
        guest_iommu_clear_status(iommu, IOMMU_STATUS_EVENT_LOG_RUN_SHIFT);

    if ( iommu_en_old && !iommu_en )
        guest_iommu_disable(iommu);

    u64_to_reg(&iommu->reg_ctrl, newctrl);
    return 0;
}

static uint64_t iommu_mmio_read64(struct guest_iommu *iommu,
                                  unsigned long offset)
{
    uint64_t val;

    switch ( offset )
    {
    case IOMMU_DEV_TABLE_BASE_LOW_OFFSET:
        val = reg_to_u64(iommu->dev_table.reg_base);
        break;
    case IOMMU_CMD_BUFFER_BASE_LOW_OFFSET:
        val = reg_to_u64(iommu->cmd_buffer.reg_base);
        break;
    case IOMMU_EVENT_LOG_BASE_LOW_OFFSET:
        val = reg_to_u64(iommu->event_log.reg_base);
        break;
    case IOMMU_PPR_LOG_BASE_LOW_OFFSET:
        val = reg_to_u64(iommu->ppr_log.reg_base);
        break;
    case IOMMU_CMD_BUFFER_HEAD_OFFSET:
        val = reg_to_u64(iommu->cmd_buffer.reg_head);
        break;
    case IOMMU_CMD_BUFFER_TAIL_OFFSET:
        val = reg_to_u64(iommu->cmd_buffer.reg_tail);
        break;
    case IOMMU_EVENT_LOG_HEAD_OFFSET:
        val = reg_to_u64(iommu->event_log.reg_head);
        break;
    case IOMMU_EVENT_LOG_TAIL_OFFSET:
        val = reg_to_u64(iommu->event_log.reg_tail);
        break;
    case IOMMU_PPR_LOG_HEAD_OFFSET:
        val = reg_to_u64(iommu->ppr_log.reg_head);
        break;
    case IOMMU_PPR_LOG_TAIL_OFFSET:
        val = reg_to_u64(iommu->ppr_log.reg_tail);
        break;
    case IOMMU_CONTROL_MMIO_OFFSET:
        val = reg_to_u64(iommu->reg_ctrl);
        break;
    case IOMMU_STATUS_MMIO_OFFSET:
        val = reg_to_u64(iommu->reg_status);
        break;
    case IOMMU_EXT_FEATURE_MMIO_OFFSET:
        val = reg_to_u64(iommu->reg_ext_feature);
        break;

    default:
        AMD_IOMMU_DEBUG("Guest reads unknown mmio offset = %lx\n", offset);
        val = 0;
        break;
    }

    return val;
}

static int guest_iommu_mmio_read(struct vcpu *v, unsigned long addr,
                                 unsigned int len, unsigned long *pval)
{
    struct guest_iommu *iommu = vcpu_iommu(v);
    unsigned long offset;
    uint64_t val;
    uint32_t mmio, shift;
    uint64_t mask = 0;

    offset = addr - iommu->mmio_base;

    if ( unlikely((offset & (len - 1 )) || (len > 8)) )
    {
        AMD_IOMMU_DEBUG("iommu mmio read access is not aligned:"
                        " offset = %lx, len = %x\n", offset, len);
        return X86EMUL_UNHANDLEABLE;
    }

    mask = (len == 8) ? ~0ULL : (1ULL << (len * 8)) - 1;
    shift = (offset & 7u) * 8;

    /* mmio access is always aligned on 8-byte boundary */
    mmio = offset & (~7u);

    spin_lock(&iommu->lock);
    val = iommu_mmio_read64(iommu, mmio);
    spin_unlock(&iommu->lock);

    *pval = (val >> shift ) & mask;

    return X86EMUL_OKAY;
}

static void guest_iommu_mmio_write64(struct guest_iommu *iommu,
                                    unsigned long offset, uint64_t val)
{
    switch ( offset )
    {
    case IOMMU_DEV_TABLE_BASE_LOW_OFFSET:
        u64_to_reg(&iommu->dev_table.reg_base, val);
        break;
    case IOMMU_CMD_BUFFER_BASE_LOW_OFFSET:
        u64_to_reg(&iommu->cmd_buffer.reg_base, val);
        break;
    case IOMMU_EVENT_LOG_BASE_LOW_OFFSET:
        u64_to_reg(&iommu->event_log.reg_base, val);
        break;
    case IOMMU_PPR_LOG_BASE_LOW_OFFSET:
        u64_to_reg(&iommu->ppr_log.reg_base, val);
        break;
    case IOMMU_CONTROL_MMIO_OFFSET:
        guest_iommu_write_ctrl(iommu, val);
        break;
    case IOMMU_CMD_BUFFER_HEAD_OFFSET:
        u64_to_reg(&iommu->cmd_buffer.reg_head, val);
        break;
    case IOMMU_CMD_BUFFER_TAIL_OFFSET:
        u64_to_reg(&iommu->cmd_buffer.reg_tail, val);
        tasklet_schedule(&iommu->cmd_buffer_tasklet);
        break;
    case IOMMU_EVENT_LOG_HEAD_OFFSET:
        u64_to_reg(&iommu->event_log.reg_head, val);
        break;
    case IOMMU_EVENT_LOG_TAIL_OFFSET:
        u64_to_reg(&iommu->event_log.reg_tail, val);
        break;
    case IOMMU_PPR_LOG_HEAD_OFFSET:
        u64_to_reg(&iommu->ppr_log.reg_head, val);
        break;
    case IOMMU_PPR_LOG_TAIL_OFFSET:
        u64_to_reg(&iommu->ppr_log.reg_tail, val);
        break;
    case IOMMU_STATUS_MMIO_OFFSET:
        val &= IOMMU_STATUS_EVENT_OVERFLOW_MASK |
               IOMMU_STATUS_EVENT_LOG_INT_MASK |
               IOMMU_STATUS_COMP_WAIT_INT_MASK |
               IOMMU_STATUS_PPR_LOG_OVERFLOW_MASK |
               IOMMU_STATUS_PPR_LOG_INT_MASK |
               IOMMU_STATUS_GAPIC_LOG_OVERFLOW_MASK |
               IOMMU_STATUS_GAPIC_LOG_INT_MASK;
        u64_to_reg(&iommu->reg_status, reg_to_u64(iommu->reg_status) & ~val);
        break;

    default:
        AMD_IOMMU_DEBUG("guest writes unknown mmio offset = %lx,"
                        " val = %" PRIx64 "\n", offset, val);
        break;
    }
}

static int guest_iommu_mmio_write(struct vcpu *v, unsigned long addr,
                                  unsigned int len, unsigned long val)
{
    struct guest_iommu *iommu = vcpu_iommu(v);
    unsigned long offset;
    uint64_t reg_old, mmio;
    uint32_t shift;
    uint64_t mask = 0;

    offset = addr - iommu->mmio_base;

    if ( unlikely((offset & (len - 1)) || (len > 8)) )
    {
        AMD_IOMMU_DEBUG("iommu mmio write access is not aligned:"
                        " offset = %lx, len = %x\n", offset, len);
        return X86EMUL_UNHANDLEABLE;
    }

    mask = (len == 8) ? ~0ULL : (1ULL << (len * 8)) - 1;
    shift = (offset & 7) * 8;

    /* mmio access is always aligned on 8-byte boundary */
    mmio = offset & ~7;

    spin_lock(&iommu->lock);

    reg_old = iommu_mmio_read64(iommu, mmio);
    reg_old &= ~(mask << shift);
    val = reg_old | ((val & mask) << shift);
    guest_iommu_mmio_write64(iommu, mmio, val);

    spin_unlock(&iommu->lock);

    return X86EMUL_OKAY;
}

int guest_iommu_set_base(struct domain *d, uint64_t base)
{
    p2m_type_t t;
    struct guest_iommu *iommu = domain_iommu(d);

    if ( !iommu )
        return -EACCES;

    iommu->mmio_base = base;
    base >>= PAGE_SHIFT;

    for ( int i = 0; i < IOMMU_MMIO_PAGE_NR; i++ )
    {
        unsigned long gfn = base + i;

        get_gfn_query(d, gfn, &t);
        p2m_change_type_one(d, gfn, t, p2m_mmio_dm);
        put_gfn(d, gfn);
    }

    return 0;
}

/* Initialize mmio read only bits */
static void guest_iommu_reg_init(struct guest_iommu *iommu)
{
    uint32_t lower, upper;

    lower = upper = 0;
    /* Support prefetch */
    iommu_set_bit(&lower,IOMMU_EXT_FEATURE_PREFSUP_SHIFT);
    /* Support PPR log */
    iommu_set_bit(&lower,IOMMU_EXT_FEATURE_PPRSUP_SHIFT);
    /* Support guest translation */
    iommu_set_bit(&lower,IOMMU_EXT_FEATURE_GTSUP_SHIFT);
    /* Support invalidate all command */
    iommu_set_bit(&lower,IOMMU_EXT_FEATURE_IASUP_SHIFT);

    /* Host translation size has 6 levels */
    set_field_in_reg_u32(HOST_ADDRESS_SIZE_6_LEVEL, lower,
                         IOMMU_EXT_FEATURE_HATS_MASK,
                         IOMMU_EXT_FEATURE_HATS_SHIFT,
                         &lower);
    /* Guest translation size has 6 levels */
    set_field_in_reg_u32(GUEST_ADDRESS_SIZE_6_LEVEL, lower,
                         IOMMU_EXT_FEATURE_GATS_MASK,
                         IOMMU_EXT_FEATURE_GATS_SHIFT,
                         &lower);
    /* Single level gCR3 */
    set_field_in_reg_u32(GUEST_CR3_1_LEVEL, lower,
                         IOMMU_EXT_FEATURE_GLXSUP_MASK,
                         IOMMU_EXT_FEATURE_GLXSUP_SHIFT, &lower);
    /* 9 bit PASID */
    set_field_in_reg_u32(PASMAX_9_bit, upper,
                         IOMMU_EXT_FEATURE_PASMAX_MASK,
                         IOMMU_EXT_FEATURE_PASMAX_SHIFT, &upper);

    iommu->reg_ext_feature.lo = lower;
    iommu->reg_ext_feature.hi = upper;
}

static int guest_iommu_mmio_range(struct vcpu *v, unsigned long addr)
{
    struct guest_iommu *iommu = vcpu_iommu(v);

    return iommu && addr >= iommu->mmio_base &&
           addr < iommu->mmio_base + IOMMU_MMIO_SIZE;
}

static const struct hvm_mmio_ops iommu_mmio_ops = {
    .check = guest_iommu_mmio_range,
    .read = guest_iommu_mmio_read,
    .write = guest_iommu_mmio_write
};

/* Domain specific initialization */
int guest_iommu_init(struct domain* d)
{
    struct guest_iommu *iommu;
    struct domain_iommu *hd = dom_iommu(d);

    if ( !is_hvm_domain(d) || !iommu_enabled || !iommuv2_enabled ||
         !has_viommu(d) )
        return 0;

    iommu = xzalloc(struct guest_iommu);
    if ( !iommu )
    {
        AMD_IOMMU_DEBUG("Error allocating guest iommu structure.\n");
        return 1;
    }

    guest_iommu_reg_init(iommu);
    iommu->mmio_base = ~0ULL;
    iommu->domain = d;
    hd->arch.g_iommu = iommu;

    tasklet_init(&iommu->cmd_buffer_tasklet,
                 guest_iommu_process_command, (unsigned long)d);

    spin_lock_init(&iommu->lock);

    register_mmio_handler(d, &iommu_mmio_ops);

    return 0;
}

void guest_iommu_destroy(struct domain *d)
{
    struct guest_iommu *iommu;

    iommu = domain_iommu(d);
    if ( !iommu )
        return;

    tasklet_kill(&iommu->cmd_buffer_tasklet);
    xfree(iommu);

    dom_iommu(d)->arch.g_iommu = NULL;
}
