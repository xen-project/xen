/*
 * Copyright (C) 2007 Advanced Micro Devices, Inc.
 * Author: Leo Duran <leo.duran@amd.com>
 * Author: Wei Wang <wei.wang2@amd.com> - adapted to xen
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */

#include <xen/sched.h>
#include <xen/hvm/iommu.h>
#include <asm/amd-iommu.h>
#include <asm/hvm/svm/amd-iommu-proto.h>

extern long amd_iommu_poll_comp_wait;

static int queue_iommu_command(struct amd_iommu *iommu, u32 cmd[])
{
    u32 tail, head, *cmd_buffer;
    int i;

    tail = iommu->cmd_buffer_tail;
    if ( ++tail == iommu->cmd_buffer.entries )
        tail = 0;
    head = get_field_from_reg_u32(
        readl(iommu->mmio_base+IOMMU_CMD_BUFFER_HEAD_OFFSET),
        IOMMU_CMD_BUFFER_HEAD_MASK,
        IOMMU_CMD_BUFFER_HEAD_SHIFT);
    if ( head != tail )
    {
        cmd_buffer = (u32 *)(iommu->cmd_buffer.buffer +
                             (iommu->cmd_buffer_tail *
                              IOMMU_CMD_BUFFER_ENTRY_SIZE));
        for ( i = 0; i < IOMMU_CMD_BUFFER_U32_PER_ENTRY; i++ )
            cmd_buffer[i] = cmd[i];

        iommu->cmd_buffer_tail = tail;
        return 1;
    }

    return 0;
}

static void commit_iommu_command_buffer(struct amd_iommu *iommu)
{
    u32 tail;

    set_field_in_reg_u32(iommu->cmd_buffer_tail, 0,
                         IOMMU_CMD_BUFFER_TAIL_MASK,
                         IOMMU_CMD_BUFFER_TAIL_SHIFT, &tail);
    writel(tail, iommu->mmio_base+IOMMU_CMD_BUFFER_TAIL_OFFSET);
}

int send_iommu_command(struct amd_iommu *iommu, u32 cmd[])
{
    if ( queue_iommu_command(iommu, cmd) )
    {
        commit_iommu_command_buffer(iommu);
        return 1;
    }

    return 0;
}

static void invalidate_iommu_page(struct amd_iommu *iommu,
                                  u64 io_addr, u16 domain_id)
{
    u64 addr_lo, addr_hi;
    u32 cmd[4], entry;

    addr_lo = io_addr & DMA_32BIT_MASK;
    addr_hi = io_addr >> 32;

    set_field_in_reg_u32(domain_id, 0,
                         IOMMU_INV_IOMMU_PAGES_DOMAIN_ID_MASK,
                         IOMMU_INV_IOMMU_PAGES_DOMAIN_ID_SHIFT, &entry);
    set_field_in_reg_u32(IOMMU_CMD_INVALIDATE_IOMMU_PAGES, entry,
                         IOMMU_CMD_OPCODE_MASK, IOMMU_CMD_OPCODE_SHIFT,
                         &entry);
    cmd[1] = entry;

    set_field_in_reg_u32(IOMMU_CONTROL_DISABLED, 0,
                         IOMMU_INV_IOMMU_PAGES_S_FLAG_MASK,
                         IOMMU_INV_IOMMU_PAGES_S_FLAG_SHIFT, &entry);
    set_field_in_reg_u32(IOMMU_CONTROL_DISABLED, entry,
                         IOMMU_INV_IOMMU_PAGES_PDE_FLAG_MASK,
                         IOMMU_INV_IOMMU_PAGES_PDE_FLAG_SHIFT, &entry);
    set_field_in_reg_u32((u32)addr_lo >> PAGE_SHIFT, entry,
                         IOMMU_INV_IOMMU_PAGES_ADDR_LOW_MASK,
                         IOMMU_INV_IOMMU_PAGES_ADDR_LOW_SHIFT, &entry);
    cmd[2] = entry;

    set_field_in_reg_u32((u32)addr_hi, 0,
                         IOMMU_INV_IOMMU_PAGES_ADDR_HIGH_MASK,
                         IOMMU_INV_IOMMU_PAGES_ADDR_HIGH_SHIFT, &entry);
    cmd[3] = entry;

    cmd[0] = 0;
    send_iommu_command(iommu, cmd);
}

void flush_command_buffer(struct amd_iommu *iommu)
{
    u32 cmd[4], status;
    int loop_count, comp_wait;

    /* clear 'ComWaitInt' in status register (WIC) */
    set_field_in_reg_u32(IOMMU_CONTROL_ENABLED, 0,
                         IOMMU_STATUS_COMP_WAIT_INT_MASK,
                         IOMMU_STATUS_COMP_WAIT_INT_SHIFT, &status);
    writel(status, iommu->mmio_base + IOMMU_STATUS_MMIO_OFFSET);

    /* send an empty COMPLETION_WAIT command to flush command buffer */
    cmd[3] = cmd[2] = 0;
    set_field_in_reg_u32(IOMMU_CMD_COMPLETION_WAIT, 0,
                         IOMMU_CMD_OPCODE_MASK,
                         IOMMU_CMD_OPCODE_SHIFT, &cmd[1]);
    set_field_in_reg_u32(IOMMU_CONTROL_ENABLED, 0,
                         IOMMU_COMP_WAIT_I_FLAG_MASK,
                         IOMMU_COMP_WAIT_I_FLAG_SHIFT, &cmd[0]);
    send_iommu_command(iommu, cmd);

    /* wait for 'ComWaitInt' to signal comp#endifletion? */
    if ( amd_iommu_poll_comp_wait )
    {
        loop_count = amd_iommu_poll_comp_wait;
        do {
            status = readl(iommu->mmio_base +
                           IOMMU_STATUS_MMIO_OFFSET);
            comp_wait = get_field_from_reg_u32(
                status,
                IOMMU_STATUS_COMP_WAIT_INT_MASK,
                IOMMU_STATUS_COMP_WAIT_INT_SHIFT);
            --loop_count;
        } while ( loop_count && !comp_wait );

        if ( comp_wait )
        {
            /* clear 'ComWaitInt' in status register (WIC) */
            status &= IOMMU_STATUS_COMP_WAIT_INT_MASK;
            writel(status, iommu->mmio_base +
                   IOMMU_STATUS_MMIO_OFFSET);
        }
        else
        {
            amd_iov_warning("Warning: ComWaitInt bit did not assert!\n");
        }
    }
}

static void clear_page_table_entry_present(u32 *pte)
{
    set_field_in_reg_u32(IOMMU_CONTROL_DISABLED, pte[0],
                         IOMMU_PTE_PRESENT_MASK,
                         IOMMU_PTE_PRESENT_SHIFT, &pte[0]);
}

static void set_page_table_entry_present(u32 *pte, u64 page_addr,
                                         int iw, int ir)
{
    u64 addr_lo, addr_hi;
    u32 entry;

    addr_lo = page_addr & DMA_32BIT_MASK;
    addr_hi = page_addr >> 32;

    set_field_in_reg_u32((u32)addr_hi, 0,
                         IOMMU_PTE_ADDR_HIGH_MASK,
                         IOMMU_PTE_ADDR_HIGH_SHIFT, &entry);
    set_field_in_reg_u32(iw ? IOMMU_CONTROL_ENABLED :
                         IOMMU_CONTROL_DISABLED, entry,
                         IOMMU_PTE_IO_WRITE_PERMISSION_MASK,
                         IOMMU_PTE_IO_WRITE_PERMISSION_SHIFT, &entry);
    set_field_in_reg_u32(ir ? IOMMU_CONTROL_ENABLED :
                         IOMMU_CONTROL_DISABLED, entry,
                         IOMMU_PTE_IO_READ_PERMISSION_MASK,
                         IOMMU_PTE_IO_READ_PERMISSION_SHIFT, &entry);
    pte[1] = entry;

    set_field_in_reg_u32((u32)addr_lo >> PAGE_SHIFT, 0,
                         IOMMU_PTE_ADDR_LOW_MASK,
                         IOMMU_PTE_ADDR_LOW_SHIFT, &entry);
    set_field_in_reg_u32(IOMMU_PAGING_MODE_LEVEL_0, entry,
                         IOMMU_PTE_NEXT_LEVEL_MASK,
                         IOMMU_PTE_NEXT_LEVEL_SHIFT, &entry);
    set_field_in_reg_u32(IOMMU_CONTROL_ENABLED, entry,
                         IOMMU_PTE_PRESENT_MASK,
                         IOMMU_PTE_PRESENT_SHIFT, &entry);
    pte[0] = entry;
}


static void amd_iommu_set_page_directory_entry(u32 *pde, 
                                               u64 next_ptr, u8 next_level)
{
    u64 addr_lo, addr_hi;
    u32 entry;

    addr_lo = next_ptr & DMA_32BIT_MASK;
    addr_hi = next_ptr >> 32;

    /* enable read/write permissions,which will be enforced at the PTE */
    set_field_in_reg_u32((u32)addr_hi, 0,
                         IOMMU_PDE_ADDR_HIGH_MASK,
                         IOMMU_PDE_ADDR_HIGH_SHIFT, &entry);
    set_field_in_reg_u32(IOMMU_CONTROL_ENABLED, entry,
                         IOMMU_PDE_IO_WRITE_PERMISSION_MASK,
                         IOMMU_PDE_IO_WRITE_PERMISSION_SHIFT, &entry);
    set_field_in_reg_u32(IOMMU_CONTROL_ENABLED, entry,
                         IOMMU_PDE_IO_READ_PERMISSION_MASK,
                         IOMMU_PDE_IO_READ_PERMISSION_SHIFT, &entry);
    pde[1] = entry;

    /* mark next level as 'present' */
    set_field_in_reg_u32((u32)addr_lo >> PAGE_SHIFT, 0,
                         IOMMU_PDE_ADDR_LOW_MASK,
                         IOMMU_PDE_ADDR_LOW_SHIFT, &entry);
    set_field_in_reg_u32(next_level, entry,
                         IOMMU_PDE_NEXT_LEVEL_MASK,
                         IOMMU_PDE_NEXT_LEVEL_SHIFT, &entry);
    set_field_in_reg_u32(IOMMU_CONTROL_ENABLED, entry,
                         IOMMU_PDE_PRESENT_MASK,
                         IOMMU_PDE_PRESENT_SHIFT, &entry);
    pde[0] = entry;
}

void amd_iommu_set_dev_table_entry(u32 *dte, u64 root_ptr, u16 domain_id,
                                   u8 sys_mgt, u8 dev_ex, u8 paging_mode)
{
    u64 addr_hi, addr_lo;
    u32 entry;

    dte[7] = dte[6] = dte[5] = dte[4] = 0;

    set_field_in_reg_u32(sys_mgt, 0,
                         IOMMU_DEV_TABLE_SYS_MGT_MSG_ENABLE_MASK,
                         IOMMU_DEV_TABLE_SYS_MGT_MSG_ENABLE_SHIFT, &entry);
    set_field_in_reg_u32(dev_ex, entry,
                         IOMMU_DEV_TABLE_ALLOW_EXCLUSION_MASK,
                         IOMMU_DEV_TABLE_ALLOW_EXCLUSION_SHIFT, &entry);
    dte[3] = entry;

    set_field_in_reg_u32(domain_id, 0,
                         IOMMU_DEV_TABLE_DOMAIN_ID_MASK,
                         IOMMU_DEV_TABLE_DOMAIN_ID_SHIFT, &entry);
    dte[2] = entry;

    addr_lo = root_ptr & DMA_32BIT_MASK;
    addr_hi = root_ptr >> 32;
    set_field_in_reg_u32((u32)addr_hi, 0,
                         IOMMU_DEV_TABLE_PAGE_TABLE_PTR_HIGH_MASK,
                         IOMMU_DEV_TABLE_PAGE_TABLE_PTR_HIGH_SHIFT, &entry);
    set_field_in_reg_u32(IOMMU_CONTROL_ENABLED, entry,
                         IOMMU_DEV_TABLE_IO_WRITE_PERMISSION_MASK,
                         IOMMU_DEV_TABLE_IO_WRITE_PERMISSION_SHIFT, &entry);
    set_field_in_reg_u32(IOMMU_CONTROL_ENABLED, entry,
                         IOMMU_DEV_TABLE_IO_READ_PERMISSION_MASK,
                         IOMMU_DEV_TABLE_IO_READ_PERMISSION_SHIFT, &entry);
    dte[1] = entry;

    set_field_in_reg_u32((u32)addr_lo >> PAGE_SHIFT, 0,
                         IOMMU_DEV_TABLE_PAGE_TABLE_PTR_LOW_MASK,
                         IOMMU_DEV_TABLE_PAGE_TABLE_PTR_LOW_SHIFT, &entry);
    set_field_in_reg_u32(paging_mode, entry,
                         IOMMU_DEV_TABLE_PAGING_MODE_MASK,
                         IOMMU_DEV_TABLE_PAGING_MODE_SHIFT, &entry);
    set_field_in_reg_u32(IOMMU_CONTROL_ENABLED, entry,
                         IOMMU_DEV_TABLE_TRANSLATION_VALID_MASK,
                         IOMMU_DEV_TABLE_TRANSLATION_VALID_SHIFT, &entry);
    set_field_in_reg_u32(IOMMU_CONTROL_ENABLED, entry,
                         IOMMU_DEV_TABLE_VALID_MASK,
                         IOMMU_DEV_TABLE_VALID_SHIFT, &entry);
    dte[0] = entry;
}

void *amd_iommu_get_vptr_from_page_table_entry(u32 *entry)
{
    u64 addr_lo, addr_hi, ptr;

    addr_lo = get_field_from_reg_u32(
        entry[0],
        IOMMU_DEV_TABLE_PAGE_TABLE_PTR_LOW_MASK,
        IOMMU_DEV_TABLE_PAGE_TABLE_PTR_LOW_SHIFT);

    addr_hi = get_field_from_reg_u32(
        entry[1],
        IOMMU_DEV_TABLE_PAGE_TABLE_PTR_HIGH_MASK,
        IOMMU_DEV_TABLE_PAGE_TABLE_PTR_HIGH_SHIFT);

    ptr = (addr_hi << 32) | (addr_lo << PAGE_SHIFT);
    return ptr ? maddr_to_virt((unsigned long)ptr) : NULL;
}

static int amd_iommu_is_pte_present(u32 *entry)
{
    return (get_field_from_reg_u32(entry[0],
                                   IOMMU_PDE_PRESENT_MASK,
                                   IOMMU_PDE_PRESENT_SHIFT));
}

void invalidate_dev_table_entry(struct amd_iommu *iommu,
                                u16 device_id)
{
    u32 cmd[4], entry;

    cmd[3] = cmd[2] = 0;
    set_field_in_reg_u32(device_id, 0,
                         IOMMU_INV_DEVTAB_ENTRY_DEVICE_ID_MASK,
                         IOMMU_INV_DEVTAB_ENTRY_DEVICE_ID_SHIFT, &entry);
    cmd[0] = entry;

    set_field_in_reg_u32(IOMMU_CMD_INVALIDATE_DEVTAB_ENTRY, 0,
                         IOMMU_CMD_OPCODE_MASK, IOMMU_CMD_OPCODE_SHIFT,
                         &entry);
    cmd[1] = entry;

    send_iommu_command(iommu, cmd);
}

int amd_iommu_is_dte_page_translation_valid(u32 *entry)
{
    return (get_field_from_reg_u32(entry[0],
                                   IOMMU_DEV_TABLE_VALID_MASK,
                                   IOMMU_DEV_TABLE_VALID_SHIFT) &&
            get_field_from_reg_u32(entry[0],
                                   IOMMU_DEV_TABLE_TRANSLATION_VALID_MASK,
                                   IOMMU_DEV_TABLE_TRANSLATION_VALID_SHIFT));
}

static void *get_pte_from_page_tables(void *table, int level,
                                      unsigned long io_pfn)
{
    unsigned long offset;
    void *pde = NULL;

    BUG_ON(table == NULL);

    while ( level > 0 )
    {
        offset = io_pfn >> ((PTE_PER_TABLE_SHIFT *
                             (level - IOMMU_PAGING_MODE_LEVEL_1)));
        offset &= ~PTE_PER_TABLE_MASK;
        pde = table + (offset * IOMMU_PAGE_TABLE_ENTRY_SIZE);

        if ( level == 1 )
            break;
        if ( !pde )
            return NULL;
        if ( !amd_iommu_is_pte_present(pde) )
        {
            void *next_table = alloc_xenheap_page();
            if ( next_table == NULL )
                return NULL;
            memset(next_table, 0, PAGE_SIZE);
            if ( *(u64 *)pde == 0 )
            {
                unsigned long next_ptr = (u64)virt_to_maddr(next_table);
                amd_iommu_set_page_directory_entry(
                    (u32 *)pde, next_ptr, level - 1);
            }
            else
            {
                free_xenheap_page(next_table);
            }
        }
        table = amd_iommu_get_vptr_from_page_table_entry(pde);
        level--;
    }

    return pde;
}

int amd_iommu_map_page(struct domain *d, unsigned long gfn, unsigned long mfn)
{
    void *pte;
    unsigned long flags;
    u64 maddr;
    struct hvm_iommu *hd = domain_hvm_iommu(d);
    int iw = IOMMU_IO_WRITE_ENABLED;
    int ir = IOMMU_IO_READ_ENABLED;

    BUG_ON( !hd->root_table );

    spin_lock_irqsave(&hd->mapping_lock, flags);

    if ( is_hvm_domain(d) && !hd->p2m_synchronized )
        goto out;

    maddr = (u64)mfn << PAGE_SHIFT;
    pte = get_pte_from_page_tables(hd->root_table, hd->paging_mode, gfn);
    if ( pte == NULL )
    {
        amd_iov_error("Invalid IO pagetable entry gfn = %lx\n", gfn);
        spin_unlock_irqrestore(&hd->mapping_lock, flags);
        return -EFAULT;
    }

    set_page_table_entry_present((u32 *)pte, maddr, iw, ir);
out:
    spin_unlock_irqrestore(&hd->mapping_lock, flags);
    return 0;
}

int amd_iommu_unmap_page(struct domain *d, unsigned long gfn)
{
    void *pte;
    unsigned long flags;
    u64 io_addr = gfn;
    int requestor_id;
    struct amd_iommu *iommu;
    struct hvm_iommu *hd = domain_hvm_iommu(d);

    BUG_ON( !hd->root_table );

    spin_lock_irqsave(&hd->mapping_lock, flags);

    if ( is_hvm_domain(d) && !hd->p2m_synchronized )
    {
        spin_unlock_irqrestore(&hd->mapping_lock, flags);
        return 0;
    }

    requestor_id = hd->domain_id;
    io_addr = (u64)gfn << PAGE_SHIFT;

    pte = get_pte_from_page_tables(hd->root_table, hd->paging_mode, gfn);
    if ( pte == NULL )
    {
        amd_iov_error("Invalid IO pagetable entry gfn = %lx\n", gfn);
        spin_unlock_irqrestore(&hd->mapping_lock, flags);
        return -EFAULT;
    }

    /* mark PTE as 'page not present' */
    clear_page_table_entry_present((u32 *)pte);
    spin_unlock_irqrestore(&hd->mapping_lock, flags);

    /* send INVALIDATE_IOMMU_PAGES command */
    for_each_amd_iommu ( iommu )
    {
        spin_lock_irqsave(&iommu->lock, flags);
        invalidate_iommu_page(iommu, io_addr, requestor_id);
        flush_command_buffer(iommu);
        spin_unlock_irqrestore(&iommu->lock, flags);
    }

    return 0;
}

int amd_iommu_reserve_domain_unity_map(
    struct domain *domain,
    unsigned long phys_addr,
    unsigned long size, int iw, int ir)
{
    unsigned long flags, npages, i;
    void *pte;
    struct hvm_iommu *hd = domain_hvm_iommu(domain);

    npages = region_to_pages(phys_addr, size);

    spin_lock_irqsave(&hd->mapping_lock, flags);
    for ( i = 0; i < npages; ++i )
    {
        pte = get_pte_from_page_tables(
            hd->root_table, hd->paging_mode, phys_addr >> PAGE_SHIFT);
        if ( pte == NULL )
        {
            amd_iov_error(
            "Invalid IO pagetable entry phys_addr = %lx\n", phys_addr);
            spin_unlock_irqrestore(&hd->mapping_lock, flags);
            return -EFAULT;
        }
        set_page_table_entry_present((u32 *)pte,
                                     phys_addr, iw, ir);
        phys_addr += PAGE_SIZE;
    }
    spin_unlock_irqrestore(&hd->mapping_lock, flags);
    return 0;
}

int amd_iommu_sync_p2m(struct domain *d)
{
    unsigned long mfn, gfn, flags;
    void *pte;
    u64 maddr;
    struct list_head *entry;
    struct page_info *page;
    struct hvm_iommu *hd;
    int iw = IOMMU_IO_WRITE_ENABLED;
    int ir = IOMMU_IO_READ_ENABLED;

    if ( !is_hvm_domain(d) )
        return 0;

    hd = domain_hvm_iommu(d);

    spin_lock_irqsave(&hd->mapping_lock, flags);

    if ( hd->p2m_synchronized )
        goto out;

    for ( entry = d->page_list.next; entry != &d->page_list;
            entry = entry->next )
    {
        page = list_entry(entry, struct page_info, list);
        mfn = page_to_mfn(page);
        gfn = get_gpfn_from_mfn(mfn);

        if ( gfn == INVALID_M2P_ENTRY )
            continue;

        maddr = (u64)mfn << PAGE_SHIFT;
        pte = get_pte_from_page_tables(hd->root_table, hd->paging_mode, gfn);
        if ( pte == NULL )
        {
            amd_iov_error("Invalid IO pagetable entry gfn = %lx\n", gfn);
            spin_unlock_irqrestore(&hd->mapping_lock, flags);
            return -EFAULT;
        }
        set_page_table_entry_present((u32 *)pte, maddr, iw, ir);
    }

    hd->p2m_synchronized = 1;

out:
    spin_unlock_irqrestore(&hd->mapping_lock, flags);
    return 0;
}
