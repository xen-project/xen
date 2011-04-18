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
#include <asm/p2m.h>
#include <xen/hvm/iommu.h>
#include <asm/amd-iommu.h>
#include <asm/hvm/svm/amd-iommu-proto.h>

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

static void invalidate_iommu_pages(struct amd_iommu *iommu,
                                   u64 io_addr, u16 domain_id, u16 order)
{
    u64 addr_lo, addr_hi;
    u32 cmd[4], entry;
    u64 mask = 0;
    int sflag = 0, pde = 0;

    /* If sflag == 1, the size of the invalidate command is determined
     by the first zero bit in the address starting from Address[12] */
    if ( order == 9 || order == 18 )
    {
        mask = ((1ULL << (order - 1)) - 1) << PAGE_SHIFT;
        io_addr |= mask;
        sflag = 1;
    }

    /* All pages associated with the domainID are invalidated */
    else if ( io_addr == 0x7FFFFFFFFFFFF000ULL )
    {
        sflag = 1;
        pde = 1;
    }

    addr_lo = io_addr & DMA_32BIT_MASK;
    addr_hi = io_addr >> 32;

    set_field_in_reg_u32(domain_id, 0,
                         IOMMU_INV_IOMMU_PAGES_DOMAIN_ID_MASK,
                         IOMMU_INV_IOMMU_PAGES_DOMAIN_ID_SHIFT, &entry);
    set_field_in_reg_u32(IOMMU_CMD_INVALIDATE_IOMMU_PAGES, entry,
                         IOMMU_CMD_OPCODE_MASK, IOMMU_CMD_OPCODE_SHIFT,
                         &entry);
    cmd[1] = entry;

    set_field_in_reg_u32(sflag, 0,
                         IOMMU_INV_IOMMU_PAGES_S_FLAG_MASK,
                         IOMMU_INV_IOMMU_PAGES_S_FLAG_SHIFT, &entry);
    set_field_in_reg_u32(pde, entry,
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

    /* Make loop_count long enough for polling completion wait bit */
    loop_count = 1000;
    do {
        status = readl(iommu->mmio_base + IOMMU_STATUS_MMIO_OFFSET);
        comp_wait = get_field_from_reg_u32(status,
            IOMMU_STATUS_COMP_WAIT_INT_MASK,
            IOMMU_STATUS_COMP_WAIT_INT_SHIFT);
        --loop_count;
    } while ( !comp_wait && loop_count );

    if ( comp_wait )
    {
        /* clear 'ComWaitInt' in status register (WIC) */
        status &= IOMMU_STATUS_COMP_WAIT_INT_MASK;
        writel(status, iommu->mmio_base + IOMMU_STATUS_MMIO_OFFSET);
        return;
    }
    AMD_IOMMU_DEBUG("Warning: ComWaitInt bit did not assert!\n");
}

static void clear_iommu_l1e_present(u64 l2e, unsigned long gfn)
{
    u32 *l1e;
    int offset;
    void *l1_table;

    l1_table = map_domain_page(l2e >> PAGE_SHIFT);

    offset = gfn & (~PTE_PER_TABLE_MASK);
    l1e = (u32*)(l1_table + (offset * IOMMU_PAGE_TABLE_ENTRY_SIZE));

    /* clear l1 entry */
    l1e[0] = l1e[1] = 0;

    unmap_domain_page(l1_table);
}

static int set_iommu_l1e_present(u64 l2e, unsigned long gfn,
                                 u64 maddr, int iw, int ir)
{
    u64 addr_lo, addr_hi, maddr_old;
    u32 entry;
    void *l1_table;
    int offset;
    u32 *l1e;
    int need_flush = 0;

    l1_table = map_domain_page(l2e >> PAGE_SHIFT);

    offset = gfn & (~PTE_PER_TABLE_MASK);
    l1e = (u32*)((u8*)l1_table + (offset * IOMMU_PAGE_TABLE_ENTRY_SIZE));

    addr_hi = get_field_from_reg_u32(l1e[1],
                                     IOMMU_PTE_ADDR_HIGH_MASK,
                                     IOMMU_PTE_ADDR_HIGH_SHIFT);
    addr_lo = get_field_from_reg_u32(l1e[0],
                                     IOMMU_PTE_ADDR_LOW_MASK,
                                     IOMMU_PTE_ADDR_LOW_SHIFT);

    maddr_old = ((addr_hi << 32) | addr_lo) << PAGE_SHIFT;

    if ( maddr_old && (maddr_old != maddr) )
        need_flush = 1;

    addr_lo = maddr & DMA_32BIT_MASK;
    addr_hi = maddr >> 32;

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
    l1e[1] = entry;

    set_field_in_reg_u32((u32)addr_lo >> PAGE_SHIFT, 0,
                         IOMMU_PTE_ADDR_LOW_MASK,
                         IOMMU_PTE_ADDR_LOW_SHIFT, &entry);
    set_field_in_reg_u32(IOMMU_PAGING_MODE_LEVEL_0, entry,
                         IOMMU_PTE_NEXT_LEVEL_MASK,
                         IOMMU_PTE_NEXT_LEVEL_SHIFT, &entry);
    set_field_in_reg_u32(IOMMU_CONTROL_ENABLED, entry,
                         IOMMU_PTE_PRESENT_MASK,
                         IOMMU_PTE_PRESENT_SHIFT, &entry);
    l1e[0] = entry;

    unmap_domain_page(l1_table);
    return need_flush;
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

void amd_iommu_set_root_page_table(
    u32 *dte, u64 root_ptr, u16 domain_id, u8 paging_mode, u8 valid)
{
    u64 addr_hi, addr_lo;
    u32 entry;
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
    set_field_in_reg_u32(valid ? IOMMU_CONTROL_ENABLED :
                         IOMMU_CONTROL_DISABLED, entry,
                         IOMMU_DEV_TABLE_VALID_MASK,
                         IOMMU_DEV_TABLE_VALID_SHIFT, &entry);
    dte[0] = entry;
}

void amd_iommu_set_intremap_table(u32 *dte, u64 intremap_ptr, u8 int_valid)
{
    u64 addr_hi, addr_lo;
    u32 entry;

    addr_lo = intremap_ptr & DMA_32BIT_MASK;
    addr_hi = intremap_ptr >> 32;

    entry = dte[5];
    set_field_in_reg_u32((u32)addr_hi, entry,
                        IOMMU_DEV_TABLE_INT_TABLE_PTR_HIGH_MASK,
                        IOMMU_DEV_TABLE_INT_TABLE_PTR_HIGH_SHIFT, &entry);
    /* Fixed and arbitrated interrupts remapepd */
    set_field_in_reg_u32(2, entry,
                        IOMMU_DEV_TABLE_INT_CONTROL_MASK,
                        IOMMU_DEV_TABLE_INT_CONTROL_SHIFT, &entry);
    dte[5] = entry;

    set_field_in_reg_u32((u32)addr_lo >> 6, 0,
                        IOMMU_DEV_TABLE_INT_TABLE_PTR_LOW_MASK,
                        IOMMU_DEV_TABLE_INT_TABLE_PTR_LOW_SHIFT, &entry);
    /* 2048 entries */
    set_field_in_reg_u32(0xB, entry,
                         IOMMU_DEV_TABLE_INT_TABLE_LENGTH_MASK,
                         IOMMU_DEV_TABLE_INT_TABLE_LENGTH_SHIFT, &entry);

    /* unmapped interrupt results io page faults*/
    set_field_in_reg_u32(IOMMU_CONTROL_DISABLED, entry,
                         IOMMU_DEV_TABLE_INT_TABLE_IGN_UNMAPPED_MASK,
                         IOMMU_DEV_TABLE_INT_TABLE_IGN_UNMAPPED_SHIFT, &entry);
    set_field_in_reg_u32(int_valid ? IOMMU_CONTROL_ENABLED :
                         IOMMU_CONTROL_DISABLED, entry,
                         IOMMU_DEV_TABLE_INT_VALID_MASK,
                         IOMMU_DEV_TABLE_INT_VALID_SHIFT, &entry);
    dte[4] = entry;
}

void amd_iommu_add_dev_table_entry(
    u32 *dte, u8 sys_mgt, u8 dev_ex, u8 lint1_pass, u8 lint0_pass, 
    u8 nmi_pass, u8 ext_int_pass, u8 init_pass)
{
    u32 entry;

    dte[7] = dte[6] = dte[4] = dte[2] = dte[1] = dte[0] = 0;


    set_field_in_reg_u32(init_pass ? IOMMU_CONTROL_ENABLED :
                        IOMMU_CONTROL_DISABLED, 0,
                        IOMMU_DEV_TABLE_INIT_PASSTHRU_MASK,
                        IOMMU_DEV_TABLE_INIT_PASSTHRU_SHIFT, &entry);
    set_field_in_reg_u32(ext_int_pass ? IOMMU_CONTROL_ENABLED :
                        IOMMU_CONTROL_DISABLED, entry,
                        IOMMU_DEV_TABLE_EINT_PASSTHRU_MASK,
                        IOMMU_DEV_TABLE_EINT_PASSTHRU_SHIFT, &entry);
    set_field_in_reg_u32(nmi_pass ? IOMMU_CONTROL_ENABLED :
                        IOMMU_CONTROL_DISABLED, entry,
                        IOMMU_DEV_TABLE_NMI_PASSTHRU_MASK,
                        IOMMU_DEV_TABLE_NMI_PASSTHRU_SHIFT, &entry);
    set_field_in_reg_u32(lint0_pass ? IOMMU_CONTROL_ENABLED :
                        IOMMU_CONTROL_DISABLED, entry,
                        IOMMU_DEV_TABLE_LINT0_ENABLE_MASK,
                        IOMMU_DEV_TABLE_LINT0_ENABLE_SHIFT, &entry);
    set_field_in_reg_u32(lint1_pass ? IOMMU_CONTROL_ENABLED :
                        IOMMU_CONTROL_DISABLED, entry,
                        IOMMU_DEV_TABLE_LINT1_ENABLE_MASK,
                        IOMMU_DEV_TABLE_LINT1_ENABLE_SHIFT, &entry);
    dte[5] = entry;

    set_field_in_reg_u32(sys_mgt, 0,
                         IOMMU_DEV_TABLE_SYS_MGT_MSG_ENABLE_MASK,
                         IOMMU_DEV_TABLE_SYS_MGT_MSG_ENABLE_SHIFT, &entry);
    set_field_in_reg_u32(dev_ex, entry,
                         IOMMU_DEV_TABLE_ALLOW_EXCLUSION_MASK,
                         IOMMU_DEV_TABLE_ALLOW_EXCLUSION_SHIFT, &entry);
    dte[3] = entry;
}

u64 amd_iommu_get_next_table_from_pte(u32 *entry)
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
    return ptr;
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

static u64 iommu_l2e_from_pfn(struct page_info *table, int level,
                              unsigned long io_pfn)
{
    unsigned long offset;
    void *pde = NULL;
    void *table_vaddr;
    u64 next_table_maddr = 0;
    unsigned int lowest = 1;

    BUG_ON( table == NULL || level < lowest );

    if ( level == lowest )
        return page_to_maddr(table);

    while ( level > lowest )
    {
        offset = io_pfn >> ((PTE_PER_TABLE_SHIFT *
                             (level - IOMMU_PAGING_MODE_LEVEL_1)));
        offset &= ~PTE_PER_TABLE_MASK;

        table_vaddr = __map_domain_page(table);
        pde = table_vaddr + (offset * IOMMU_PAGE_TABLE_ENTRY_SIZE);
        next_table_maddr = amd_iommu_get_next_table_from_pte(pde);

        if ( !amd_iommu_is_pte_present(pde) )
        {
            if ( next_table_maddr == 0 )
            {
                table = alloc_amd_iommu_pgtable();
                if ( table == NULL )
                {
                    printk("AMD-Vi: Cannot allocate I/O page table\n");
                    return 0;
                }
                next_table_maddr = page_to_maddr(table);
                amd_iommu_set_page_directory_entry(
                    (u32 *)pde, next_table_maddr, level - 1);
            }
            else /* should never reach here */
                return 0;
        }

        unmap_domain_page(table_vaddr);
        table = maddr_to_page(next_table_maddr);
        level--;
    }

    return next_table_maddr;
}

static int update_paging_mode(struct domain *d, unsigned long gfn)
{
    u16 bdf;
    void *device_entry;
    unsigned int req_id, level, offset;
    unsigned long flags;
    struct pci_dev *pdev;
    struct amd_iommu *iommu = NULL;
    struct page_info *new_root = NULL;
    struct page_info *old_root = NULL;
    void *new_root_vaddr;
    u64 old_root_maddr;
    struct hvm_iommu *hd = domain_hvm_iommu(d);

    level = hd->paging_mode;
    old_root = hd->root_table;
    offset = gfn >> (PTE_PER_TABLE_SHIFT * (level - 1));

    ASSERT(spin_is_locked(&hd->mapping_lock) && is_hvm_domain(d));

    while ( offset >= PTE_PER_TABLE_SIZE )
    {
        /* Allocate and install a new root table.
         * Only upper I/O page table grows, no need to fix next level bits */
        new_root = alloc_amd_iommu_pgtable();
        if ( new_root == NULL )
        {
            AMD_IOMMU_DEBUG("%s Cannot allocate I/O page table\n",
                            __func__);
            return -ENOMEM;
        }

        new_root_vaddr = __map_domain_page(new_root);
        old_root_maddr = page_to_maddr(old_root);
        amd_iommu_set_page_directory_entry((u32 *)new_root_vaddr,
                                           old_root_maddr, level);
        level++;
        old_root = new_root;
        offset >>= PTE_PER_TABLE_SHIFT;
    }

    if ( new_root != NULL )
    {
        hd->paging_mode = level;
        hd->root_table = new_root;

        if ( !spin_is_locked(&pcidevs_lock) )
            AMD_IOMMU_DEBUG("%s Try to access pdev_list "
                            "without aquiring pcidevs_lock.\n", __func__);

        /* Update device table entries using new root table and paging mode */
        for_each_pdev( d, pdev )
        {
            bdf = (pdev->bus << 8) | pdev->devfn;
            req_id = get_dma_requestor_id(bdf);
            iommu = find_iommu_for_device(bdf);
            if ( !iommu )
            {
                AMD_IOMMU_DEBUG("%s Fail to find iommu.\n", __func__);
                return -ENODEV;
            }

            spin_lock_irqsave(&iommu->lock, flags);
            device_entry = iommu->dev_table.buffer +
                           (req_id * IOMMU_DEV_TABLE_ENTRY_SIZE);

            /* valid = 0 only works for dom0 passthrough mode */
            amd_iommu_set_root_page_table((u32 *)device_entry,
                                          page_to_maddr(hd->root_table),
                                          hd->domain_id,
                                          hd->paging_mode, 1);

            invalidate_dev_table_entry(iommu, req_id);
            flush_command_buffer(iommu);
            spin_unlock_irqrestore(&iommu->lock, flags);
        }

        /* For safety, invalidate all entries */
        amd_iommu_flush_all_pages(d);
    }
    return 0;
}

int amd_iommu_map_page(struct domain *d, unsigned long gfn, unsigned long mfn,
                       unsigned int flags)
{
    u64 iommu_l2e;
    int need_flush = 0;
    struct hvm_iommu *hd = domain_hvm_iommu(d);

    BUG_ON( !hd->root_table );

    if ( iommu_hap_pt_share && is_hvm_domain(d) )
        return 0;

    spin_lock(&hd->mapping_lock);

    /* Since HVM domain is initialized with 2 level IO page table,
     * we might need a deeper page table for lager gfn now */
    if ( is_hvm_domain(d) )
    {
        if ( update_paging_mode(d, gfn) )
        {
            AMD_IOMMU_DEBUG("Update page mode failed gfn = %lx\n", gfn);
            domain_crash(d);
            return -EFAULT;
        }
    }

    iommu_l2e = iommu_l2e_from_pfn(hd->root_table, hd->paging_mode, gfn);
    if ( iommu_l2e == 0 )
    {
        spin_unlock(&hd->mapping_lock);
        AMD_IOMMU_DEBUG("Invalid IO pagetable entry gfn = %lx\n", gfn);
        domain_crash(d);
        return -EFAULT;
    }

    need_flush = set_iommu_l1e_present(iommu_l2e, gfn, (u64)mfn << PAGE_SHIFT,
                                       !!(flags & IOMMUF_writable),
                                       !!(flags & IOMMUF_readable));
    if ( need_flush )
        amd_iommu_flush_pages(d, gfn, 0);

    spin_unlock(&hd->mapping_lock);
    return 0;
}

int amd_iommu_unmap_page(struct domain *d, unsigned long gfn)
{
    u64 iommu_l2e;
    struct hvm_iommu *hd = domain_hvm_iommu(d);

    BUG_ON( !hd->root_table );

    if ( iommu_hap_pt_share && is_hvm_domain(d) )
        return 0;

    spin_lock(&hd->mapping_lock);

    /* Since HVM domain is initialized with 2 level IO page table,
     * we might need a deeper page table for lager gfn now */
    if ( is_hvm_domain(d) )
    {
        if ( update_paging_mode(d, gfn) )
        {
            AMD_IOMMU_DEBUG("Update page mode failed gfn = %lx\n", gfn);
            domain_crash(d);
            return -EFAULT;
        }
    }

    iommu_l2e = iommu_l2e_from_pfn(hd->root_table, hd->paging_mode, gfn);

    if ( iommu_l2e == 0 )
    {
        spin_unlock(&hd->mapping_lock);
        AMD_IOMMU_DEBUG("Invalid IO pagetable entry gfn = %lx\n", gfn);
        domain_crash(d);
        return -EFAULT;
    }

    /* mark PTE as 'page not present' */
    clear_iommu_l1e_present(iommu_l2e, gfn);
    spin_unlock(&hd->mapping_lock);

    amd_iommu_flush_pages(d, gfn, 0);

    return 0;
}

int amd_iommu_reserve_domain_unity_map(struct domain *domain,
                                       u64 phys_addr,
                                       unsigned long size, int iw, int ir)
{
    unsigned long npages, i;
    unsigned long gfn;
    unsigned int flags = !!ir;
    int rt = 0;

    if ( iw )
        flags |= IOMMUF_writable;

    npages = region_to_pages(phys_addr, size);
    gfn = phys_addr >> PAGE_SHIFT;
    for ( i = 0; i < npages; i++ )
    {
        rt = amd_iommu_map_page(domain, gfn +i, gfn +i, flags);
        if ( rt != 0 )
            return rt;
    }
    return 0;
}


/* Flush iommu cache after p2m changes. */
static void _amd_iommu_flush_pages(struct domain *d,
                                   uint64_t gaddr, unsigned int order)
{
    unsigned long flags;
    struct amd_iommu *iommu;
    struct hvm_iommu *hd = domain_hvm_iommu(d);
    unsigned int dom_id = hd->domain_id;

    /* send INVALIDATE_IOMMU_PAGES command */
    for_each_amd_iommu ( iommu )
    {
        spin_lock_irqsave(&iommu->lock, flags);
        invalidate_iommu_pages(iommu, gaddr, dom_id, order);
        flush_command_buffer(iommu);
        spin_unlock_irqrestore(&iommu->lock, flags);
    }
}

void amd_iommu_flush_all_pages(struct domain *d)
{
    _amd_iommu_flush_pages(d, 0x7FFFFFFFFFFFFULL, 0);
}

void amd_iommu_flush_pages(struct domain *d,
                           unsigned long gfn, unsigned int order)
{
    _amd_iommu_flush_pages(d, (uint64_t) gfn << PAGE_SHIFT, order);
}

/* Share p2m table with iommu. */
void amd_iommu_share_p2m(struct domain *d)
{
    struct hvm_iommu *hd  = domain_hvm_iommu(d);
    struct page_info *p2m_table;
    mfn_t pgd_mfn;

    ASSERT( is_hvm_domain(d) && d->arch.hvm_domain.hap_enabled );

    pgd_mfn = pagetable_get_mfn(p2m_get_pagetable(p2m_get_hostp2m(d)));
    p2m_table = mfn_to_page(mfn_x(pgd_mfn));

    if ( hd->root_table != p2m_table )
    {
        free_amd_iommu_pgtable(hd->root_table);
        hd->root_table = p2m_table;

        /* When sharing p2m with iommu, paging mode = 4 */
        hd->paging_mode = IOMMU_PAGING_MODE_LEVEL_4;
        iommu_hap_pt_share = 1;

        AMD_IOMMU_DEBUG("Share p2m table with iommu: p2m table = 0x%lx\n",
                        mfn_x(pgd_mfn));
    }
}
