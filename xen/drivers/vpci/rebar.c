/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2025 Advanced Micro Devices, Inc. All Rights Reserved.
 *
 * Author: Jiqian Chen <Jiqian.Chen@amd.com>
 */

#include <xen/sched.h>
#include <xen/vpci.h>

static void cf_check rebar_ctrl_write(const struct pci_dev *pdev,
                                      unsigned int reg,
                                      uint32_t val,
                                      void *data)
{
    struct vpci_bar *bar = data;
    const unsigned int index = bar - pdev->vpci->header.bars;
    const uint64_t size = PCI_REBAR_CTRL_SIZE(val);

    if ( bar->enabled )
    {
        /*
         * Refuse to resize a BAR while memory decoding is enabled, as
         * otherwise the size of the mapped region in the p2m would become
         * stale with the newly set BAR size, and the position of the BAR
         * would be reset to undefined.  Note the PCIe specification also
         * forbids resizing a BAR with memory decoding enabled.
         */
        if ( size != bar->size )
            gprintk(XENLOG_ERR,
                    "%pp: refuse to resize BAR#%u with memory decoding enabled\n",
                    &pdev->sbdf, index);
        return;
    }

    if ( !((size >> PCI_REBAR_CTRL_SIZE_BIAS) & bar->resizable_sizes) )
        gprintk(XENLOG_WARNING,
                "%pp: new BAR#%u size %#lx is not supported by hardware\n",
                &pdev->sbdf, index, size);

    pci_conf_write32(pdev->sbdf, reg, val);

    pci_size_mem_bar(pdev->sbdf,
                     PCI_BASE_ADDRESS_0 + index * 4,
                     &bar->addr,
                     &bar->size,
                     (index == PCI_HEADER_NORMAL_NR_BARS - 1) ?
                      PCI_BAR_LAST : 0);
    bar->guest_addr = bar->addr;
}

static int cf_check init_rebar(struct pci_dev *pdev)
{
    uint32_t ctrl;
    unsigned int nbars;
    unsigned int rebar_offset = pci_find_ext_capability(pdev->sbdf,
                                                        PCI_EXT_CAP_ID_REBAR);

    if ( !rebar_offset )
        return 0;

    if ( !is_hardware_domain(pdev->domain) )
    {
        printk(XENLOG_ERR "%pp: resizable BARs unsupported for unpriv %pd\n",
               &pdev->sbdf, pdev->domain);
        return -EOPNOTSUPP;
    }

    ctrl = pci_conf_read32(pdev->sbdf, rebar_offset + PCI_REBAR_CTRL(0));
    nbars = MASK_EXTR(ctrl, PCI_REBAR_CTRL_NBAR_MASK);
    for ( unsigned int i = 0; i < nbars; i++ )
    {
        int rc;
        struct vpci_bar *bar;
        unsigned int index;

        ctrl = pci_conf_read32(pdev->sbdf, rebar_offset + PCI_REBAR_CTRL(i));
        index = ctrl & PCI_REBAR_CTRL_BAR_IDX;
        if ( index >= PCI_HEADER_NORMAL_NR_BARS )
        {
            printk(XENLOG_ERR "%pd %pp: too big BAR number %u in REBAR_CTRL\n",
                   pdev->domain, &pdev->sbdf, index);
            continue;
        }

        bar = &pdev->vpci->header.bars[index];
        if ( bar->type != VPCI_BAR_MEM64_LO && bar->type != VPCI_BAR_MEM32 )
        {
            printk(XENLOG_ERR "%pd %pp: BAR%u is not in memory space\n",
                   pdev->domain, &pdev->sbdf, index);
            continue;
        }

        rc = vpci_add_register(pdev->vpci, vpci_hw_read32, rebar_ctrl_write,
                               rebar_offset + PCI_REBAR_CTRL(i), 4, bar);
        if ( rc )
        {
            printk(XENLOG_ERR "%pd %pp: BAR%u fail to add reg of REBAR_CTRL rc=%d\n",
                   pdev->domain, &pdev->sbdf, index, rc);
            /*
             * Ideally we would hide the ReBar capability on error, but code
             * for doing so still needs to be written. Use continue instead
             * to keep any already setup register hooks, as returning an
             * error will cause the hardware domain to get unmediated access
             * to all device registers.
             */
            continue;
        }

        bar->resizable_sizes =
            MASK_EXTR(pci_conf_read32(pdev->sbdf,
                                      rebar_offset + PCI_REBAR_CAP(i)),
                      PCI_REBAR_CAP_SIZES_MASK);
        bar->resizable_sizes |=
            (((uint64_t)MASK_EXTR(ctrl, PCI_REBAR_CTRL_SIZES_MASK) << 32) /
             ISOLATE_LSB(PCI_REBAR_CAP_SIZES_MASK));
    }

    return 0;
}
REGISTER_VPCI_EXTCAP(REBAR, init_rebar, NULL);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
