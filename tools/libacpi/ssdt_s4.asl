/* SPDX-License-Identifier: LGPL-2.1-only */
/*
 * ssdt_s4.asl
 *
 * Copyright (c) 2011  Citrix Systems, Inc.
 */

DefinitionBlock ("SSDT_S4.aml", "SSDT", 2, "Xen", "HVM", 0)
{
    /* Must match piix emulation */
    Name (\_S4, Package (0x04)
    {
        0x00,  /* PM1a_CNT.SLP_TYP */
        0x00,  /* PM1b_CNT.SLP_TYP */
        0x00,  /* reserved */
        0x00   /* reserved */
    })
}

