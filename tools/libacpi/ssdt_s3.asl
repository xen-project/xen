/* SPDX-License-Identifier: LGPL-2.1-only */
/*
 * ssdt_s3.asl
 *
 * Copyright (c) 2011  Citrix Systems, Inc.
 */

DefinitionBlock ("SSDT_S3.aml", "SSDT", 2, "Xen", "HVM", 0)
{
    /* Must match piix emulation */
    Name (\_S3, Package (0x04)
    {
        0x01,  /* PM1a_CNT.SLP_TYP */
        0x01,  /* PM1b_CNT.SLP_TYP */
        0x0,   /* reserved */
        0x0    /* reserved */
    })
}

