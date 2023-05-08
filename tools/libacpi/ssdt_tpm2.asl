/* SPDX-License-Identifier: LGPL-2.1-only */
/*
 * ssdt_tpm2.asl
 *
 * Copyright (c) 2018-2022, Citrix Systems, Inc.
 */

/* SSDT for TPM CRB Interface for Xen with Qemu device model. */

DefinitionBlock ("SSDT_TPM2.aml", "SSDT", 2, "Xen", "HVM", 0)
{
    Device (TPM)
    {
        Name (_HID, "MSFT0101" /* TPM 2.0 Security Device */)  // _HID: Hardware ID
        Name (_CRS, ResourceTemplate ()  // _CRS: Current Resource Settings
        {
            Memory32Fixed (ReadWrite,
                0xFED40000,         // Address Base
                0x00001000,         // Address Length
                )
        })
        Method (_STA, 0, NotSerialized)  // _STA: Status
        {
            Return (0x0F)
        }
    }
}
