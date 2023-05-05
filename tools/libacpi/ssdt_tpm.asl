/* SPDX-License-Identifier: LGPL-2.1-only */
/*
 * ssdt_tpm.asl
 *
 * Copyright (c) 2006, IBM Corporation.
 */

/* SSDT for TPM TIS Interface for Xen with Qemu device model. */

DefinitionBlock ("SSDT_TPM.aml", "SSDT", 2, "Xen", "HVM", 0)
{
    Device (TPM) {
        Name (_HID, EisaId ("PNP0C31"))
        Name (_CRS, ResourceTemplate ()
        {
            Memory32Fixed (ReadWrite, 0xFED40000, 0x5000,)
        })
    }
}
