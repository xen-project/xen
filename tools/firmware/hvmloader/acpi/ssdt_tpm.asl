/*
 * ssdt_tpm.asl
 *
 * Copyright (c) 2006, IBM Corporation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
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
