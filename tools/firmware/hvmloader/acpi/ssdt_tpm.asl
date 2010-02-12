/*
 * ssdt_tpm.asl
 *
 * Copyright (c) 2006, IBM Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
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
