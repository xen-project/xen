/*
 * ssdt_conv.asl
 *
 * Copyright (c) 2017  Citrix Systems, Inc.
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

/*
 * Windows laptop/slate mode device
 *
 * See https://msdn.microsoft.com/en-us/windows/hardware/commercialize/design/device-experiences/continuum#method-2----use-the-injection-interface
 */

DefinitionBlock ("SSDT_LAPTOP_SLATE.aml", "SSDT", 2, "Xen", "HVM", 0)
{
    Device (CONV) {
        Method (_HID, 0x0, NotSerialized) {
            Return("ID9001")
        }
        Name (_CID, "PNP0C60")
    }
}

/*
 * Local variables:
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
