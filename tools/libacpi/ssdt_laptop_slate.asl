/* SPDX-License-Identifier: LGPL-2.1-only */
/*
 * ssdt_conv.asl
 *
 * Copyright (c) 2017  Citrix Systems, Inc.
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
