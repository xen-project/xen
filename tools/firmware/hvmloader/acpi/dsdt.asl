/******************************************************************************
 * DSDT for Xen with Qemu device model
 *
 * Copyright (c) 2004, Intel Corporation.
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

DefinitionBlock ("DSDT.aml", "DSDT", 2, "Xen", "HVM", 0)
{
    Name (\PMBS, 0x0C00)
    Name (\PMLN, 0x08)
    Name (\IOB1, 0x00)
    Name (\IOL1, 0x00)
    Name (\APCB, 0xFEC00000)
    Name (\APCL, 0x00010000)
    Name (\PUID, 0x00)

    Scope (\_PR)
    {
        Processor (PR00, 0x00, 0x0000, 0x00) {}
        Processor (PR01, 0x01, 0x0000, 0x00) {}
        Processor (PR02, 0x02, 0x0000, 0x00) {}
        Processor (PR03, 0x03, 0x0000, 0x00) {}
        Processor (PR04, 0x04, 0x0000, 0x00) {}
        Processor (PR05, 0x05, 0x0000, 0x00) {}
        Processor (PR06, 0x06, 0x0000, 0x00) {}
        Processor (PR07, 0x07, 0x0000, 0x00) {}
        Processor (PR08, 0x08, 0x0000, 0x00) {}
        Processor (PR09, 0x09, 0x0000, 0x00) {}
        Processor (PR0A, 0x0a, 0x0000, 0x00) {}
        Processor (PR0B, 0x0b, 0x0000, 0x00) {}
        Processor (PR0C, 0x0c, 0x0000, 0x00) {}
        Processor (PR0D, 0x0d, 0x0000, 0x00) {}
        Processor (PR0E, 0x0e, 0x0000, 0x00) {}
        /* No more than 15 Processor objects, as otherwise Windows 2000
         * experiences a BSOD of KMODE_EXCEPTION_NOT_HANDLED. If we require
         * more in some configurations then we should move \_PR scope into a
         * SSDT, statically compiled with a range of different numbers of
         * processors. We can then link the appropriate one into the RSDT/XSDT
         * at HVM guest boot time. */
    }

    /*
     * S3 (suspend-to-ram), S4 (suspend-to-disc) and S5 (power-off) type codes:
     * must match piix4 emulation.
     */
    Name (\_S3, Package (0x04)
    {
        0x05,  /* PM1a_CNT.SLP_TYP */
        0x05,  /* PM1b_CNT.SLP_TYP */
        0x0,   /* reserved */
        0x0    /* reserved */
    })
    Name (\_S4, Package (0x04)
    {
        0x06,  /* PM1a_CNT.SLP_TYP */
        0x06,  /* PM1b_CNT.SLP_TYP */
        0x00,  /* reserved */
        0x00   /* reserved */
    })
    Name (\_S5, Package (0x04)
    {
        0x07,  /* PM1a_CNT.SLP_TYP */
        0x07,  /* PM1b_CNT.SLP_TYP */
        0x00,  /* reserved */
        0x00   /* reserved */
    })

    Name(PICD, 0)
    Method(_PIC, 1)
    {
        Store(Arg0, PICD) 
    }

    Scope (\_SB)
    {
       /* BIOS_INFO_PHYSICAL_ADDRESS == 0xEA000 */
       OperationRegion(BIOS, SystemMemory, 0xEA000, 16)
       Field(BIOS, ByteAcc, NoLock, Preserve) {
           UAR1, 1,
           UAR2, 1,
           HPET, 1,
           Offset(4),
           PMIN, 32,
           PLEN, 32
       }

        /* Fix HCT test for 0x400 pci memory:
         * - need to report low 640 MB mem as motherboard resource
         */
       Device(MEM0)
       {
           Name(_HID, EISAID("PNP0C02"))
           Name(_CRS, ResourceTemplate() {
               QWordMemory(
                    ResourceConsumer, PosDecode, MinFixed,
                    MaxFixed, Cacheable, ReadWrite,
                    0x00000000,
                    0x00000000,
                    0x0009ffff,
                    0x00000000,
                    0x000a0000)
           })
       }

       Device (PCI0)
       {
           Name (_HID, EisaId ("PNP0A03"))
           Name (_UID, 0x00)
           Name (_ADR, 0x00)
           Name (_BBN, 0x00)

           /*
            * Reserve the IO port ranges [0x10c0, 0x1101] and [0xb044, 0xb047].
            * Or else, for a hotplugged-in device, the port IO BAR assigned
            * by guest OS may conflict with the ranges here.
            */
           Device(HP0)
           {
               Name(_HID, EISAID("PNP0C02"))
               Name(_CRS, ResourceTemplate() {
                   IO (Decode16, 0x10c0, 0x10c0, 0x00, 0x82)
                   IO (Decode16, 0xb044, 0xb044, 0x00, 0x04)
               })
           }

           Method (_CRS, 0, NotSerialized)
           {
               Name (PRT0, ResourceTemplate ()
               {
                   /* bus number is from 0 - 255*/
                   WordBusNumber(
                        ResourceProducer, MinFixed, MaxFixed, SubDecode,
                        0x0000,
                        0x0000,
                        0x00FF,
                        0x0000,
                        0x0100)
                    IO (Decode16, 0x0CF8, 0x0CF8, 0x01, 0x08)
                    WordIO(
                        ResourceProducer, MinFixed, MaxFixed, PosDecode,
                        EntireRange,
                        0x0000,
                        0x0000,
                        0x0CF7,
                        0x0000,
                        0x0CF8)
                    WordIO(
                        ResourceProducer, MinFixed, MaxFixed, PosDecode,
                        EntireRange,
                        0x0000,
                        0x0D00,
                        0xFFFF,
                        0x0000,
                        0xF300)

                    /* reserve memory for pci devices */
                    DWordMemory(
                        ResourceProducer, PosDecode, MinFixed, MaxFixed,
                        Cacheable, ReadWrite,
                        0x00000000,
                        0x000A0000,
                        0x000BFFFF,
                        0x00000000,
                        0x00020000)

                    DWordMemory(
                        ResourceProducer, PosDecode, MinFixed, MaxFixed,
                        Cacheable, ReadWrite,
                        0x00000000,
                        0xF0000000,
                        0xF4FFFFFF,
                        0x00000000,
                        0x05000000,
                        ,, _Y01)
                })

                CreateDWordField(PRT0, \_SB.PCI0._CRS._Y01._MIN, MMIN)
                CreateDWordField(PRT0, \_SB.PCI0._CRS._Y01._MAX, MMAX)
                CreateDWordField(PRT0, \_SB.PCI0._CRS._Y01._LEN, MLEN)

                Store(\_SB.PMIN, MMIN)
                Store(\_SB.PLEN, MLEN)
                Add(MMIN, MLEN, MMAX)
                Subtract(MMAX, One, MMAX)

                Return (PRT0)
            }

            Name(BUFA, ResourceTemplate() {
                IRQ(Level, ActiveLow, Shared) { 5, 10, 11 }
            })

            Name(BUFB, Buffer() {
                0x23, 0x00, 0x00, 0x18, /* IRQ descriptor */
                0x79, 0                 /* End tag, null checksum */
            })

            CreateWordField(BUFB, 0x01, IRQV)

            Device(LNKA) {
                Name(_HID, EISAID("PNP0C0F")) /* PCI interrupt link */
                Name(_UID, 1)

                Method(_STA, 0) {
                    And(PIRA, 0x80, Local0)
                    If(LEqual(Local0, 0x80)) {
                        Return(0x09)   
                    } Else {
                        Return(0x0B) 
                    }
                }

                Method(_PRS) {
                    Return(BUFA)
                }

                Method(_DIS) {
                    Or(PIRA, 0x80, PIRA)
                }

                Method(_CRS) {
                    And(PIRA, 0x0f, Local0)
                    ShiftLeft(0x1, Local0, IRQV)
                    Return(BUFB)
                }

                Method(_SRS, 1) {
                    CreateWordField(ARG0, 0x01, IRQ1)
                    FindSetRightBit(IRQ1, Local0)
                    Decrement(Local0)
                    Store(Local0, PIRA)
                }
            }

            Device(LNKB) {
                Name(_HID, EISAID("PNP0C0F")) /* PCI interrupt link */
                Name(_UID, 2)

                Method(_STA, 0) {
                    And(PIRB, 0x80, Local0)
                    If(LEqual(Local0, 0x80)) {
                        Return(0x09) 
                    } Else {
                        Return(0x0B) 
                    }
                }

                Method(_PRS) {
                    Return(BUFA) 
                }

                Method(_DIS) {
                    Or(PIRB, 0x80, PIRB)
                }

                Method(_CRS) {
                    And(PIRB, 0x0f, Local0) 
                    ShiftLeft(0x1, Local0, IRQV) 
                    Return(BUFB) 
                }

                Method(_SRS, 1) {
                    CreateWordField(ARG0, 0x01, IRQ1) 
                    FindSetRightBit(IRQ1, Local0) 
                    Decrement(Local0)
                    Store(Local0, PIRB) 
                }
            }

            Device(LNKC) {
                Name(_HID, EISAID("PNP0C0F")) /* PCI interrupt link */
                Name(_UID, 3)

                Method(_STA, 0) {
                    And(PIRC, 0x80, Local0)
                    If(LEqual(Local0, 0x80)) {
                        Return(0x09) 
                    } Else {
                        Return(0x0B)
                    }
                }

                Method(_PRS) { 
                    Return(BUFA)
                }

                Method(_DIS) {
                    Or(PIRC, 0x80, PIRC)
                }

                Method(_CRS) {
                    And(PIRC, 0x0f, Local0) 
                    ShiftLeft(0x1, Local0, IRQV) 
                    Return(BUFB) 
                }

                Method(_SRS, 1) {
                    CreateWordField(ARG0, 0x01, IRQ1) 
                    FindSetRightBit(IRQ1, Local0) 
                    Decrement(Local0) 
                    Store(Local0, PIRC)
                }
            }

            Device(LNKD) {
                Name(_HID, EISAID("PNP0C0F")) /* PCI interrupt link */
                Name(_UID, 4)

                Method(_STA, 0) {
                    And(PIRD, 0x80, Local0)
                    If(LEqual(Local0, 0x80)) {
                        Return(0x09) 
                    } Else {
                        Return(0x0B) 
                    }
                }

                Method(_PRS) { 
                    Return(BUFA) 
                }

                Method(_DIS) {
                    Or(PIRD, 0x80, PIRD)
                }

                Method(_CRS) {
                    And(PIRD, 0x0f, Local0) 
                    ShiftLeft(0x1, Local0, IRQV) 
                    Return(BUFB) 
                }

                Method(_SRS, 1) {
                    CreateWordField(ARG0, 0x01, IRQ1) 
                    FindSetRightBit(IRQ1, Local0) 
                    Decrement(Local0) 
                    Store(Local0, PIRD) 
                }
            }

            Device(HPET) {
                Name(_HID,  EISAID("PNP0103"))
                Name(_UID, 0)
                Method (_STA, 0, NotSerialized) {
                    If(LEqual(\_SB.HPET, 0)) {
                        Return(0x00)
                    } Else {
                        Return(0x0F)
                    }
                }
                Name(_CRS, ResourceTemplate() {
                    DWordMemory(
                        ResourceConsumer, PosDecode, MinFixed, MaxFixed,
                        NonCacheable, ReadWrite,
                        0x00000000,
                        0xFED00000,
                        0xFED003FF,
                        0x00000000,
                        0x00000400 /* 1K memory: FED00000 - FED003FF */
                    )
                })
            }

            Method(_PRT,0) {
                If(PICD) {
                    Return(PRTA)
                }  
                Return (PRTP)  
            }

            Name(PRTP, Package() {
                /* Device 1, INTA - INTD */
                Package(){0x0001ffff, 0, \_SB.PCI0.LNKB, 0},
                Package(){0x0001ffff, 1, \_SB.PCI0.LNKC, 0},
                Package(){0x0001ffff, 2, \_SB.PCI0.LNKD, 0},
                Package(){0x0001ffff, 3, \_SB.PCI0.LNKA, 0},
                        
                /* Device 2, INTA - INTD */
                Package(){0x0002ffff, 0, \_SB.PCI0.LNKC, 0},
                Package(){0x0002ffff, 1, \_SB.PCI0.LNKD, 0},
                Package(){0x0002ffff, 2, \_SB.PCI0.LNKA, 0},
                Package(){0x0002ffff, 3, \_SB.PCI0.LNKB, 0},
                        
                /* Device 3, INTA - INTD */
                Package(){0x0003ffff, 0, \_SB.PCI0.LNKD, 0},
                Package(){0x0003ffff, 1, \_SB.PCI0.LNKA, 0},
                Package(){0x0003ffff, 2, \_SB.PCI0.LNKB, 0},
                Package(){0x0003ffff, 3, \_SB.PCI0.LNKC, 0},
                        
                /* Device 4, INTA - INTD */
                Package(){0x0004ffff, 0, \_SB.PCI0.LNKA, 0},
                Package(){0x0004ffff, 1, \_SB.PCI0.LNKB, 0},
                Package(){0x0004ffff, 2, \_SB.PCI0.LNKC, 0},
                Package(){0x0004ffff, 3, \_SB.PCI0.LNKD, 0},
                        
                /* Device 5, INTA - INTD */
                Package(){0x0005ffff, 0, \_SB.PCI0.LNKB, 0},
                Package(){0x0005ffff, 1, \_SB.PCI0.LNKC, 0},
                Package(){0x0005ffff, 2, \_SB.PCI0.LNKD, 0},
                Package(){0x0005ffff, 3, \_SB.PCI0.LNKA, 0},
                        
                /* Device 6, INTA - INTD */
                Package(){0x0006ffff, 0, \_SB.PCI0.LNKC, 0},
                Package(){0x0006ffff, 1, \_SB.PCI0.LNKD, 0},
                Package(){0x0006ffff, 2, \_SB.PCI0.LNKA, 0},
                Package(){0x0006ffff, 3, \_SB.PCI0.LNKB, 0},
                        
                /* Device 7, INTA - INTD */
                Package(){0x0007ffff, 0, \_SB.PCI0.LNKD, 0},
                Package(){0x0007ffff, 1, \_SB.PCI0.LNKA, 0},
                Package(){0x0007ffff, 2, \_SB.PCI0.LNKB, 0},
                Package(){0x0007ffff, 3, \_SB.PCI0.LNKC, 0},
                        
                /* Device 8, INTA - INTD */
                Package(){0x0008ffff, 0, \_SB.PCI0.LNKA, 0},
                Package(){0x0008ffff, 1, \_SB.PCI0.LNKB, 0},
                Package(){0x0008ffff, 2, \_SB.PCI0.LNKC, 0},
                Package(){0x0008ffff, 3, \_SB.PCI0.LNKD, 0},
                        
                /* Device 9, INTA - INTD */
                Package(){0x0009ffff, 0, \_SB.PCI0.LNKB, 0},
                Package(){0x0009ffff, 1, \_SB.PCI0.LNKC, 0},
                Package(){0x0009ffff, 2, \_SB.PCI0.LNKD, 0},
                Package(){0x0009ffff, 3, \_SB.PCI0.LNKA, 0},
                        
                /* Device 10, INTA - INTD */
                Package(){0x000affff, 0, \_SB.PCI0.LNKC, 0},
                Package(){0x000affff, 1, \_SB.PCI0.LNKD, 0},
                Package(){0x000affff, 2, \_SB.PCI0.LNKA, 0},
                Package(){0x000affff, 3, \_SB.PCI0.LNKB, 0},
                        
                /* Device 11, INTA - INTD */
                Package(){0x000bffff, 0, \_SB.PCI0.LNKD, 0},
                Package(){0x000bffff, 1, \_SB.PCI0.LNKA, 0},
                Package(){0x000bffff, 2, \_SB.PCI0.LNKB, 0},
                Package(){0x000bffff, 3, \_SB.PCI0.LNKC, 0},
                        
                /* Device 12, INTA - INTD */
                Package(){0x000cffff, 0, \_SB.PCI0.LNKA, 0},
                Package(){0x000cffff, 1, \_SB.PCI0.LNKB, 0},
                Package(){0x000cffff, 2, \_SB.PCI0.LNKC, 0},
                Package(){0x000cffff, 3, \_SB.PCI0.LNKD, 0},
                        
                /* Device 13, INTA - INTD */
                Package(){0x000dffff, 0, \_SB.PCI0.LNKB, 0},
                Package(){0x000dffff, 1, \_SB.PCI0.LNKC, 0},
                Package(){0x000dffff, 2, \_SB.PCI0.LNKD, 0},
                Package(){0x000dffff, 3, \_SB.PCI0.LNKA, 0},
                        
                /* Device 14, INTA - INTD */
                Package(){0x000effff, 0, \_SB.PCI0.LNKC, 0},
                Package(){0x000effff, 1, \_SB.PCI0.LNKD, 0},
                Package(){0x000effff, 2, \_SB.PCI0.LNKA, 0},
                Package(){0x000effff, 3, \_SB.PCI0.LNKB, 0},
                        
                /* Device 15, INTA - INTD */
                Package(){0x000fffff, 0, \_SB.PCI0.LNKD, 0},
                Package(){0x000fffff, 1, \_SB.PCI0.LNKA, 0},
                Package(){0x000fffff, 2, \_SB.PCI0.LNKB, 0},
                Package(){0x000fffff, 3, \_SB.PCI0.LNKC, 0},

                /* Device 16, INTA - INTD */
                Package(){0x0010ffff, 0, \_SB.PCI0.LNKA, 0},
                Package(){0x0010ffff, 1, \_SB.PCI0.LNKB, 0},
                Package(){0x0010ffff, 2, \_SB.PCI0.LNKC, 0},
                Package(){0x0010ffff, 3, \_SB.PCI0.LNKD, 0},

                /* Device 17, INTA - INTD */
                Package(){0x0011ffff, 0, \_SB.PCI0.LNKB, 0},
                Package(){0x0011ffff, 1, \_SB.PCI0.LNKC, 0},
                Package(){0x0011ffff, 2, \_SB.PCI0.LNKD, 0},
                Package(){0x0011ffff, 3, \_SB.PCI0.LNKA, 0},

                /* Device 18, INTA - INTD */
                Package(){0x0012ffff, 0, \_SB.PCI0.LNKC, 0},
                Package(){0x0012ffff, 1, \_SB.PCI0.LNKD, 0},
                Package(){0x0012ffff, 2, \_SB.PCI0.LNKA, 0},
                Package(){0x0012ffff, 3, \_SB.PCI0.LNKB, 0},

                /* Device 19, INTA - INTD */
                Package(){0x0013ffff, 0, \_SB.PCI0.LNKD, 0},
                Package(){0x0013ffff, 1, \_SB.PCI0.LNKA, 0},
                Package(){0x0013ffff, 2, \_SB.PCI0.LNKB, 0},
                Package(){0x0013ffff, 3, \_SB.PCI0.LNKC, 0},

                /* Device 20, INTA - INTD */
                Package(){0x0014ffff, 0, \_SB.PCI0.LNKA, 0},
                Package(){0x0014ffff, 1, \_SB.PCI0.LNKB, 0},
                Package(){0x0014ffff, 2, \_SB.PCI0.LNKC, 0},
                Package(){0x0014ffff, 3, \_SB.PCI0.LNKD, 0},

                /* Device 21, INTA - INTD */
                Package(){0x0015ffff, 0, \_SB.PCI0.LNKB, 0},
                Package(){0x0015ffff, 1, \_SB.PCI0.LNKC, 0},
                Package(){0x0015ffff, 2, \_SB.PCI0.LNKD, 0},
                Package(){0x0015ffff, 3, \_SB.PCI0.LNKA, 0},

                /* Device 22, INTA - INTD */
                Package(){0x0016ffff, 0, \_SB.PCI0.LNKC, 0},
                Package(){0x0016ffff, 1, \_SB.PCI0.LNKD, 0},
                Package(){0x0016ffff, 2, \_SB.PCI0.LNKA, 0},
                Package(){0x0016ffff, 3, \_SB.PCI0.LNKB, 0},

                /* Device 23, INTA - INTD */
                Package(){0x0017ffff, 0, \_SB.PCI0.LNKD, 0},
                Package(){0x0017ffff, 1, \_SB.PCI0.LNKA, 0},
                Package(){0x0017ffff, 2, \_SB.PCI0.LNKB, 0},
                Package(){0x0017ffff, 3, \_SB.PCI0.LNKC, 0},

                /* Device 24, INTA - INTD */
                Package(){0x0018ffff, 0, \_SB.PCI0.LNKA, 0},
                Package(){0x0018ffff, 1, \_SB.PCI0.LNKB, 0},
                Package(){0x0018ffff, 2, \_SB.PCI0.LNKC, 0},
                Package(){0x0018ffff, 3, \_SB.PCI0.LNKD, 0},

                /* Device 25, INTA - INTD */
                Package(){0x0019ffff, 0, \_SB.PCI0.LNKB, 0},
                Package(){0x0019ffff, 1, \_SB.PCI0.LNKC, 0},
                Package(){0x0019ffff, 2, \_SB.PCI0.LNKD, 0},
                Package(){0x0019ffff, 3, \_SB.PCI0.LNKA, 0},

                /* Device 26, INTA - INTD */
                Package(){0x001affff, 0, \_SB.PCI0.LNKC, 0},
                Package(){0x001affff, 1, \_SB.PCI0.LNKD, 0},
                Package(){0x001affff, 2, \_SB.PCI0.LNKA, 0},
                Package(){0x001affff, 3, \_SB.PCI0.LNKB, 0},

                /* Device 27, INTA - INTD */
                Package(){0x001bffff, 0, \_SB.PCI0.LNKD, 0},
                Package(){0x001bffff, 1, \_SB.PCI0.LNKA, 0},
                Package(){0x001bffff, 2, \_SB.PCI0.LNKB, 0},
                Package(){0x001bffff, 3, \_SB.PCI0.LNKC, 0},

                /* Device 28, INTA - INTD */
                Package(){0x001cffff, 0, \_SB.PCI0.LNKA, 0},
                Package(){0x001cffff, 1, \_SB.PCI0.LNKB, 0},
                Package(){0x001cffff, 2, \_SB.PCI0.LNKC, 0},
                Package(){0x001cffff, 3, \_SB.PCI0.LNKD, 0},

                /* Device 29, INTA - INTD */
                Package(){0x001dffff, 0, \_SB.PCI0.LNKB, 0},
                Package(){0x001dffff, 1, \_SB.PCI0.LNKC, 0},
                Package(){0x001dffff, 2, \_SB.PCI0.LNKD, 0},
                Package(){0x001dffff, 3, \_SB.PCI0.LNKA, 0},

                /* Device 30, INTA - INTD */
                Package(){0x001effff, 0, \_SB.PCI0.LNKC, 0},
                Package(){0x001effff, 1, \_SB.PCI0.LNKD, 0},
                Package(){0x001effff, 2, \_SB.PCI0.LNKA, 0},
                Package(){0x001effff, 3, \_SB.PCI0.LNKB, 0},

                /* Device 31, INTA - INTD */
                Package(){0x001fffff, 0, \_SB.PCI0.LNKD, 0},
                Package(){0x001fffff, 1, \_SB.PCI0.LNKA, 0},
                Package(){0x001fffff, 2, \_SB.PCI0.LNKB, 0},
                Package(){0x001fffff, 3, \_SB.PCI0.LNKC, 0},
            })

            Name(PRTA, Package() {
                /* Device 1, INTA - INTD */
                Package(){0x0001ffff, 0, 0, 20},
                Package(){0x0001ffff, 1, 0, 21},
                Package(){0x0001ffff, 2, 0, 22},
                Package(){0x0001ffff, 3, 0, 23},

                /* Device 2, INTA - INTD */
                Package(){0x0002ffff, 0, 0, 24},
                Package(){0x0002ffff, 1, 0, 25},
                Package(){0x0002ffff, 2, 0, 26},
                Package(){0x0002ffff, 3, 0, 27},

                /* Device 3, INTA - INTD */
                Package(){0x0003ffff, 0, 0, 28},
                Package(){0x0003ffff, 1, 0, 29},
                Package(){0x0003ffff, 2, 0, 30},
                Package(){0x0003ffff, 3, 0, 31},

                /* Device 4, INTA - INTD */
                Package(){0x0004ffff, 0, 0, 32},
                Package(){0x0004ffff, 1, 0, 33},
                Package(){0x0004ffff, 2, 0, 34},
                Package(){0x0004ffff, 3, 0, 35},

                /* Device 5, INTA - INTD */
                Package(){0x0005ffff, 0, 0, 36},
                Package(){0x0005ffff, 1, 0, 37},
                Package(){0x0005ffff, 2, 0, 38},
                Package(){0x0005ffff, 3, 0, 39},

                /* Device 6, INTA - INTD */
                Package(){0x0006ffff, 0, 0, 40},
                Package(){0x0006ffff, 1, 0, 41},
                Package(){0x0006ffff, 2, 0, 42},
                Package(){0x0006ffff, 3, 0, 43},

                /* Device 7, INTA - INTD */
                Package(){0x0007ffff, 0, 0, 44},
                Package(){0x0007ffff, 1, 0, 45},
                Package(){0x0007ffff, 2, 0, 46},
                Package(){0x0007ffff, 3, 0, 47},

                /* Device 8, INTA - INTD */
                Package(){0x0008ffff, 0, 0, 17},
                Package(){0x0008ffff, 1, 0, 18},
                Package(){0x0008ffff, 2, 0, 19},
                Package(){0x0008ffff, 3, 0, 20},

                /* Device 9, INTA - INTD */
                Package(){0x0009ffff, 0, 0, 21},
                Package(){0x0009ffff, 1, 0, 22},
                Package(){0x0009ffff, 2, 0, 23},
                Package(){0x0009ffff, 3, 0, 24},

                /* Device 10, INTA - INTD */
                Package(){0x000affff, 0, 0, 25},
                Package(){0x000affff, 1, 0, 26},
                Package(){0x000affff, 2, 0, 27},
                Package(){0x000affff, 3, 0, 28},

                /* Device 11, INTA - INTD */
                Package(){0x000bffff, 0, 0, 29},
                Package(){0x000bffff, 1, 0, 30},
                Package(){0x000bffff, 2, 0, 31},
                Package(){0x000bffff, 3, 0, 32},

                /* Device 12, INTA - INTD */
                Package(){0x000cffff, 0, 0, 33},
                Package(){0x000cffff, 1, 0, 34},
                Package(){0x000cffff, 2, 0, 35},
                Package(){0x000cffff, 3, 0, 36},

                /* Device 13, INTA - INTD */
                Package(){0x000dffff, 0, 0, 37},
                Package(){0x000dffff, 1, 0, 38},
                Package(){0x000dffff, 2, 0, 39},
                Package(){0x000dffff, 3, 0, 40},

                /* Device 14, INTA - INTD */
                Package(){0x000effff, 0, 0, 41},
                Package(){0x000effff, 1, 0, 42},
                Package(){0x000effff, 2, 0, 43},
                Package(){0x000effff, 3, 0, 44},

                /* Device 15, INTA - INTD */
                Package(){0x000fffff, 0, 0, 45},
                Package(){0x000fffff, 1, 0, 46},
                Package(){0x000fffff, 2, 0, 47},
                Package(){0x000fffff, 3, 0, 16},

                /* Device 16, INTA - INTD */
                Package(){0x0010ffff, 0, 0, 18},
                Package(){0x0010ffff, 1, 0, 19},
                Package(){0x0010ffff, 2, 0, 20},
                Package(){0x0010ffff, 3, 0, 21},

                /* Device 17, INTA - INTD */
                Package(){0x0011ffff, 0, 0, 22},
                Package(){0x0011ffff, 1, 0, 23},
                Package(){0x0011ffff, 2, 0, 24},
                Package(){0x0011ffff, 3, 0, 25},

                /* Device 18, INTA - INTD */
                Package(){0x0012ffff, 0, 0, 26},
                Package(){0x0012ffff, 1, 0, 27},
                Package(){0x0012ffff, 2, 0, 28},
                Package(){0x0012ffff, 3, 0, 29},

                /* Device 19, INTA - INTD */
                Package(){0x0013ffff, 0, 0, 30},
                Package(){0x0013ffff, 1, 0, 31},
                Package(){0x0013ffff, 2, 0, 32},
                Package(){0x0013ffff, 3, 0, 33},

                /* Device 20, INTA - INTD */
                Package(){0x0014ffff, 0, 0, 34},
                Package(){0x0014ffff, 1, 0, 35},
                Package(){0x0014ffff, 2, 0, 36},
                Package(){0x0014ffff, 3, 0, 37},

                /* Device 21, INTA - INTD */
                Package(){0x0015ffff, 0, 0, 38},
                Package(){0x0015ffff, 1, 0, 39},
                Package(){0x0015ffff, 2, 0, 40},
                Package(){0x0015ffff, 3, 0, 41},

                /* Device 22, INTA - INTD */
                Package(){0x0016ffff, 0, 0, 42},
                Package(){0x0016ffff, 1, 0, 43},
                Package(){0x0016ffff, 2, 0, 44},
                Package(){0x0016ffff, 3, 0, 45},

                /* Device 23, INTA - INTD */
                Package(){0x0017ffff, 0, 0, 46},
                Package(){0x0017ffff, 1, 0, 47},
                Package(){0x0017ffff, 2, 0, 16},
                Package(){0x0017ffff, 3, 0, 17},

                /* Device 24, INTA - INTD */
                Package(){0x0018ffff, 0, 0, 19},
                Package(){0x0018ffff, 1, 0, 20},
                Package(){0x0018ffff, 2, 0, 21},
                Package(){0x0018ffff, 3, 0, 22},

                /* Device 25, INTA - INTD */
                Package(){0x0019ffff, 0, 0, 23},
                Package(){0x0019ffff, 1, 0, 24},
                Package(){0x0019ffff, 2, 0, 25},
                Package(){0x0019ffff, 3, 0, 26},

                /* Device 26, INTA - INTD */
                Package(){0x001affff, 0, 0, 27},
                Package(){0x001affff, 1, 0, 28},
                Package(){0x001affff, 2, 0, 29},
                Package(){0x001affff, 3, 0, 30},

                /* Device 27, INTA - INTD */
                Package(){0x001bffff, 0, 0, 31},
                Package(){0x001bffff, 1, 0, 32},
                Package(){0x001bffff, 2, 0, 33},
                Package(){0x001bffff, 3, 0, 34},

                /* Device 28, INTA - INTD */
                Package(){0x001cffff, 0, 0, 35},
                Package(){0x001cffff, 1, 0, 36},
                Package(){0x001cffff, 2, 0, 37},
                Package(){0x001cffff, 3, 0, 38},

                /* Device 29, INTA - INTD */
                Package(){0x001dffff, 0, 0, 39},
                Package(){0x001dffff, 1, 0, 40},
                Package(){0x001dffff, 2, 0, 41},
                Package(){0x001dffff, 3, 0, 42},

                /* Device 30, INTA - INTD */
                Package(){0x001effff, 0, 0, 43},
                Package(){0x001effff, 1, 0, 44},
                Package(){0x001effff, 2, 0, 45},
                Package(){0x001effff, 3, 0, 46},

                /* Device 31, INTA - INTD */
                Package(){0x001fffff, 0, 0, 47},
                Package(){0x001fffff, 1, 0, 16},
                Package(){0x001fffff, 2, 0, 17},
                Package(){0x001fffff, 3, 0, 18},
            })
            
            Device (ISA)
            {
                Name (_ADR, 0x00010000) /* device 1, fn 0 */

                OperationRegion(PIRQ, PCI_Config, 0x60, 0x4)
                Scope(\) {
                    Field (\_SB.PCI0.ISA.PIRQ, ByteAcc, NoLock, Preserve) {
                        PIRA, 8,
                        PIRB, 8,
                        PIRC, 8,
                        PIRD, 8
                    }
                }
                Device (SYSR)
                {
                    Name (_HID, EisaId ("PNP0C02"))
                    Name (_UID, 0x01)
                    Name (CRS, ResourceTemplate ()
                    {
                        /* TODO: list hidden resources */
                        IO (Decode16, 0x0010, 0x0010, 0x00, 0x10)
                        IO (Decode16, 0x0022, 0x0022, 0x00, 0x0C)
                        IO (Decode16, 0x0030, 0x0030, 0x00, 0x10)
                        IO (Decode16, 0x0044, 0x0044, 0x00, 0x1C)
                        IO (Decode16, 0x0062, 0x0062, 0x00, 0x02)
                        IO (Decode16, 0x0065, 0x0065, 0x00, 0x0B)
                        IO (Decode16, 0x0072, 0x0072, 0x00, 0x0E)
                        IO (Decode16, 0x0080, 0x0080, 0x00, 0x01)
                        IO (Decode16, 0x0084, 0x0084, 0x00, 0x03)
                        IO (Decode16, 0x0088, 0x0088, 0x00, 0x01)
                        IO (Decode16, 0x008C, 0x008C, 0x00, 0x03)
                        IO (Decode16, 0x0090, 0x0090, 0x00, 0x10)
                        IO (Decode16, 0x00A2, 0x00A2, 0x00, 0x1C)
                        IO (Decode16, 0x00E0, 0x00E0, 0x00, 0x10)
                        IO (Decode16, 0x08A0, 0x08A0, 0x00, 0x04)
                        IO (Decode16, 0x0CC0, 0x0CC0, 0x00, 0x10)
                        IO (Decode16, 0x04D0, 0x04D0, 0x00, 0x02)
                    })
                    Method (_CRS, 0, NotSerialized)
                    {
                        Return (CRS)
                    }
                }

                Device (PIC)
                {
                    Name (_HID, EisaId ("PNP0000"))
                    Name (_CRS, ResourceTemplate ()
                    {
                        IO (Decode16, 0x0020, 0x0020, 0x01, 0x02)
                        IO (Decode16, 0x00A0, 0x00A0, 0x01, 0x02)
                        IRQNoFlags () {2}
                    })
                }

                Device (DMA0)
                {
                    Name (_HID, EisaId ("PNP0200"))
                    Name (_CRS, ResourceTemplate ()
                    {
                        DMA (Compatibility, BusMaster, Transfer8) {4}
                        IO (Decode16, 0x0000, 0x0000, 0x00, 0x10)
                        IO (Decode16, 0x0081, 0x0081, 0x00, 0x03)
                        IO (Decode16, 0x0087, 0x0087, 0x00, 0x01)
                        IO (Decode16, 0x0089, 0x0089, 0x00, 0x03)
                        IO (Decode16, 0x008F, 0x008F, 0x00, 0x01)
                        IO (Decode16, 0x00C0, 0x00C0, 0x00, 0x20)
                        IO (Decode16, 0x0480, 0x0480, 0x00, 0x10)
                    })
                }

                Device (TMR)
                {
                    Name (_HID, EisaId ("PNP0100"))
                    Name (_CRS, ResourceTemplate ()
                    {
                        IO (Decode16, 0x0040, 0x0040, 0x00, 0x04)
                        IRQNoFlags () {0}
                    })
                }

                Device (RTC)
                {
                    Name (_HID, EisaId ("PNP0B00"))
                    Name (_CRS, ResourceTemplate ()
                    {
                        IO (Decode16, 0x0070, 0x0070, 0x00, 0x02)
                        IRQNoFlags () {8}
                    })
                }

                Device (SPKR)
                {
                    Name (_HID, EisaId ("PNP0800"))
                    Name (_CRS, ResourceTemplate ()
                    {
                        IO (Decode16, 0x0061, 0x0061, 0x00, 0x01)
                    })
                }

                Device (PS2M)
                {
                    Name (_HID, EisaId ("PNP0F13"))
                    Name (_CID, 0x130FD041)
                    Method (_STA, 0, NotSerialized)
                    {
                        Return (0x0F)
                    }

                    Name (_CRS, ResourceTemplate ()
                    {
                        IRQNoFlags () {12}
                    })
                }

                Device (PS2K)
                {
                    Name (_HID, EisaId ("PNP0303"))
                    Name (_CID, 0x0B03D041)
                    Method (_STA, 0, NotSerialized)
                    {
                        Return (0x0F)
                    }

                    Name (_CRS, ResourceTemplate ()
                    {
                        IO (Decode16, 0x0060, 0x0060, 0x00, 0x01)
                        IO (Decode16, 0x0064, 0x0064, 0x00, 0x01)
                        IRQNoFlags () {1}
                    })
                }

                Device (FDC0)
                {
                    Name (_HID, EisaId ("PNP0700"))
                    Method (_STA, 0, NotSerialized)
                    {
                          Return (0x0F)
                    }

                    Name (_CRS, ResourceTemplate ()
                    {
                        IO (Decode16, 0x03F0, 0x03F0, 0x01, 0x06)
                        IO (Decode16, 0x03F7, 0x03F7, 0x01, 0x01)
                        IRQNoFlags () {6}
                        DMA (Compatibility, NotBusMaster, Transfer8) {2}
                    })
                }

                Device (UAR1)
                {
                    Name (_HID, EisaId ("PNP0501"))
                    Name (_UID, 0x01)
                    Method (_STA, 0, NotSerialized)
                    {
                        If(LEqual(\_SB.UAR1, 0)) {
                            Return(0x00)
                        } Else {
                            Return(0x0F)
                        }
                    }

                    Name (_CRS, ResourceTemplate()
                    {
                        IO (Decode16, 0x03F8, 0x03F8, 8, 8)
                        IRQNoFlags () {4}
                    })
                }

                Device (UAR2)
                {
                    Name (_HID, EisaId ("PNP0501"))
                    Name (_UID, 0x02)
                    Method (_STA, 0, NotSerialized)
                    {
                        If(LEqual(\_SB.UAR2, 0)) {
                            Return(0x00)
                        } Else {
                            Return(0x0F)
                        }
                    }

                    Name (_CRS, ResourceTemplate()
                    {
                        IO (Decode16, 0x02F8, 0x02F8, 8, 8)
                        IRQNoFlags () {3}
                    })
                }

                Device (LTP1)
                {
                    Name (_HID, EisaId ("PNP0400"))
                    Name (_UID, 0x02)
                    Method (_STA, 0, NotSerialized)
                    {
                        Return (0x0F)
                    }

                    Name (_CRS, ResourceTemplate()
                    {
                        IO (Decode16, 0x0378, 0x0378, 0x08, 0x08)
                        IRQNoFlags () {7}
                    })
                } 
            }

            /******************************************************************
             * Each PCI hotplug slot needs at least two methods to handle
             * the ACPI event:
             *  _EJ0: eject a device
             *  _STA: return a device's status, e.g. enabled or removed
             * Other methods are optional: 
             *  _PS0/3: put them here for debug purpose
             * 
             * Eject button would generate a general-purpose event, then the
             * control method for this event uses Notify() to inform OSPM which
             * action happened and on which device.
             *
             * Pls. refer "6.3 Device Insertion, Removal, and Status Objects"
             * in ACPI spec 3.0b for details.
             *
             * QEMU provides a simple hotplug controller with some I/O to
             * handle the hotplug action and status, which is beyond the ACPI
             * scope.
             */
            Device(S00)
            {
                Name (_ADR, 0x00000000) /* Dev 0x00, Func 0x0 */
                Name (_SUN, 0x00000000)

                Method (_PS0, 0)
                {
                    Store (0x00, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x00, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x00, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH00) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x00, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH00, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S01)
            {
                Name (_ADR, 0x00000001) /* Dev 0x00, Func 0x1 */
                Name (_SUN, 0x00000000)

                Method (_PS0, 0)
                {
                    Store (0x01, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x01, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x01, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH00) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x01, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH00, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S02)
            {
                Name (_ADR, 0x00000002) /* Dev 0x00, Func 0x2 */
                Name (_SUN, 0x00000000)

                Method (_PS0, 0)
                {
                    Store (0x02, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x02, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x02, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH02) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x02, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH02, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S03)
            {
                Name (_ADR, 0x00000003) /* Dev 0x00, Func 0x3 */
                Name (_SUN, 0x00000000)

                Method (_PS0, 0)
                {
                    Store (0x03, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x03, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x03, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH02) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x03, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH02, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S04)
            {
                Name (_ADR, 0x00000004) /* Dev 0x00, Func 0x4 */
                Name (_SUN, 0x00000000)

                Method (_PS0, 0)
                {
                    Store (0x04, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x04, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x04, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH04) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x04, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH04, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S05)
            {
                Name (_ADR, 0x00000005) /* Dev 0x00, Func 0x5 */
                Name (_SUN, 0x00000000)

                Method (_PS0, 0)
                {
                    Store (0x05, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x05, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x05, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH04) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x05, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH04, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S06)
            {
                Name (_ADR, 0x00000006) /* Dev 0x00, Func 0x6 */
                Name (_SUN, 0x00000000)

                Method (_PS0, 0)
                {
                    Store (0x06, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x06, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x06, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH06) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x06, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH06, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S07)
            {
                Name (_ADR, 0x00000007) /* Dev 0x00, Func 0x7 */
                Name (_SUN, 0x00000000)

                Method (_PS0, 0)
                {
                    Store (0x07, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x07, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x07, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH06) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x07, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH06, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S08)
            {
                Name (_ADR, 0x00010000) /* Dev 0x01, Func 0x0 */
                Name (_SUN, 0x00000001)

                Method (_PS0, 0)
                {
                    Store (0x08, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x08, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x08, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH08) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x08, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH08, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S09)
            {
                Name (_ADR, 0x00010001) /* Dev 0x01, Func 0x1 */
                Name (_SUN, 0x00000001)

                Method (_PS0, 0)
                {
                    Store (0x09, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x09, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x09, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH08) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x09, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH08, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S0A)
            {
                Name (_ADR, 0x00010002) /* Dev 0x01, Func 0x2 */
                Name (_SUN, 0x00000001)

                Method (_PS0, 0)
                {
                    Store (0x0a, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x0a, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x0a, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH0A) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x0a, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH0A, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S0B)
            {
                Name (_ADR, 0x00010003) /* Dev 0x01, Func 0x3 */
                Name (_SUN, 0x00000001)

                Method (_PS0, 0)
                {
                    Store (0x0b, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x0b, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x0b, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH0A) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x0b, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH0A, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S0C)
            {
                Name (_ADR, 0x00010004) /* Dev 0x01, Func 0x4 */
                Name (_SUN, 0x00000001)

                Method (_PS0, 0)
                {
                    Store (0x0c, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x0c, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x0c, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH0C) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x0c, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH0C, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S0D)
            {
                Name (_ADR, 0x00010005) /* Dev 0x01, Func 0x5 */
                Name (_SUN, 0x00000001)

                Method (_PS0, 0)
                {
                    Store (0x0d, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x0d, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x0d, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH0C) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x0d, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH0C, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S0E)
            {
                Name (_ADR, 0x00010006) /* Dev 0x01, Func 0x6 */
                Name (_SUN, 0x00000001)

                Method (_PS0, 0)
                {
                    Store (0x0e, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x0e, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x0e, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH0E) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x0e, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH0E, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S0F)
            {
                Name (_ADR, 0x00010007) /* Dev 0x01, Func 0x7 */
                Name (_SUN, 0x00000001)

                Method (_PS0, 0)
                {
                    Store (0x0f, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x0f, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x0f, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH0E) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x0f, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH0E, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S10)
            {
                Name (_ADR, 0x00020000) /* Dev 0x02, Func 0x0 */
                Name (_SUN, 0x00000002)

                Method (_PS0, 0)
                {
                    Store (0x10, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x10, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x10, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH10) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x10, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH10, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S11)
            {
                Name (_ADR, 0x00020001) /* Dev 0x02, Func 0x1 */
                Name (_SUN, 0x00000002)

                Method (_PS0, 0)
                {
                    Store (0x11, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x11, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x11, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH10) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x11, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH10, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S12)
            {
                Name (_ADR, 0x00020002) /* Dev 0x02, Func 0x2 */
                Name (_SUN, 0x00000002)

                Method (_PS0, 0)
                {
                    Store (0x12, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x12, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x12, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH12) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x12, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH12, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S13)
            {
                Name (_ADR, 0x00020003) /* Dev 0x02, Func 0x3 */
                Name (_SUN, 0x00000002)

                Method (_PS0, 0)
                {
                    Store (0x13, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x13, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x13, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH12) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x13, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH12, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S14)
            {
                Name (_ADR, 0x00020004) /* Dev 0x02, Func 0x4 */
                Name (_SUN, 0x00000002)

                Method (_PS0, 0)
                {
                    Store (0x14, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x14, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x14, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH14) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x14, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH14, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S15)
            {
                Name (_ADR, 0x00020005) /* Dev 0x02, Func 0x5 */
                Name (_SUN, 0x00000002)

                Method (_PS0, 0)
                {
                    Store (0x15, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x15, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x15, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH14) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x15, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH14, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S16)
            {
                Name (_ADR, 0x00020006) /* Dev 0x02, Func 0x6 */
                Name (_SUN, 0x00000002)

                Method (_PS0, 0)
                {
                    Store (0x16, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x16, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x16, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH16) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x16, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH16, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S17)
            {
                Name (_ADR, 0x00020007) /* Dev 0x02, Func 0x7 */
                Name (_SUN, 0x00000002)

                Method (_PS0, 0)
                {
                    Store (0x17, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x17, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x17, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH16) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x17, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH16, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S18)
            {
                Name (_ADR, 0x00030000) /* Dev 0x03, Func 0x0 */
                Name (_SUN, 0x00000003)

                Method (_PS0, 0)
                {
                    Store (0x18, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x18, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x18, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH18) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x18, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH18, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S19)
            {
                Name (_ADR, 0x00030001) /* Dev 0x03, Func 0x1 */
                Name (_SUN, 0x00000003)

                Method (_PS0, 0)
                {
                    Store (0x19, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x19, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x19, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH18) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x19, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH18, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S1A)
            {
                Name (_ADR, 0x00030002) /* Dev 0x03, Func 0x2 */
                Name (_SUN, 0x00000003)

                Method (_PS0, 0)
                {
                    Store (0x1a, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x1a, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x1a, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH1A) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x1a, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH1A, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S1B)
            {
                Name (_ADR, 0x00030003) /* Dev 0x03, Func 0x3 */
                Name (_SUN, 0x00000003)

                Method (_PS0, 0)
                {
                    Store (0x1b, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x1b, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x1b, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH1A) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x1b, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH1A, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S1C)
            {
                Name (_ADR, 0x00030004) /* Dev 0x03, Func 0x4 */
                Name (_SUN, 0x00000003)

                Method (_PS0, 0)
                {
                    Store (0x1c, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x1c, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x1c, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH1C) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x1c, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH1C, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S1D)
            {
                Name (_ADR, 0x00030005) /* Dev 0x03, Func 0x5 */
                Name (_SUN, 0x00000003)

                Method (_PS0, 0)
                {
                    Store (0x1d, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x1d, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x1d, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH1C) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x1d, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH1C, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S1E)
            {
                Name (_ADR, 0x00030006) /* Dev 0x03, Func 0x6 */
                Name (_SUN, 0x00000003)

                Method (_PS0, 0)
                {
                    Store (0x1e, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x1e, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x1e, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH1E) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x1e, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH1E, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S1F)
            {
                Name (_ADR, 0x00030007) /* Dev 0x03, Func 0x7 */
                Name (_SUN, 0x00000003)

                Method (_PS0, 0)
                {
                    Store (0x1f, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x1f, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x1f, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH1E) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x1f, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH1E, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S20)
            {
                Name (_ADR, 0x00040000) /* Dev 0x04, Func 0x0 */
                Name (_SUN, 0x00000004)

                Method (_PS0, 0)
                {
                    Store (0x20, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x20, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x20, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH20) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x20, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH20, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S21)
            {
                Name (_ADR, 0x00040001) /* Dev 0x04, Func 0x1 */
                Name (_SUN, 0x00000004)

                Method (_PS0, 0)
                {
                    Store (0x21, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x21, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x21, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH20) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x21, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH20, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S22)
            {
                Name (_ADR, 0x00040002) /* Dev 0x04, Func 0x2 */
                Name (_SUN, 0x00000004)

                Method (_PS0, 0)
                {
                    Store (0x22, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x22, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x22, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH22) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x22, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH22, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S23)
            {
                Name (_ADR, 0x00040003) /* Dev 0x04, Func 0x3 */
                Name (_SUN, 0x00000004)

                Method (_PS0, 0)
                {
                    Store (0x23, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x23, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x23, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH22) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x23, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH22, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S24)
            {
                Name (_ADR, 0x00040004) /* Dev 0x04, Func 0x4 */
                Name (_SUN, 0x00000004)

                Method (_PS0, 0)
                {
                    Store (0x24, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x24, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x24, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH24) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x24, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH24, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S25)
            {
                Name (_ADR, 0x00040005) /* Dev 0x04, Func 0x5 */
                Name (_SUN, 0x00000004)

                Method (_PS0, 0)
                {
                    Store (0x25, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x25, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x25, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH24) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x25, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH24, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S26)
            {
                Name (_ADR, 0x00040006) /* Dev 0x04, Func 0x6 */
                Name (_SUN, 0x00000004)

                Method (_PS0, 0)
                {
                    Store (0x26, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x26, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x26, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH26) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x26, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH26, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S27)
            {
                Name (_ADR, 0x00040007) /* Dev 0x04, Func 0x7 */
                Name (_SUN, 0x00000004)

                Method (_PS0, 0)
                {
                    Store (0x27, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x27, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x27, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH26) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x27, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH26, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S28)
            {
                Name (_ADR, 0x00050000) /* Dev 0x05, Func 0x0 */
                Name (_SUN, 0x00000005)

                Method (_PS0, 0)
                {
                    Store (0x28, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x28, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x28, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH28) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x28, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH28, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S29)
            {
                Name (_ADR, 0x00050001) /* Dev 0x05, Func 0x1 */
                Name (_SUN, 0x00000005)

                Method (_PS0, 0)
                {
                    Store (0x29, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x29, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x29, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH28) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x29, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH28, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S2A)
            {
                Name (_ADR, 0x00050002) /* Dev 0x05, Func 0x2 */
                Name (_SUN, 0x00000005)

                Method (_PS0, 0)
                {
                    Store (0x2a, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x2a, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x2a, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH2A) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x2a, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH2A, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S2B)
            {
                Name (_ADR, 0x00050003) /* Dev 0x05, Func 0x3 */
                Name (_SUN, 0x00000005)

                Method (_PS0, 0)
                {
                    Store (0x2b, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x2b, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x2b, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH2A) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x2b, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH2A, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S2C)
            {
                Name (_ADR, 0x00050004) /* Dev 0x05, Func 0x4 */
                Name (_SUN, 0x00000005)

                Method (_PS0, 0)
                {
                    Store (0x2c, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x2c, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x2c, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH2C) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x2c, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH2C, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S2D)
            {
                Name (_ADR, 0x00050005) /* Dev 0x05, Func 0x5 */
                Name (_SUN, 0x00000005)

                Method (_PS0, 0)
                {
                    Store (0x2d, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x2d, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x2d, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH2C) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x2d, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH2C, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S2E)
            {
                Name (_ADR, 0x00050006) /* Dev 0x05, Func 0x6 */
                Name (_SUN, 0x00000005)

                Method (_PS0, 0)
                {
                    Store (0x2e, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x2e, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x2e, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH2E) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x2e, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH2E, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S2F)
            {
                Name (_ADR, 0x00050007) /* Dev 0x05, Func 0x7 */
                Name (_SUN, 0x00000005)

                Method (_PS0, 0)
                {
                    Store (0x2f, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x2f, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x2f, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH2E) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x2f, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH2E, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S30)
            {
                Name (_ADR, 0x00060000) /* Dev 0x06, Func 0x0 */
                Name (_SUN, 0x00000006)

                Method (_PS0, 0)
                {
                    Store (0x30, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x30, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x30, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH30) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x30, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH30, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S31)
            {
                Name (_ADR, 0x00060001) /* Dev 0x06, Func 0x1 */
                Name (_SUN, 0x00000006)

                Method (_PS0, 0)
                {
                    Store (0x31, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x31, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x31, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH30) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x31, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH30, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S32)
            {
                Name (_ADR, 0x00060002) /* Dev 0x06, Func 0x2 */
                Name (_SUN, 0x00000006)

                Method (_PS0, 0)
                {
                    Store (0x32, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x32, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x32, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH32) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x32, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH32, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S33)
            {
                Name (_ADR, 0x00060003) /* Dev 0x06, Func 0x3 */
                Name (_SUN, 0x00000006)

                Method (_PS0, 0)
                {
                    Store (0x33, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x33, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x33, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH32) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x33, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH32, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S34)
            {
                Name (_ADR, 0x00060004) /* Dev 0x06, Func 0x4 */
                Name (_SUN, 0x00000006)

                Method (_PS0, 0)
                {
                    Store (0x34, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x34, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x34, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH34) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x34, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH34, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S35)
            {
                Name (_ADR, 0x00060005) /* Dev 0x06, Func 0x5 */
                Name (_SUN, 0x00000006)

                Method (_PS0, 0)
                {
                    Store (0x35, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x35, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x35, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH34) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x35, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH34, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S36)
            {
                Name (_ADR, 0x00060006) /* Dev 0x06, Func 0x6 */
                Name (_SUN, 0x00000006)

                Method (_PS0, 0)
                {
                    Store (0x36, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x36, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x36, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH36) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x36, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH36, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S37)
            {
                Name (_ADR, 0x00060007) /* Dev 0x06, Func 0x7 */
                Name (_SUN, 0x00000006)

                Method (_PS0, 0)
                {
                    Store (0x37, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x37, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x37, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH36) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x37, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH36, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S38)
            {
                Name (_ADR, 0x00070000) /* Dev 0x07, Func 0x0 */
                Name (_SUN, 0x00000007)

                Method (_PS0, 0)
                {
                    Store (0x38, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x38, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x38, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH38) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x38, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH38, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S39)
            {
                Name (_ADR, 0x00070001) /* Dev 0x07, Func 0x1 */
                Name (_SUN, 0x00000007)

                Method (_PS0, 0)
                {
                    Store (0x39, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x39, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x39, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH38) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x39, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH38, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S3A)
            {
                Name (_ADR, 0x00070002) /* Dev 0x07, Func 0x2 */
                Name (_SUN, 0x00000007)

                Method (_PS0, 0)
                {
                    Store (0x3a, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x3a, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x3a, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH3A) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x3a, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH3A, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S3B)
            {
                Name (_ADR, 0x00070003) /* Dev 0x07, Func 0x3 */
                Name (_SUN, 0x00000007)

                Method (_PS0, 0)
                {
                    Store (0x3b, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x3b, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x3b, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH3A) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x3b, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH3A, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S3C)
            {
                Name (_ADR, 0x00070004) /* Dev 0x07, Func 0x4 */
                Name (_SUN, 0x00000007)

                Method (_PS0, 0)
                {
                    Store (0x3c, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x3c, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x3c, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH3C) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x3c, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH3C, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S3D)
            {
                Name (_ADR, 0x00070005) /* Dev 0x07, Func 0x5 */
                Name (_SUN, 0x00000007)

                Method (_PS0, 0)
                {
                    Store (0x3d, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x3d, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x3d, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH3C) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x3d, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH3C, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S3E)
            {
                Name (_ADR, 0x00070006) /* Dev 0x07, Func 0x6 */
                Name (_SUN, 0x00000007)

                Method (_PS0, 0)
                {
                    Store (0x3e, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x3e, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x3e, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH3E) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x3e, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH3E, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S3F)
            {
                Name (_ADR, 0x00070007) /* Dev 0x07, Func 0x7 */
                Name (_SUN, 0x00000007)

                Method (_PS0, 0)
                {
                    Store (0x3f, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x3f, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x3f, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH3E) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x3f, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH3E, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S40)
            {
                Name (_ADR, 0x00080000) /* Dev 0x08, Func 0x0 */
                Name (_SUN, 0x00000008)

                Method (_PS0, 0)
                {
                    Store (0x40, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x40, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x40, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH40) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x40, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH40, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S41)
            {
                Name (_ADR, 0x00080001) /* Dev 0x08, Func 0x1 */
                Name (_SUN, 0x00000008)

                Method (_PS0, 0)
                {
                    Store (0x41, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x41, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x41, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH40) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x41, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH40, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S42)
            {
                Name (_ADR, 0x00080002) /* Dev 0x08, Func 0x2 */
                Name (_SUN, 0x00000008)

                Method (_PS0, 0)
                {
                    Store (0x42, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x42, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x42, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH42) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x42, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH42, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S43)
            {
                Name (_ADR, 0x00080003) /* Dev 0x08, Func 0x3 */
                Name (_SUN, 0x00000008)

                Method (_PS0, 0)
                {
                    Store (0x43, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x43, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x43, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH42) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x43, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH42, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S44)
            {
                Name (_ADR, 0x00080004) /* Dev 0x08, Func 0x4 */
                Name (_SUN, 0x00000008)

                Method (_PS0, 0)
                {
                    Store (0x44, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x44, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x44, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH44) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x44, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH44, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S45)
            {
                Name (_ADR, 0x00080005) /* Dev 0x08, Func 0x5 */
                Name (_SUN, 0x00000008)

                Method (_PS0, 0)
                {
                    Store (0x45, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x45, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x45, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH44) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x45, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH44, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S46)
            {
                Name (_ADR, 0x00080006) /* Dev 0x08, Func 0x6 */
                Name (_SUN, 0x00000008)

                Method (_PS0, 0)
                {
                    Store (0x46, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x46, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x46, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH46) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x46, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH46, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S47)
            {
                Name (_ADR, 0x00080007) /* Dev 0x08, Func 0x7 */
                Name (_SUN, 0x00000008)

                Method (_PS0, 0)
                {
                    Store (0x47, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x47, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x47, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH46) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x47, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH46, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S48)
            {
                Name (_ADR, 0x00090000) /* Dev 0x09, Func 0x0 */
                Name (_SUN, 0x00000009)

                Method (_PS0, 0)
                {
                    Store (0x48, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x48, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x48, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH48) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x48, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH48, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S49)
            {
                Name (_ADR, 0x00090001) /* Dev 0x09, Func 0x1 */
                Name (_SUN, 0x00000009)

                Method (_PS0, 0)
                {
                    Store (0x49, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x49, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x49, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH48) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x49, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH48, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S4A)
            {
                Name (_ADR, 0x00090002) /* Dev 0x09, Func 0x2 */
                Name (_SUN, 0x00000009)

                Method (_PS0, 0)
                {
                    Store (0x4a, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x4a, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x4a, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH4A) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x4a, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH4A, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S4B)
            {
                Name (_ADR, 0x00090003) /* Dev 0x09, Func 0x3 */
                Name (_SUN, 0x00000009)

                Method (_PS0, 0)
                {
                    Store (0x4b, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x4b, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x4b, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH4A) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x4b, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH4A, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S4C)
            {
                Name (_ADR, 0x00090004) /* Dev 0x09, Func 0x4 */
                Name (_SUN, 0x00000009)

                Method (_PS0, 0)
                {
                    Store (0x4c, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x4c, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x4c, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH4C) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x4c, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH4C, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S4D)
            {
                Name (_ADR, 0x00090005) /* Dev 0x09, Func 0x5 */
                Name (_SUN, 0x00000009)

                Method (_PS0, 0)
                {
                    Store (0x4d, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x4d, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x4d, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH4C) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x4d, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH4C, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S4E)
            {
                Name (_ADR, 0x00090006) /* Dev 0x09, Func 0x6 */
                Name (_SUN, 0x00000009)

                Method (_PS0, 0)
                {
                    Store (0x4e, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x4e, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x4e, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH4E) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x4e, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH4E, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S4F)
            {
                Name (_ADR, 0x00090007) /* Dev 0x09, Func 0x7 */
                Name (_SUN, 0x00000009)

                Method (_PS0, 0)
                {
                    Store (0x4f, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x4f, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x4f, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH4E) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x4f, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH4E, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S50)
            {
                Name (_ADR, 0x000a0000) /* Dev 0x0a, Func 0x0 */
                Name (_SUN, 0x0000000a)

                Method (_PS0, 0)
                {
                    Store (0x50, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x50, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x50, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH50) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x50, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH50, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S51)
            {
                Name (_ADR, 0x000a0001) /* Dev 0x0a, Func 0x1 */
                Name (_SUN, 0x0000000a)

                Method (_PS0, 0)
                {
                    Store (0x51, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x51, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x51, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH50) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x51, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH50, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S52)
            {
                Name (_ADR, 0x000a0002) /* Dev 0x0a, Func 0x2 */
                Name (_SUN, 0x0000000a)

                Method (_PS0, 0)
                {
                    Store (0x52, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x52, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x52, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH52) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x52, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH52, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S53)
            {
                Name (_ADR, 0x000a0003) /* Dev 0x0a, Func 0x3 */
                Name (_SUN, 0x0000000a)

                Method (_PS0, 0)
                {
                    Store (0x53, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x53, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x53, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH52) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x53, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH52, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S54)
            {
                Name (_ADR, 0x000a0004) /* Dev 0x0a, Func 0x4 */
                Name (_SUN, 0x0000000a)

                Method (_PS0, 0)
                {
                    Store (0x54, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x54, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x54, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH54) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x54, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH54, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S55)
            {
                Name (_ADR, 0x000a0005) /* Dev 0x0a, Func 0x5 */
                Name (_SUN, 0x0000000a)

                Method (_PS0, 0)
                {
                    Store (0x55, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x55, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x55, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH54) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x55, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH54, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S56)
            {
                Name (_ADR, 0x000a0006) /* Dev 0x0a, Func 0x6 */
                Name (_SUN, 0x0000000a)

                Method (_PS0, 0)
                {
                    Store (0x56, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x56, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x56, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH56) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x56, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH56, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S57)
            {
                Name (_ADR, 0x000a0007) /* Dev 0x0a, Func 0x7 */
                Name (_SUN, 0x0000000a)

                Method (_PS0, 0)
                {
                    Store (0x57, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x57, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x57, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH56) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x57, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH56, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S58)
            {
                Name (_ADR, 0x000b0000) /* Dev 0x0b, Func 0x0 */
                Name (_SUN, 0x0000000b)

                Method (_PS0, 0)
                {
                    Store (0x58, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x58, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x58, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH58) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x58, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH58, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S59)
            {
                Name (_ADR, 0x000b0001) /* Dev 0x0b, Func 0x1 */
                Name (_SUN, 0x0000000b)

                Method (_PS0, 0)
                {
                    Store (0x59, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x59, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x59, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH58) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x59, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH58, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S5A)
            {
                Name (_ADR, 0x000b0002) /* Dev 0x0b, Func 0x2 */
                Name (_SUN, 0x0000000b)

                Method (_PS0, 0)
                {
                    Store (0x5a, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x5a, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x5a, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH5A) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x5a, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH5A, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S5B)
            {
                Name (_ADR, 0x000b0003) /* Dev 0x0b, Func 0x3 */
                Name (_SUN, 0x0000000b)

                Method (_PS0, 0)
                {
                    Store (0x5b, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x5b, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x5b, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH5A) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x5b, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH5A, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S5C)
            {
                Name (_ADR, 0x000b0004) /* Dev 0x0b, Func 0x4 */
                Name (_SUN, 0x0000000b)

                Method (_PS0, 0)
                {
                    Store (0x5c, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x5c, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x5c, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH5C) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x5c, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH5C, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S5D)
            {
                Name (_ADR, 0x000b0005) /* Dev 0x0b, Func 0x5 */
                Name (_SUN, 0x0000000b)

                Method (_PS0, 0)
                {
                    Store (0x5d, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x5d, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x5d, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH5C) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x5d, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH5C, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S5E)
            {
                Name (_ADR, 0x000b0006) /* Dev 0x0b, Func 0x6 */
                Name (_SUN, 0x0000000b)

                Method (_PS0, 0)
                {
                    Store (0x5e, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x5e, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x5e, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH5E) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x5e, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH5E, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S5F)
            {
                Name (_ADR, 0x000b0007) /* Dev 0x0b, Func 0x7 */
                Name (_SUN, 0x0000000b)

                Method (_PS0, 0)
                {
                    Store (0x5f, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x5f, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x5f, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH5E) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x5f, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH5E, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S60)
            {
                Name (_ADR, 0x000c0000) /* Dev 0x0c, Func 0x0 */
                Name (_SUN, 0x0000000c)

                Method (_PS0, 0)
                {
                    Store (0x60, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x60, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x60, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH60) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x60, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH60, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S61)
            {
                Name (_ADR, 0x000c0001) /* Dev 0x0c, Func 0x1 */
                Name (_SUN, 0x0000000c)

                Method (_PS0, 0)
                {
                    Store (0x61, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x61, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x61, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH60) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x61, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH60, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S62)
            {
                Name (_ADR, 0x000c0002) /* Dev 0x0c, Func 0x2 */
                Name (_SUN, 0x0000000c)

                Method (_PS0, 0)
                {
                    Store (0x62, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x62, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x62, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH62) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x62, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH62, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S63)
            {
                Name (_ADR, 0x000c0003) /* Dev 0x0c, Func 0x3 */
                Name (_SUN, 0x0000000c)

                Method (_PS0, 0)
                {
                    Store (0x63, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x63, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x63, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH62) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x63, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH62, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S64)
            {
                Name (_ADR, 0x000c0004) /* Dev 0x0c, Func 0x4 */
                Name (_SUN, 0x0000000c)

                Method (_PS0, 0)
                {
                    Store (0x64, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x64, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x64, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH64) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x64, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH64, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S65)
            {
                Name (_ADR, 0x000c0005) /* Dev 0x0c, Func 0x5 */
                Name (_SUN, 0x0000000c)

                Method (_PS0, 0)
                {
                    Store (0x65, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x65, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x65, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH64) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x65, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH64, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S66)
            {
                Name (_ADR, 0x000c0006) /* Dev 0x0c, Func 0x6 */
                Name (_SUN, 0x0000000c)

                Method (_PS0, 0)
                {
                    Store (0x66, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x66, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x66, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH66) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x66, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH66, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S67)
            {
                Name (_ADR, 0x000c0007) /* Dev 0x0c, Func 0x7 */
                Name (_SUN, 0x0000000c)

                Method (_PS0, 0)
                {
                    Store (0x67, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x67, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x67, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH66) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x67, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH66, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S68)
            {
                Name (_ADR, 0x000d0000) /* Dev 0x0d, Func 0x0 */
                Name (_SUN, 0x0000000d)

                Method (_PS0, 0)
                {
                    Store (0x68, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x68, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x68, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH68) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x68, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH68, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S69)
            {
                Name (_ADR, 0x000d0001) /* Dev 0x0d, Func 0x1 */
                Name (_SUN, 0x0000000d)

                Method (_PS0, 0)
                {
                    Store (0x69, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x69, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x69, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH68) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x69, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH68, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S6A)
            {
                Name (_ADR, 0x000d0002) /* Dev 0x0d, Func 0x2 */
                Name (_SUN, 0x0000000d)

                Method (_PS0, 0)
                {
                    Store (0x6a, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x6a, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x6a, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH6A) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x6a, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH6A, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S6B)
            {
                Name (_ADR, 0x000d0003) /* Dev 0x0d, Func 0x3 */
                Name (_SUN, 0x0000000d)

                Method (_PS0, 0)
                {
                    Store (0x6b, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x6b, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x6b, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH6A) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x6b, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH6A, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S6C)
            {
                Name (_ADR, 0x000d0004) /* Dev 0x0d, Func 0x4 */
                Name (_SUN, 0x0000000d)

                Method (_PS0, 0)
                {
                    Store (0x6c, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x6c, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x6c, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH6C) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x6c, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH6C, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S6D)
            {
                Name (_ADR, 0x000d0005) /* Dev 0x0d, Func 0x5 */
                Name (_SUN, 0x0000000d)

                Method (_PS0, 0)
                {
                    Store (0x6d, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x6d, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x6d, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH6C) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x6d, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH6C, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S6E)
            {
                Name (_ADR, 0x000d0006) /* Dev 0x0d, Func 0x6 */
                Name (_SUN, 0x0000000d)

                Method (_PS0, 0)
                {
                    Store (0x6e, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x6e, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x6e, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH6E) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x6e, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH6E, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S6F)
            {
                Name (_ADR, 0x000d0007) /* Dev 0x0d, Func 0x7 */
                Name (_SUN, 0x0000000d)

                Method (_PS0, 0)
                {
                    Store (0x6f, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x6f, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x6f, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH6E) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x6f, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH6E, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S70)
            {
                Name (_ADR, 0x000e0000) /* Dev 0x0e, Func 0x0 */
                Name (_SUN, 0x0000000e)

                Method (_PS0, 0)
                {
                    Store (0x70, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x70, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x70, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH70) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x70, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH70, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S71)
            {
                Name (_ADR, 0x000e0001) /* Dev 0x0e, Func 0x1 */
                Name (_SUN, 0x0000000e)

                Method (_PS0, 0)
                {
                    Store (0x71, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x71, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x71, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH70) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x71, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH70, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S72)
            {
                Name (_ADR, 0x000e0002) /* Dev 0x0e, Func 0x2 */
                Name (_SUN, 0x0000000e)

                Method (_PS0, 0)
                {
                    Store (0x72, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x72, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x72, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH72) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x72, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH72, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S73)
            {
                Name (_ADR, 0x000e0003) /* Dev 0x0e, Func 0x3 */
                Name (_SUN, 0x0000000e)

                Method (_PS0, 0)
                {
                    Store (0x73, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x73, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x73, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH72) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x73, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH72, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S74)
            {
                Name (_ADR, 0x000e0004) /* Dev 0x0e, Func 0x4 */
                Name (_SUN, 0x0000000e)

                Method (_PS0, 0)
                {
                    Store (0x74, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x74, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x74, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH74) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x74, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH74, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S75)
            {
                Name (_ADR, 0x000e0005) /* Dev 0x0e, Func 0x5 */
                Name (_SUN, 0x0000000e)

                Method (_PS0, 0)
                {
                    Store (0x75, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x75, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x75, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH74) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x75, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH74, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S76)
            {
                Name (_ADR, 0x000e0006) /* Dev 0x0e, Func 0x6 */
                Name (_SUN, 0x0000000e)

                Method (_PS0, 0)
                {
                    Store (0x76, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x76, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x76, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH76) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x76, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH76, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S77)
            {
                Name (_ADR, 0x000e0007) /* Dev 0x0e, Func 0x7 */
                Name (_SUN, 0x0000000e)

                Method (_PS0, 0)
                {
                    Store (0x77, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x77, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x77, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH76) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x77, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH76, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S78)
            {
                Name (_ADR, 0x000f0000) /* Dev 0x0f, Func 0x0 */
                Name (_SUN, 0x0000000f)

                Method (_PS0, 0)
                {
                    Store (0x78, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x78, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x78, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH78) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x78, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH78, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S79)
            {
                Name (_ADR, 0x000f0001) /* Dev 0x0f, Func 0x1 */
                Name (_SUN, 0x0000000f)

                Method (_PS0, 0)
                {
                    Store (0x79, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x79, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x79, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH78) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x79, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH78, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S7A)
            {
                Name (_ADR, 0x000f0002) /* Dev 0x0f, Func 0x2 */
                Name (_SUN, 0x0000000f)

                Method (_PS0, 0)
                {
                    Store (0x7a, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x7a, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x7a, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH7A) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x7a, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH7A, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S7B)
            {
                Name (_ADR, 0x000f0003) /* Dev 0x0f, Func 0x3 */
                Name (_SUN, 0x0000000f)

                Method (_PS0, 0)
                {
                    Store (0x7b, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x7b, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x7b, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH7A) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x7b, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH7A, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S7C)
            {
                Name (_ADR, 0x000f0004) /* Dev 0x0f, Func 0x4 */
                Name (_SUN, 0x0000000f)

                Method (_PS0, 0)
                {
                    Store (0x7c, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x7c, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x7c, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH7C) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x7c, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH7C, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S7D)
            {
                Name (_ADR, 0x000f0005) /* Dev 0x0f, Func 0x5 */
                Name (_SUN, 0x0000000f)

                Method (_PS0, 0)
                {
                    Store (0x7d, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x7d, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x7d, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH7C) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x7d, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH7C, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S7E)
            {
                Name (_ADR, 0x000f0006) /* Dev 0x0f, Func 0x6 */
                Name (_SUN, 0x0000000f)

                Method (_PS0, 0)
                {
                    Store (0x7e, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x7e, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x7e, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH7E) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x7e, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH7E, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S7F)
            {
                Name (_ADR, 0x000f0007) /* Dev 0x0f, Func 0x7 */
                Name (_SUN, 0x0000000f)

                Method (_PS0, 0)
                {
                    Store (0x7f, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x7f, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x7f, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH7E) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x7f, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH7E, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S80)
            {
                Name (_ADR, 0x00100000) /* Dev 0x10, Func 0x0 */
                Name (_SUN, 0x00000010)

                Method (_PS0, 0)
                {
                    Store (0x80, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x80, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x80, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH80) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x80, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH80, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S81)
            {
                Name (_ADR, 0x00100001) /* Dev 0x10, Func 0x1 */
                Name (_SUN, 0x00000010)

                Method (_PS0, 0)
                {
                    Store (0x81, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x81, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x81, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH80) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x81, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH80, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S82)
            {
                Name (_ADR, 0x00100002) /* Dev 0x10, Func 0x2 */
                Name (_SUN, 0x00000010)

                Method (_PS0, 0)
                {
                    Store (0x82, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x82, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x82, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH82) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x82, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH82, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S83)
            {
                Name (_ADR, 0x00100003) /* Dev 0x10, Func 0x3 */
                Name (_SUN, 0x00000010)

                Method (_PS0, 0)
                {
                    Store (0x83, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x83, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x83, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH82) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x83, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH82, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S84)
            {
                Name (_ADR, 0x00100004) /* Dev 0x10, Func 0x4 */
                Name (_SUN, 0x00000010)

                Method (_PS0, 0)
                {
                    Store (0x84, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x84, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x84, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH84) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x84, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH84, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S85)
            {
                Name (_ADR, 0x00100005) /* Dev 0x10, Func 0x5 */
                Name (_SUN, 0x00000010)

                Method (_PS0, 0)
                {
                    Store (0x85, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x85, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x85, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH84) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x85, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH84, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S86)
            {
                Name (_ADR, 0x00100006) /* Dev 0x10, Func 0x6 */
                Name (_SUN, 0x00000010)

                Method (_PS0, 0)
                {
                    Store (0x86, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x86, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x86, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH86) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x86, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH86, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S87)
            {
                Name (_ADR, 0x00100007) /* Dev 0x10, Func 0x7 */
                Name (_SUN, 0x00000010)

                Method (_PS0, 0)
                {
                    Store (0x87, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x87, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x87, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH86) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x87, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH86, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S88)
            {
                Name (_ADR, 0x00110000) /* Dev 0x11, Func 0x0 */
                Name (_SUN, 0x00000011)

                Method (_PS0, 0)
                {
                    Store (0x88, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x88, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x88, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH88) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x88, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH88, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S89)
            {
                Name (_ADR, 0x00110001) /* Dev 0x11, Func 0x1 */
                Name (_SUN, 0x00000011)

                Method (_PS0, 0)
                {
                    Store (0x89, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x89, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x89, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH88) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x89, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH88, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S8A)
            {
                Name (_ADR, 0x00110002) /* Dev 0x11, Func 0x2 */
                Name (_SUN, 0x00000011)

                Method (_PS0, 0)
                {
                    Store (0x8a, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x8a, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x8a, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH8A) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x8a, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH8A, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S8B)
            {
                Name (_ADR, 0x00110003) /* Dev 0x11, Func 0x3 */
                Name (_SUN, 0x00000011)

                Method (_PS0, 0)
                {
                    Store (0x8b, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x8b, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x8b, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH8A) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x8b, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH8A, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S8C)
            {
                Name (_ADR, 0x00110004) /* Dev 0x11, Func 0x4 */
                Name (_SUN, 0x00000011)

                Method (_PS0, 0)
                {
                    Store (0x8c, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x8c, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x8c, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH8C) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x8c, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH8C, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S8D)
            {
                Name (_ADR, 0x00110005) /* Dev 0x11, Func 0x5 */
                Name (_SUN, 0x00000011)

                Method (_PS0, 0)
                {
                    Store (0x8d, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x8d, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x8d, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH8C) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x8d, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH8C, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S8E)
            {
                Name (_ADR, 0x00110006) /* Dev 0x11, Func 0x6 */
                Name (_SUN, 0x00000011)

                Method (_PS0, 0)
                {
                    Store (0x8e, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x8e, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x8e, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH8E) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x8e, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH8E, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S8F)
            {
                Name (_ADR, 0x00110007) /* Dev 0x11, Func 0x7 */
                Name (_SUN, 0x00000011)

                Method (_PS0, 0)
                {
                    Store (0x8f, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x8f, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x8f, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH8E) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x8f, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH8E, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S90)
            {
                Name (_ADR, 0x00120000) /* Dev 0x12, Func 0x0 */
                Name (_SUN, 0x00000012)

                Method (_PS0, 0)
                {
                    Store (0x90, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x90, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x90, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH90) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x90, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH90, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S91)
            {
                Name (_ADR, 0x00120001) /* Dev 0x12, Func 0x1 */
                Name (_SUN, 0x00000012)

                Method (_PS0, 0)
                {
                    Store (0x91, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x91, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x91, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH90) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x91, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH90, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S92)
            {
                Name (_ADR, 0x00120002) /* Dev 0x12, Func 0x2 */
                Name (_SUN, 0x00000012)

                Method (_PS0, 0)
                {
                    Store (0x92, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x92, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x92, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH92) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x92, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH92, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S93)
            {
                Name (_ADR, 0x00120003) /* Dev 0x12, Func 0x3 */
                Name (_SUN, 0x00000012)

                Method (_PS0, 0)
                {
                    Store (0x93, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x93, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x93, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH92) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x93, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH92, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S94)
            {
                Name (_ADR, 0x00120004) /* Dev 0x12, Func 0x4 */
                Name (_SUN, 0x00000012)

                Method (_PS0, 0)
                {
                    Store (0x94, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x94, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x94, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH94) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x94, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH94, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S95)
            {
                Name (_ADR, 0x00120005) /* Dev 0x12, Func 0x5 */
                Name (_SUN, 0x00000012)

                Method (_PS0, 0)
                {
                    Store (0x95, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x95, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x95, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH94) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x95, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH94, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S96)
            {
                Name (_ADR, 0x00120006) /* Dev 0x12, Func 0x6 */
                Name (_SUN, 0x00000012)

                Method (_PS0, 0)
                {
                    Store (0x96, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x96, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x96, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH96) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x96, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH96, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S97)
            {
                Name (_ADR, 0x00120007) /* Dev 0x12, Func 0x7 */
                Name (_SUN, 0x00000012)

                Method (_PS0, 0)
                {
                    Store (0x97, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x97, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x97, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH96) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x97, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH96, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S98)
            {
                Name (_ADR, 0x00130000) /* Dev 0x13, Func 0x0 */
                Name (_SUN, 0x00000013)

                Method (_PS0, 0)
                {
                    Store (0x98, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x98, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x98, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH98) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x98, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH98, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S99)
            {
                Name (_ADR, 0x00130001) /* Dev 0x13, Func 0x1 */
                Name (_SUN, 0x00000013)

                Method (_PS0, 0)
                {
                    Store (0x99, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x99, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x99, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH98) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x99, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH98, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S9A)
            {
                Name (_ADR, 0x00130002) /* Dev 0x13, Func 0x2 */
                Name (_SUN, 0x00000013)

                Method (_PS0, 0)
                {
                    Store (0x9a, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x9a, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x9a, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH9A) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x9a, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH9A, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S9B)
            {
                Name (_ADR, 0x00130003) /* Dev 0x13, Func 0x3 */
                Name (_SUN, 0x00000013)

                Method (_PS0, 0)
                {
                    Store (0x9b, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x9b, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x9b, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH9A) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x9b, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH9A, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S9C)
            {
                Name (_ADR, 0x00130004) /* Dev 0x13, Func 0x4 */
                Name (_SUN, 0x00000013)

                Method (_PS0, 0)
                {
                    Store (0x9c, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x9c, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x9c, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH9C) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x9c, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH9C, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S9D)
            {
                Name (_ADR, 0x00130005) /* Dev 0x13, Func 0x5 */
                Name (_SUN, 0x00000013)

                Method (_PS0, 0)
                {
                    Store (0x9d, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x9d, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x9d, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH9C) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x9d, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH9C, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S9E)
            {
                Name (_ADR, 0x00130006) /* Dev 0x13, Func 0x6 */
                Name (_SUN, 0x00000013)

                Method (_PS0, 0)
                {
                    Store (0x9e, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x9e, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x9e, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PH9E) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x9e, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PH9E, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(S9F)
            {
                Name (_ADR, 0x00130007) /* Dev 0x13, Func 0x7 */
                Name (_SUN, 0x00000013)

                Method (_PS0, 0)
                {
                    Store (0x9f, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0x9f, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0x9f, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PH9E) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0x9f, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PH9E, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SA0)
            {
                Name (_ADR, 0x00140000) /* Dev 0x14, Func 0x0 */
                Name (_SUN, 0x00000014)

                Method (_PS0, 0)
                {
                    Store (0xa0, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xa0, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xa0, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PHA0) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xa0, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PHA0, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SA1)
            {
                Name (_ADR, 0x00140001) /* Dev 0x14, Func 0x1 */
                Name (_SUN, 0x00000014)

                Method (_PS0, 0)
                {
                    Store (0xa1, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xa1, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xa1, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PHA0) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xa1, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PHA0, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SA2)
            {
                Name (_ADR, 0x00140002) /* Dev 0x14, Func 0x2 */
                Name (_SUN, 0x00000014)

                Method (_PS0, 0)
                {
                    Store (0xa2, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xa2, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xa2, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PHA2) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xa2, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PHA2, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SA3)
            {
                Name (_ADR, 0x00140003) /* Dev 0x14, Func 0x3 */
                Name (_SUN, 0x00000014)

                Method (_PS0, 0)
                {
                    Store (0xa3, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xa3, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xa3, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PHA2) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xa3, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PHA2, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SA4)
            {
                Name (_ADR, 0x00140004) /* Dev 0x14, Func 0x4 */
                Name (_SUN, 0x00000014)

                Method (_PS0, 0)
                {
                    Store (0xa4, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xa4, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xa4, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PHA4) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xa4, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PHA4, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SA5)
            {
                Name (_ADR, 0x00140005) /* Dev 0x14, Func 0x5 */
                Name (_SUN, 0x00000014)

                Method (_PS0, 0)
                {
                    Store (0xa5, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xa5, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xa5, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PHA4) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xa5, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PHA4, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SA6)
            {
                Name (_ADR, 0x00140006) /* Dev 0x14, Func 0x6 */
                Name (_SUN, 0x00000014)

                Method (_PS0, 0)
                {
                    Store (0xa6, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xa6, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xa6, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PHA6) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xa6, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PHA6, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SA7)
            {
                Name (_ADR, 0x00140007) /* Dev 0x14, Func 0x7 */
                Name (_SUN, 0x00000014)

                Method (_PS0, 0)
                {
                    Store (0xa7, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xa7, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xa7, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PHA6) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xa7, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PHA6, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SA8)
            {
                Name (_ADR, 0x00150000) /* Dev 0x15, Func 0x0 */
                Name (_SUN, 0x00000015)

                Method (_PS0, 0)
                {
                    Store (0xa8, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xa8, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xa8, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PHA8) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xa8, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PHA8, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SA9)
            {
                Name (_ADR, 0x00150001) /* Dev 0x15, Func 0x1 */
                Name (_SUN, 0x00000015)

                Method (_PS0, 0)
                {
                    Store (0xa9, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xa9, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xa9, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PHA8) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xa9, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PHA8, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SAA)
            {
                Name (_ADR, 0x00150002) /* Dev 0x15, Func 0x2 */
                Name (_SUN, 0x00000015)

                Method (_PS0, 0)
                {
                    Store (0xaa, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xaa, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xaa, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PHAA) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xaa, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PHAA, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SAB)
            {
                Name (_ADR, 0x00150003) /* Dev 0x15, Func 0x3 */
                Name (_SUN, 0x00000015)

                Method (_PS0, 0)
                {
                    Store (0xab, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xab, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xab, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PHAA) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xab, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PHAA, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SAC)
            {
                Name (_ADR, 0x00150004) /* Dev 0x15, Func 0x4 */
                Name (_SUN, 0x00000015)

                Method (_PS0, 0)
                {
                    Store (0xac, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xac, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xac, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PHAC) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xac, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PHAC, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SAD)
            {
                Name (_ADR, 0x00150005) /* Dev 0x15, Func 0x5 */
                Name (_SUN, 0x00000015)

                Method (_PS0, 0)
                {
                    Store (0xad, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xad, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xad, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PHAC) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xad, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PHAC, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SAE)
            {
                Name (_ADR, 0x00150006) /* Dev 0x15, Func 0x6 */
                Name (_SUN, 0x00000015)

                Method (_PS0, 0)
                {
                    Store (0xae, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xae, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xae, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PHAE) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xae, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PHAE, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SAF)
            {
                Name (_ADR, 0x00150007) /* Dev 0x15, Func 0x7 */
                Name (_SUN, 0x00000015)

                Method (_PS0, 0)
                {
                    Store (0xaf, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xaf, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xaf, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PHAE) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xaf, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PHAE, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SB0)
            {
                Name (_ADR, 0x00160000) /* Dev 0x16, Func 0x0 */
                Name (_SUN, 0x00000016)

                Method (_PS0, 0)
                {
                    Store (0xb0, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xb0, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xb0, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PHB0) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xb0, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PHB0, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SB1)
            {
                Name (_ADR, 0x00160001) /* Dev 0x16, Func 0x1 */
                Name (_SUN, 0x00000016)

                Method (_PS0, 0)
                {
                    Store (0xb1, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xb1, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xb1, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PHB0) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xb1, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PHB0, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SB2)
            {
                Name (_ADR, 0x00160002) /* Dev 0x16, Func 0x2 */
                Name (_SUN, 0x00000016)

                Method (_PS0, 0)
                {
                    Store (0xb2, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xb2, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xb2, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PHB2) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xb2, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PHB2, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SB3)
            {
                Name (_ADR, 0x00160003) /* Dev 0x16, Func 0x3 */
                Name (_SUN, 0x00000016)

                Method (_PS0, 0)
                {
                    Store (0xb3, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xb3, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xb3, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PHB2) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xb3, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PHB2, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SB4)
            {
                Name (_ADR, 0x00160004) /* Dev 0x16, Func 0x4 */
                Name (_SUN, 0x00000016)

                Method (_PS0, 0)
                {
                    Store (0xb4, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xb4, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xb4, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PHB4) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xb4, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PHB4, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SB5)
            {
                Name (_ADR, 0x00160005) /* Dev 0x16, Func 0x5 */
                Name (_SUN, 0x00000016)

                Method (_PS0, 0)
                {
                    Store (0xb5, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xb5, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xb5, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PHB4) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xb5, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PHB4, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SB6)
            {
                Name (_ADR, 0x00160006) /* Dev 0x16, Func 0x6 */
                Name (_SUN, 0x00000016)

                Method (_PS0, 0)
                {
                    Store (0xb6, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xb6, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xb6, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PHB6) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xb6, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PHB6, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SB7)
            {
                Name (_ADR, 0x00160007) /* Dev 0x16, Func 0x7 */
                Name (_SUN, 0x00000016)

                Method (_PS0, 0)
                {
                    Store (0xb7, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xb7, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xb7, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PHB6) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xb7, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PHB6, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SB8)
            {
                Name (_ADR, 0x00170000) /* Dev 0x17, Func 0x0 */
                Name (_SUN, 0x00000017)

                Method (_PS0, 0)
                {
                    Store (0xb8, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xb8, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xb8, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PHB8) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xb8, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PHB8, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SB9)
            {
                Name (_ADR, 0x00170001) /* Dev 0x17, Func 0x1 */
                Name (_SUN, 0x00000017)

                Method (_PS0, 0)
                {
                    Store (0xb9, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xb9, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xb9, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PHB8) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xb9, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PHB8, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SBA)
            {
                Name (_ADR, 0x00170002) /* Dev 0x17, Func 0x2 */
                Name (_SUN, 0x00000017)

                Method (_PS0, 0)
                {
                    Store (0xba, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xba, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xba, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PHBA) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xba, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PHBA, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SBB)
            {
                Name (_ADR, 0x00170003) /* Dev 0x17, Func 0x3 */
                Name (_SUN, 0x00000017)

                Method (_PS0, 0)
                {
                    Store (0xbb, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xbb, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xbb, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PHBA) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xbb, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PHBA, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SBC)
            {
                Name (_ADR, 0x00170004) /* Dev 0x17, Func 0x4 */
                Name (_SUN, 0x00000017)

                Method (_PS0, 0)
                {
                    Store (0xbc, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xbc, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xbc, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PHBC) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xbc, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PHBC, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SBD)
            {
                Name (_ADR, 0x00170005) /* Dev 0x17, Func 0x5 */
                Name (_SUN, 0x00000017)

                Method (_PS0, 0)
                {
                    Store (0xbd, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xbd, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xbd, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PHBC) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xbd, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PHBC, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SBE)
            {
                Name (_ADR, 0x00170006) /* Dev 0x17, Func 0x6 */
                Name (_SUN, 0x00000017)

                Method (_PS0, 0)
                {
                    Store (0xbe, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xbe, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xbe, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PHBE) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xbe, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PHBE, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SBF)
            {
                Name (_ADR, 0x00170007) /* Dev 0x17, Func 0x7 */
                Name (_SUN, 0x00000017)

                Method (_PS0, 0)
                {
                    Store (0xbf, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xbf, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xbf, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PHBE) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xbf, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PHBE, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SC0)
            {
                Name (_ADR, 0x00180000) /* Dev 0x18, Func 0x0 */
                Name (_SUN, 0x00000018)

                Method (_PS0, 0)
                {
                    Store (0xc0, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xc0, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xc0, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PHC0) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xc0, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PHC0, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SC1)
            {
                Name (_ADR, 0x00180001) /* Dev 0x18, Func 0x1 */
                Name (_SUN, 0x00000018)

                Method (_PS0, 0)
                {
                    Store (0xc1, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xc1, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xc1, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PHC0) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xc1, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PHC0, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SC2)
            {
                Name (_ADR, 0x00180002) /* Dev 0x18, Func 0x2 */
                Name (_SUN, 0x00000018)

                Method (_PS0, 0)
                {
                    Store (0xc2, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xc2, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xc2, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PHC2) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xc2, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PHC2, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SC3)
            {
                Name (_ADR, 0x00180003) /* Dev 0x18, Func 0x3 */
                Name (_SUN, 0x00000018)

                Method (_PS0, 0)
                {
                    Store (0xc3, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xc3, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xc3, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PHC2) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xc3, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PHC2, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SC4)
            {
                Name (_ADR, 0x00180004) /* Dev 0x18, Func 0x4 */
                Name (_SUN, 0x00000018)

                Method (_PS0, 0)
                {
                    Store (0xc4, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xc4, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xc4, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PHC4) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xc4, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PHC4, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SC5)
            {
                Name (_ADR, 0x00180005) /* Dev 0x18, Func 0x5 */
                Name (_SUN, 0x00000018)

                Method (_PS0, 0)
                {
                    Store (0xc5, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xc5, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xc5, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PHC4) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xc5, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PHC4, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SC6)
            {
                Name (_ADR, 0x00180006) /* Dev 0x18, Func 0x6 */
                Name (_SUN, 0x00000018)

                Method (_PS0, 0)
                {
                    Store (0xc6, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xc6, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xc6, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PHC6) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xc6, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PHC6, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SC7)
            {
                Name (_ADR, 0x00180007) /* Dev 0x18, Func 0x7 */
                Name (_SUN, 0x00000018)

                Method (_PS0, 0)
                {
                    Store (0xc7, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xc7, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xc7, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PHC6) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xc7, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PHC6, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SC8)
            {
                Name (_ADR, 0x00190000) /* Dev 0x19, Func 0x0 */
                Name (_SUN, 0x00000019)

                Method (_PS0, 0)
                {
                    Store (0xc8, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xc8, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xc8, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PHC8) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xc8, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PHC8, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SC9)
            {
                Name (_ADR, 0x00190001) /* Dev 0x19, Func 0x1 */
                Name (_SUN, 0x00000019)

                Method (_PS0, 0)
                {
                    Store (0xc9, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xc9, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xc9, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PHC8) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xc9, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PHC8, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SCA)
            {
                Name (_ADR, 0x00190002) /* Dev 0x19, Func 0x2 */
                Name (_SUN, 0x00000019)

                Method (_PS0, 0)
                {
                    Store (0xca, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xca, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xca, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PHCA) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xca, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PHCA, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SCB)
            {
                Name (_ADR, 0x00190003) /* Dev 0x19, Func 0x3 */
                Name (_SUN, 0x00000019)

                Method (_PS0, 0)
                {
                    Store (0xcb, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xcb, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xcb, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PHCA) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xcb, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PHCA, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SCC)
            {
                Name (_ADR, 0x00190004) /* Dev 0x19, Func 0x4 */
                Name (_SUN, 0x00000019)

                Method (_PS0, 0)
                {
                    Store (0xcc, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xcc, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xcc, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PHCC) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xcc, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PHCC, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SCD)
            {
                Name (_ADR, 0x00190005) /* Dev 0x19, Func 0x5 */
                Name (_SUN, 0x00000019)

                Method (_PS0, 0)
                {
                    Store (0xcd, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xcd, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xcd, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PHCC) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xcd, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PHCC, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SCE)
            {
                Name (_ADR, 0x00190006) /* Dev 0x19, Func 0x6 */
                Name (_SUN, 0x00000019)

                Method (_PS0, 0)
                {
                    Store (0xce, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xce, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xce, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PHCE) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xce, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PHCE, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SCF)
            {
                Name (_ADR, 0x00190007) /* Dev 0x19, Func 0x7 */
                Name (_SUN, 0x00000019)

                Method (_PS0, 0)
                {
                    Store (0xcf, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xcf, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xcf, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PHCE) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xcf, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PHCE, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SD0)
            {
                Name (_ADR, 0x001a0000) /* Dev 0x1a, Func 0x0 */
                Name (_SUN, 0x0000001a)

                Method (_PS0, 0)
                {
                    Store (0xd0, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xd0, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xd0, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PHD0) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xd0, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PHD0, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SD1)
            {
                Name (_ADR, 0x001a0001) /* Dev 0x1a, Func 0x1 */
                Name (_SUN, 0x0000001a)

                Method (_PS0, 0)
                {
                    Store (0xd1, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xd1, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xd1, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PHD0) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xd1, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PHD0, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SD2)
            {
                Name (_ADR, 0x001a0002) /* Dev 0x1a, Func 0x2 */
                Name (_SUN, 0x0000001a)

                Method (_PS0, 0)
                {
                    Store (0xd2, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xd2, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xd2, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PHD2) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xd2, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PHD2, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SD3)
            {
                Name (_ADR, 0x001a0003) /* Dev 0x1a, Func 0x3 */
                Name (_SUN, 0x0000001a)

                Method (_PS0, 0)
                {
                    Store (0xd3, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xd3, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xd3, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PHD2) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xd3, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PHD2, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SD4)
            {
                Name (_ADR, 0x001a0004) /* Dev 0x1a, Func 0x4 */
                Name (_SUN, 0x0000001a)

                Method (_PS0, 0)
                {
                    Store (0xd4, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xd4, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xd4, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PHD4) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xd4, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PHD4, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SD5)
            {
                Name (_ADR, 0x001a0005) /* Dev 0x1a, Func 0x5 */
                Name (_SUN, 0x0000001a)

                Method (_PS0, 0)
                {
                    Store (0xd5, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xd5, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xd5, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PHD4) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xd5, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PHD4, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SD6)
            {
                Name (_ADR, 0x001a0006) /* Dev 0x1a, Func 0x6 */
                Name (_SUN, 0x0000001a)

                Method (_PS0, 0)
                {
                    Store (0xd6, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xd6, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xd6, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PHD6) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xd6, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PHD6, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SD7)
            {
                Name (_ADR, 0x001a0007) /* Dev 0x1a, Func 0x7 */
                Name (_SUN, 0x0000001a)

                Method (_PS0, 0)
                {
                    Store (0xd7, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xd7, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xd7, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PHD6) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xd7, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PHD6, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SD8)
            {
                Name (_ADR, 0x001b0000) /* Dev 0x1b, Func 0x0 */
                Name (_SUN, 0x0000001b)

                Method (_PS0, 0)
                {
                    Store (0xd8, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xd8, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xd8, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PHD8) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xd8, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PHD8, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SD9)
            {
                Name (_ADR, 0x001b0001) /* Dev 0x1b, Func 0x1 */
                Name (_SUN, 0x0000001b)

                Method (_PS0, 0)
                {
                    Store (0xd9, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xd9, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xd9, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PHD8) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xd9, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PHD8, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SDA)
            {
                Name (_ADR, 0x001b0002) /* Dev 0x1b, Func 0x2 */
                Name (_SUN, 0x0000001b)

                Method (_PS0, 0)
                {
                    Store (0xda, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xda, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xda, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PHDA) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xda, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PHDA, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SDB)
            {
                Name (_ADR, 0x001b0003) /* Dev 0x1b, Func 0x3 */
                Name (_SUN, 0x0000001b)

                Method (_PS0, 0)
                {
                    Store (0xdb, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xdb, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xdb, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PHDA) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xdb, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PHDA, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SDC)
            {
                Name (_ADR, 0x001b0004) /* Dev 0x1b, Func 0x4 */
                Name (_SUN, 0x0000001b)

                Method (_PS0, 0)
                {
                    Store (0xdc, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xdc, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xdc, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PHDC) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xdc, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PHDC, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SDD)
            {
                Name (_ADR, 0x001b0005) /* Dev 0x1b, Func 0x5 */
                Name (_SUN, 0x0000001b)

                Method (_PS0, 0)
                {
                    Store (0xdd, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xdd, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xdd, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PHDC) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xdd, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PHDC, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SDE)
            {
                Name (_ADR, 0x001b0006) /* Dev 0x1b, Func 0x6 */
                Name (_SUN, 0x0000001b)

                Method (_PS0, 0)
                {
                    Store (0xde, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xde, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xde, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PHDE) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xde, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PHDE, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SDF)
            {
                Name (_ADR, 0x001b0007) /* Dev 0x1b, Func 0x7 */
                Name (_SUN, 0x0000001b)

                Method (_PS0, 0)
                {
                    Store (0xdf, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xdf, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xdf, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PHDE) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xdf, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PHDE, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SE0)
            {
                Name (_ADR, 0x001c0000) /* Dev 0x1c, Func 0x0 */
                Name (_SUN, 0x0000001c)

                Method (_PS0, 0)
                {
                    Store (0xe0, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xe0, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xe0, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PHE0) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xe0, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PHE0, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SE1)
            {
                Name (_ADR, 0x001c0001) /* Dev 0x1c, Func 0x1 */
                Name (_SUN, 0x0000001c)

                Method (_PS0, 0)
                {
                    Store (0xe1, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xe1, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xe1, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PHE0) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xe1, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PHE0, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SE2)
            {
                Name (_ADR, 0x001c0002) /* Dev 0x1c, Func 0x2 */
                Name (_SUN, 0x0000001c)

                Method (_PS0, 0)
                {
                    Store (0xe2, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xe2, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xe2, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PHE2) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xe2, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PHE2, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SE3)
            {
                Name (_ADR, 0x001c0003) /* Dev 0x1c, Func 0x3 */
                Name (_SUN, 0x0000001c)

                Method (_PS0, 0)
                {
                    Store (0xe3, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xe3, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xe3, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PHE2) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xe3, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PHE2, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SE4)
            {
                Name (_ADR, 0x001c0004) /* Dev 0x1c, Func 0x4 */
                Name (_SUN, 0x0000001c)

                Method (_PS0, 0)
                {
                    Store (0xe4, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xe4, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xe4, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PHE4) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xe4, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PHE4, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SE5)
            {
                Name (_ADR, 0x001c0005) /* Dev 0x1c, Func 0x5 */
                Name (_SUN, 0x0000001c)

                Method (_PS0, 0)
                {
                    Store (0xe5, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xe5, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xe5, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PHE4) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xe5, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PHE4, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SE6)
            {
                Name (_ADR, 0x001c0006) /* Dev 0x1c, Func 0x6 */
                Name (_SUN, 0x0000001c)

                Method (_PS0, 0)
                {
                    Store (0xe6, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xe6, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xe6, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PHE6) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xe6, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PHE6, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SE7)
            {
                Name (_ADR, 0x001c0007) /* Dev 0x1c, Func 0x7 */
                Name (_SUN, 0x0000001c)

                Method (_PS0, 0)
                {
                    Store (0xe7, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xe7, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xe7, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PHE6) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xe7, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PHE6, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SE8)
            {
                Name (_ADR, 0x001d0000) /* Dev 0x1d, Func 0x0 */
                Name (_SUN, 0x0000001d)

                Method (_PS0, 0)
                {
                    Store (0xe8, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xe8, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xe8, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PHE8) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xe8, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PHE8, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SE9)
            {
                Name (_ADR, 0x001d0001) /* Dev 0x1d, Func 0x1 */
                Name (_SUN, 0x0000001d)

                Method (_PS0, 0)
                {
                    Store (0xe9, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xe9, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xe9, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PHE8) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xe9, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PHE8, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SEA)
            {
                Name (_ADR, 0x001d0002) /* Dev 0x1d, Func 0x2 */
                Name (_SUN, 0x0000001d)

                Method (_PS0, 0)
                {
                    Store (0xea, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xea, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xea, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PHEA) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xea, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PHEA, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SEB)
            {
                Name (_ADR, 0x001d0003) /* Dev 0x1d, Func 0x3 */
                Name (_SUN, 0x0000001d)

                Method (_PS0, 0)
                {
                    Store (0xeb, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xeb, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xeb, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PHEA) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xeb, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PHEA, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SEC)
            {
                Name (_ADR, 0x001d0004) /* Dev 0x1d, Func 0x4 */
                Name (_SUN, 0x0000001d)

                Method (_PS0, 0)
                {
                    Store (0xec, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xec, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xec, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PHEC) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xec, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PHEC, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SED)
            {
                Name (_ADR, 0x001d0005) /* Dev 0x1d, Func 0x5 */
                Name (_SUN, 0x0000001d)

                Method (_PS0, 0)
                {
                    Store (0xed, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xed, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xed, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PHEC) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xed, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PHEC, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SEE)
            {
                Name (_ADR, 0x001d0006) /* Dev 0x1d, Func 0x6 */
                Name (_SUN, 0x0000001d)

                Method (_PS0, 0)
                {
                    Store (0xee, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xee, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xee, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PHEE) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xee, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PHEE, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SEF)
            {
                Name (_ADR, 0x001d0007) /* Dev 0x1d, Func 0x7 */
                Name (_SUN, 0x0000001d)

                Method (_PS0, 0)
                {
                    Store (0xef, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xef, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xef, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PHEE) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xef, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PHEE, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SF0)
            {
                Name (_ADR, 0x001e0000) /* Dev 0x1e, Func 0x0 */
                Name (_SUN, 0x0000001e)

                Method (_PS0, 0)
                {
                    Store (0xf0, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xf0, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xf0, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PHF0) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xf0, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PHF0, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SF1)
            {
                Name (_ADR, 0x001e0001) /* Dev 0x1e, Func 0x1 */
                Name (_SUN, 0x0000001e)

                Method (_PS0, 0)
                {
                    Store (0xf1, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xf1, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xf1, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PHF0) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xf1, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PHF0, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SF2)
            {
                Name (_ADR, 0x001e0002) /* Dev 0x1e, Func 0x2 */
                Name (_SUN, 0x0000001e)

                Method (_PS0, 0)
                {
                    Store (0xf2, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xf2, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xf2, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PHF2) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xf2, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PHF2, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SF3)
            {
                Name (_ADR, 0x001e0003) /* Dev 0x1e, Func 0x3 */
                Name (_SUN, 0x0000001e)

                Method (_PS0, 0)
                {
                    Store (0xf3, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xf3, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xf3, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PHF2) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xf3, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PHF2, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SF4)
            {
                Name (_ADR, 0x001e0004) /* Dev 0x1e, Func 0x4 */
                Name (_SUN, 0x0000001e)

                Method (_PS0, 0)
                {
                    Store (0xf4, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xf4, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xf4, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PHF4) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xf4, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PHF4, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SF5)
            {
                Name (_ADR, 0x001e0005) /* Dev 0x1e, Func 0x5 */
                Name (_SUN, 0x0000001e)

                Method (_PS0, 0)
                {
                    Store (0xf5, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xf5, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xf5, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PHF4) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xf5, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PHF4, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SF6)
            {
                Name (_ADR, 0x001e0006) /* Dev 0x1e, Func 0x6 */
                Name (_SUN, 0x0000001e)

                Method (_PS0, 0)
                {
                    Store (0xf6, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xf6, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xf6, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PHF6) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xf6, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PHF6, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SF7)
            {
                Name (_ADR, 0x001e0007) /* Dev 0x1e, Func 0x7 */
                Name (_SUN, 0x0000001e)

                Method (_PS0, 0)
                {
                    Store (0xf7, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xf7, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xf7, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PHF6) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xf7, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PHF6, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SF8)
            {
                Name (_ADR, 0x001f0000) /* Dev 0x1f, Func 0x0 */
                Name (_SUN, 0x0000001f)

                Method (_PS0, 0)
                {
                    Store (0xf8, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xf8, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xf8, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PHF8) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xf8, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PHF8, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SF9)
            {
                Name (_ADR, 0x001f0001) /* Dev 0x1f, Func 0x1 */
                Name (_SUN, 0x0000001f)

                Method (_PS0, 0)
                {
                    Store (0xf9, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xf9, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xf9, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PHF8) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xf9, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PHF8, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SFA)
            {
                Name (_ADR, 0x001f0002) /* Dev 0x1f, Func 0x2 */
                Name (_SUN, 0x0000001f)

                Method (_PS0, 0)
                {
                    Store (0xfa, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xfa, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xfa, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PHFA) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xfa, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PHFA, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SFB)
            {
                Name (_ADR, 0x001f0003) /* Dev 0x1f, Func 0x3 */
                Name (_SUN, 0x0000001f)

                Method (_PS0, 0)
                {
                    Store (0xfb, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xfb, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xfb, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PHFA) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xfb, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PHFA, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SFC)
            {
                Name (_ADR, 0x001f0004) /* Dev 0x1f, Func 0x4 */
                Name (_SUN, 0x0000001f)

                Method (_PS0, 0)
                {
                    Store (0xfc, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xfc, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xfc, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PHFC) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xfc, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PHFC, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SFD)
            {
                Name (_ADR, 0x001f0005) /* Dev 0x1f, Func 0x5 */
                Name (_SUN, 0x0000001f)

                Method (_PS0, 0)
                {
                    Store (0xfd, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xfd, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xfd, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PHFC) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xfd, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PHFC, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SFE)
            {
                Name (_ADR, 0x001f0006) /* Dev 0x1f, Func 0x6 */
                Name (_SUN, 0x0000001f)

                Method (_PS0, 0)
                {
                    Store (0xfe, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xfe, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xfe, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x01, \_GPE.PHFE) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xfe, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    And (\_GPE.PHFE, 0x0f, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

            Device(SFF)
            {
                Name (_ADR, 0x001f0007) /* Dev 0x1f, Func 0x7 */
                Name (_SUN, 0x0000001f)

                Method (_PS0, 0)
                {
                    Store (0xff, \_GPE.DPT1)
                    Store (0x80, \_GPE.DPT2)
                }

                Method (_PS3, 0)
                {
                    Store (0xff, \_GPE.DPT1)
                    Store (0x83, \_GPE.DPT2)
                }

                Method (_EJ0, 1)
                {
                    Store (0xff, \_GPE.DPT1)
                    Store (0x88, \_GPE.DPT2)
                    Store (0x10, \_GPE.PHFE) /* eject */
                }

                Method (_STA, 0)
                {
                    Store (0xff, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    ShiftRight (0x4, \_GPE.PHFE, Local1)
                    Return (Local1) /* IN status as the _STA */
                }
            }

        }
    }

    Scope (\_GPE)
    {
        OperationRegion (PHP, SystemIO, 0x10c0, 0x82)
        Field (PHP, ByteAcc, NoLock, Preserve)
        {
            PSTA,  8, /* hotplug controller event reg */
            PSTB,  8, /* hotplug controller slot reg */
            PH00,  8, /* hotplug Dev 0x00, Func 0x0 and 0x1 control reg */
            PH02,  8, /* hotplug Dev 0x00, Func 0x2 and 0x3 control reg */
            PH04,  8, /* hotplug Dev 0x00, Func 0x4 and 0x5 control reg */
            PH06,  8, /* hotplug Dev 0x00, Func 0x6 and 0x7 control reg */
            PH08,  8, /* hotplug Dev 0x01, Func 0x0 and 0x1 control reg */
            PH0A,  8, /* hotplug Dev 0x01, Func 0x2 and 0x3 control reg */
            PH0C,  8, /* hotplug Dev 0x01, Func 0x4 and 0x5 control reg */
            PH0E,  8, /* hotplug Dev 0x01, Func 0x6 and 0x7 control reg */
            PH10,  8, /* hotplug Dev 0x02, Func 0x0 and 0x1 control reg */
            PH12,  8, /* hotplug Dev 0x02, Func 0x2 and 0x3 control reg */
            PH14,  8, /* hotplug Dev 0x02, Func 0x4 and 0x5 control reg */
            PH16,  8, /* hotplug Dev 0x02, Func 0x6 and 0x7 control reg */
            PH18,  8, /* hotplug Dev 0x03, Func 0x0 and 0x1 control reg */
            PH1A,  8, /* hotplug Dev 0x03, Func 0x2 and 0x3 control reg */
            PH1C,  8, /* hotplug Dev 0x03, Func 0x4 and 0x5 control reg */
            PH1E,  8, /* hotplug Dev 0x03, Func 0x6 and 0x7 control reg */
            PH20,  8, /* hotplug Dev 0x04, Func 0x0 and 0x1 control reg */
            PH22,  8, /* hotplug Dev 0x04, Func 0x2 and 0x3 control reg */
            PH24,  8, /* hotplug Dev 0x04, Func 0x4 and 0x5 control reg */
            PH26,  8, /* hotplug Dev 0x04, Func 0x6 and 0x7 control reg */
            PH28,  8, /* hotplug Dev 0x05, Func 0x0 and 0x1 control reg */
            PH2A,  8, /* hotplug Dev 0x05, Func 0x2 and 0x3 control reg */
            PH2C,  8, /* hotplug Dev 0x05, Func 0x4 and 0x5 control reg */
            PH2E,  8, /* hotplug Dev 0x05, Func 0x6 and 0x7 control reg */
            PH30,  8, /* hotplug Dev 0x06, Func 0x0 and 0x1 control reg */
            PH32,  8, /* hotplug Dev 0x06, Func 0x2 and 0x3 control reg */
            PH34,  8, /* hotplug Dev 0x06, Func 0x4 and 0x5 control reg */
            PH36,  8, /* hotplug Dev 0x06, Func 0x6 and 0x7 control reg */
            PH38,  8, /* hotplug Dev 0x07, Func 0x0 and 0x1 control reg */
            PH3A,  8, /* hotplug Dev 0x07, Func 0x2 and 0x3 control reg */
            PH3C,  8, /* hotplug Dev 0x07, Func 0x4 and 0x5 control reg */
            PH3E,  8, /* hotplug Dev 0x07, Func 0x6 and 0x7 control reg */
            PH40,  8, /* hotplug Dev 0x08, Func 0x0 and 0x1 control reg */
            PH42,  8, /* hotplug Dev 0x08, Func 0x2 and 0x3 control reg */
            PH44,  8, /* hotplug Dev 0x08, Func 0x4 and 0x5 control reg */
            PH46,  8, /* hotplug Dev 0x08, Func 0x6 and 0x7 control reg */
            PH48,  8, /* hotplug Dev 0x09, Func 0x0 and 0x1 control reg */
            PH4A,  8, /* hotplug Dev 0x09, Func 0x2 and 0x3 control reg */
            PH4C,  8, /* hotplug Dev 0x09, Func 0x4 and 0x5 control reg */
            PH4E,  8, /* hotplug Dev 0x09, Func 0x6 and 0x7 control reg */
            PH50,  8, /* hotplug Dev 0x0a, Func 0x0 and 0x1 control reg */
            PH52,  8, /* hotplug Dev 0x0a, Func 0x2 and 0x3 control reg */
            PH54,  8, /* hotplug Dev 0x0a, Func 0x4 and 0x5 control reg */
            PH56,  8, /* hotplug Dev 0x0a, Func 0x6 and 0x7 control reg */
            PH58,  8, /* hotplug Dev 0x0b, Func 0x0 and 0x1 control reg */
            PH5A,  8, /* hotplug Dev 0x0b, Func 0x2 and 0x3 control reg */
            PH5C,  8, /* hotplug Dev 0x0b, Func 0x4 and 0x5 control reg */
            PH5E,  8, /* hotplug Dev 0x0b, Func 0x6 and 0x7 control reg */
            PH60,  8, /* hotplug Dev 0x0c, Func 0x0 and 0x1 control reg */
            PH62,  8, /* hotplug Dev 0x0c, Func 0x2 and 0x3 control reg */
            PH64,  8, /* hotplug Dev 0x0c, Func 0x4 and 0x5 control reg */
            PH66,  8, /* hotplug Dev 0x0c, Func 0x6 and 0x7 control reg */
            PH68,  8, /* hotplug Dev 0x0d, Func 0x0 and 0x1 control reg */
            PH6A,  8, /* hotplug Dev 0x0d, Func 0x2 and 0x3 control reg */
            PH6C,  8, /* hotplug Dev 0x0d, Func 0x4 and 0x5 control reg */
            PH6E,  8, /* hotplug Dev 0x0d, Func 0x6 and 0x7 control reg */
            PH70,  8, /* hotplug Dev 0x0e, Func 0x0 and 0x1 control reg */
            PH72,  8, /* hotplug Dev 0x0e, Func 0x2 and 0x3 control reg */
            PH74,  8, /* hotplug Dev 0x0e, Func 0x4 and 0x5 control reg */
            PH76,  8, /* hotplug Dev 0x0e, Func 0x6 and 0x7 control reg */
            PH78,  8, /* hotplug Dev 0x0f, Func 0x0 and 0x1 control reg */
            PH7A,  8, /* hotplug Dev 0x0f, Func 0x2 and 0x3 control reg */
            PH7C,  8, /* hotplug Dev 0x0f, Func 0x4 and 0x5 control reg */
            PH7E,  8, /* hotplug Dev 0x0f, Func 0x6 and 0x7 control reg */
            PH80,  8, /* hotplug Dev 0x10, Func 0x0 and 0x1 control reg */
            PH82,  8, /* hotplug Dev 0x10, Func 0x2 and 0x3 control reg */
            PH84,  8, /* hotplug Dev 0x10, Func 0x4 and 0x5 control reg */
            PH86,  8, /* hotplug Dev 0x10, Func 0x6 and 0x7 control reg */
            PH88,  8, /* hotplug Dev 0x11, Func 0x0 and 0x1 control reg */
            PH8A,  8, /* hotplug Dev 0x11, Func 0x2 and 0x3 control reg */
            PH8C,  8, /* hotplug Dev 0x11, Func 0x4 and 0x5 control reg */
            PH8E,  8, /* hotplug Dev 0x11, Func 0x6 and 0x7 control reg */
            PH90,  8, /* hotplug Dev 0x12, Func 0x0 and 0x1 control reg */
            PH92,  8, /* hotplug Dev 0x12, Func 0x2 and 0x3 control reg */
            PH94,  8, /* hotplug Dev 0x12, Func 0x4 and 0x5 control reg */
            PH96,  8, /* hotplug Dev 0x12, Func 0x6 and 0x7 control reg */
            PH98,  8, /* hotplug Dev 0x13, Func 0x0 and 0x1 control reg */
            PH9A,  8, /* hotplug Dev 0x13, Func 0x2 and 0x3 control reg */
            PH9C,  8, /* hotplug Dev 0x13, Func 0x4 and 0x5 control reg */
            PH9E,  8, /* hotplug Dev 0x13, Func 0x6 and 0x7 control reg */
            PHA0,  8, /* hotplug Dev 0x14, Func 0x0 and 0x1 control reg */
            PHA2,  8, /* hotplug Dev 0x14, Func 0x2 and 0x3 control reg */
            PHA4,  8, /* hotplug Dev 0x14, Func 0x4 and 0x5 control reg */
            PHA6,  8, /* hotplug Dev 0x14, Func 0x6 and 0x7 control reg */
            PHA8,  8, /* hotplug Dev 0x15, Func 0x0 and 0x1 control reg */
            PHAA,  8, /* hotplug Dev 0x15, Func 0x2 and 0x3 control reg */
            PHAC,  8, /* hotplug Dev 0x15, Func 0x4 and 0x5 control reg */
            PHAE,  8, /* hotplug Dev 0x15, Func 0x6 and 0x7 control reg */
            PHB0,  8, /* hotplug Dev 0x16, Func 0x0 and 0x1 control reg */
            PHB2,  8, /* hotplug Dev 0x16, Func 0x2 and 0x3 control reg */
            PHB4,  8, /* hotplug Dev 0x16, Func 0x4 and 0x5 control reg */
            PHB6,  8, /* hotplug Dev 0x16, Func 0x6 and 0x7 control reg */
            PHB8,  8, /* hotplug Dev 0x17, Func 0x0 and 0x1 control reg */
            PHBA,  8, /* hotplug Dev 0x17, Func 0x2 and 0x3 control reg */
            PHBC,  8, /* hotplug Dev 0x17, Func 0x4 and 0x5 control reg */
            PHBE,  8, /* hotplug Dev 0x17, Func 0x6 and 0x7 control reg */
            PHC0,  8, /* hotplug Dev 0x18, Func 0x0 and 0x1 control reg */
            PHC2,  8, /* hotplug Dev 0x18, Func 0x2 and 0x3 control reg */
            PHC4,  8, /* hotplug Dev 0x18, Func 0x4 and 0x5 control reg */
            PHC6,  8, /* hotplug Dev 0x18, Func 0x6 and 0x7 control reg */
            PHC8,  8, /* hotplug Dev 0x19, Func 0x0 and 0x1 control reg */
            PHCA,  8, /* hotplug Dev 0x19, Func 0x2 and 0x3 control reg */
            PHCC,  8, /* hotplug Dev 0x19, Func 0x4 and 0x5 control reg */
            PHCE,  8, /* hotplug Dev 0x19, Func 0x6 and 0x7 control reg */
            PHD0,  8, /* hotplug Dev 0x1a, Func 0x0 and 0x1 control reg */
            PHD2,  8, /* hotplug Dev 0x1a, Func 0x2 and 0x3 control reg */
            PHD4,  8, /* hotplug Dev 0x1a, Func 0x4 and 0x5 control reg */
            PHD6,  8, /* hotplug Dev 0x1a, Func 0x6 and 0x7 control reg */
            PHD8,  8, /* hotplug Dev 0x1b, Func 0x0 and 0x1 control reg */
            PHDA,  8, /* hotplug Dev 0x1b, Func 0x2 and 0x3 control reg */
            PHDC,  8, /* hotplug Dev 0x1b, Func 0x4 and 0x5 control reg */
            PHDE,  8, /* hotplug Dev 0x1b, Func 0x6 and 0x7 control reg */
            PHE0,  8, /* hotplug Dev 0x1c, Func 0x0 and 0x1 control reg */
            PHE2,  8, /* hotplug Dev 0x1c, Func 0x2 and 0x3 control reg */
            PHE4,  8, /* hotplug Dev 0x1c, Func 0x4 and 0x5 control reg */
            PHE6,  8, /* hotplug Dev 0x1c, Func 0x6 and 0x7 control reg */
            PHE8,  8, /* hotplug Dev 0x1d, Func 0x0 and 0x1 control reg */
            PHEA,  8, /* hotplug Dev 0x1d, Func 0x2 and 0x3 control reg */
            PHEC,  8, /* hotplug Dev 0x1d, Func 0x4 and 0x5 control reg */
            PHEE,  8, /* hotplug Dev 0x1d, Func 0x6 and 0x7 control reg */
            PHF0,  8, /* hotplug Dev 0x1e, Func 0x0 and 0x1 control reg */
            PHF2,  8, /* hotplug Dev 0x1e, Func 0x2 and 0x3 control reg */
            PHF4,  8, /* hotplug Dev 0x1e, Func 0x4 and 0x5 control reg */
            PHF6,  8, /* hotplug Dev 0x1e, Func 0x6 and 0x7 control reg */
            PHF8,  8, /* hotplug Dev 0x1f, Func 0x0 and 0x1 control reg */
            PHFA,  8, /* hotplug Dev 0x1f, Func 0x2 and 0x3 control reg */
            PHFC,  8, /* hotplug Dev 0x1f, Func 0x4 and 0x5 control reg */
            PHFE,  8, /* hotplug Dev 0x1f, Func 0x6 and 0x7 control reg */
        }
        OperationRegion (DG1, SystemIO, 0xb044, 0x04)
        Field (DG1, ByteAcc, NoLock, Preserve)
        {
            DPT1,   8,
            DPT2,   8
        }
        Method (_L03, 0, Serialized)
        {
            /* detect slot and event(remove/add) */
            Name (SLT, 0x0)
            Name (EVT, 0x0)
            Store (PSTA, Local1)
            And (Local1, 0xf, EVT)
            Store (PSTB, Local1)           /* XXX: Store (PSTB, SLT) ? */
            And (Local1, 0xff, SLT)

            /* debug */
            Store (SLT, DPT1)
            Store (EVT, DPT2)

            If ( LEqual(SLT, 0x00) )
            {
                Notify (\_SB.PCI0.S00, EVT)
            }
            ElseIf ( LEqual(SLT, 0x01) )
            {
                Notify (\_SB.PCI0.S01, EVT)
            }
            ElseIf ( LEqual(SLT, 0x02) )
            {
                Notify (\_SB.PCI0.S02, EVT)
            }
            ElseIf ( LEqual(SLT, 0x03) )
            {
                Notify (\_SB.PCI0.S03, EVT)
            }
            ElseIf ( LEqual(SLT, 0x04) )
            {
                Notify (\_SB.PCI0.S04, EVT)
            }
            ElseIf ( LEqual(SLT, 0x05) )
            {
                Notify (\_SB.PCI0.S05, EVT)
            }
            ElseIf ( LEqual(SLT, 0x06) )
            {
                Notify (\_SB.PCI0.S06, EVT)
            }
            ElseIf ( LEqual(SLT, 0x07) )
            {
                Notify (\_SB.PCI0.S07, EVT)
            }
            ElseIf ( LEqual(SLT, 0x08) )
            {
                Notify (\_SB.PCI0.S08, EVT)
            }
            ElseIf ( LEqual(SLT, 0x09) )
            {
                Notify (\_SB.PCI0.S09, EVT)
            }
            ElseIf ( LEqual(SLT, 0x0a) )
            {
                Notify (\_SB.PCI0.S0A, EVT)
            }
            ElseIf ( LEqual(SLT, 0x0b) )
            {
                Notify (\_SB.PCI0.S0B, EVT)
            }
            ElseIf ( LEqual(SLT, 0x0c) )
            {
                Notify (\_SB.PCI0.S0C, EVT)
            }
            ElseIf ( LEqual(SLT, 0x0d) )
            {
                Notify (\_SB.PCI0.S0D, EVT)
            }
            ElseIf ( LEqual(SLT, 0x0e) )
            {
                Notify (\_SB.PCI0.S0E, EVT)
            }
            ElseIf ( LEqual(SLT, 0x0f) )
            {
                Notify (\_SB.PCI0.S0F, EVT)
            }
            ElseIf ( LEqual(SLT, 0x10) )
            {
                Notify (\_SB.PCI0.S10, EVT)
            }
            ElseIf ( LEqual(SLT, 0x11) )
            {
                Notify (\_SB.PCI0.S11, EVT)
            }
            ElseIf ( LEqual(SLT, 0x12) )
            {
                Notify (\_SB.PCI0.S12, EVT)
            }
            ElseIf ( LEqual(SLT, 0x13) )
            {
                Notify (\_SB.PCI0.S13, EVT)
            }
            ElseIf ( LEqual(SLT, 0x14) )
            {
                Notify (\_SB.PCI0.S14, EVT)
            }
            ElseIf ( LEqual(SLT, 0x15) )
            {
                Notify (\_SB.PCI0.S15, EVT)
            }
            ElseIf ( LEqual(SLT, 0x16) )
            {
                Notify (\_SB.PCI0.S16, EVT)
            }
            ElseIf ( LEqual(SLT, 0x17) )
            {
                Notify (\_SB.PCI0.S17, EVT)
            }
            ElseIf ( LEqual(SLT, 0x18) )
            {
                Notify (\_SB.PCI0.S18, EVT)
            }
            ElseIf ( LEqual(SLT, 0x19) )
            {
                Notify (\_SB.PCI0.S19, EVT)
            }
            ElseIf ( LEqual(SLT, 0x1a) )
            {
                Notify (\_SB.PCI0.S1A, EVT)
            }
            ElseIf ( LEqual(SLT, 0x1b) )
            {
                Notify (\_SB.PCI0.S1B, EVT)
            }
            ElseIf ( LEqual(SLT, 0x1c) )
            {
                Notify (\_SB.PCI0.S1C, EVT)
            }
            ElseIf ( LEqual(SLT, 0x1d) )
            {
                Notify (\_SB.PCI0.S1D, EVT)
            }
            ElseIf ( LEqual(SLT, 0x1e) )
            {
                Notify (\_SB.PCI0.S1E, EVT)
            }
            ElseIf ( LEqual(SLT, 0x1f) )
            {
                Notify (\_SB.PCI0.S1F, EVT)
            }
            ElseIf ( LEqual(SLT, 0x20) )
            {
                Notify (\_SB.PCI0.S20, EVT)
            }
            ElseIf ( LEqual(SLT, 0x21) )
            {
                Notify (\_SB.PCI0.S21, EVT)
            }
            ElseIf ( LEqual(SLT, 0x22) )
            {
                Notify (\_SB.PCI0.S22, EVT)
            }
            ElseIf ( LEqual(SLT, 0x23) )
            {
                Notify (\_SB.PCI0.S23, EVT)
            }
            ElseIf ( LEqual(SLT, 0x24) )
            {
                Notify (\_SB.PCI0.S24, EVT)
            }
            ElseIf ( LEqual(SLT, 0x25) )
            {
                Notify (\_SB.PCI0.S25, EVT)
            }
            ElseIf ( LEqual(SLT, 0x26) )
            {
                Notify (\_SB.PCI0.S26, EVT)
            }
            ElseIf ( LEqual(SLT, 0x27) )
            {
                Notify (\_SB.PCI0.S27, EVT)
            }
            ElseIf ( LEqual(SLT, 0x28) )
            {
                Notify (\_SB.PCI0.S28, EVT)
            }
            ElseIf ( LEqual(SLT, 0x29) )
            {
                Notify (\_SB.PCI0.S29, EVT)
            }
            ElseIf ( LEqual(SLT, 0x2a) )
            {
                Notify (\_SB.PCI0.S2A, EVT)
            }
            ElseIf ( LEqual(SLT, 0x2b) )
            {
                Notify (\_SB.PCI0.S2B, EVT)
            }
            ElseIf ( LEqual(SLT, 0x2c) )
            {
                Notify (\_SB.PCI0.S2C, EVT)
            }
            ElseIf ( LEqual(SLT, 0x2d) )
            {
                Notify (\_SB.PCI0.S2D, EVT)
            }
            ElseIf ( LEqual(SLT, 0x2e) )
            {
                Notify (\_SB.PCI0.S2E, EVT)
            }
            ElseIf ( LEqual(SLT, 0x2f) )
            {
                Notify (\_SB.PCI0.S2F, EVT)
            }
            ElseIf ( LEqual(SLT, 0x30) )
            {
                Notify (\_SB.PCI0.S30, EVT)
            }
            ElseIf ( LEqual(SLT, 0x31) )
            {
                Notify (\_SB.PCI0.S31, EVT)
            }
            ElseIf ( LEqual(SLT, 0x32) )
            {
                Notify (\_SB.PCI0.S32, EVT)
            }
            ElseIf ( LEqual(SLT, 0x33) )
            {
                Notify (\_SB.PCI0.S33, EVT)
            }
            ElseIf ( LEqual(SLT, 0x34) )
            {
                Notify (\_SB.PCI0.S34, EVT)
            }
            ElseIf ( LEqual(SLT, 0x35) )
            {
                Notify (\_SB.PCI0.S35, EVT)
            }
            ElseIf ( LEqual(SLT, 0x36) )
            {
                Notify (\_SB.PCI0.S36, EVT)
            }
            ElseIf ( LEqual(SLT, 0x37) )
            {
                Notify (\_SB.PCI0.S37, EVT)
            }
            ElseIf ( LEqual(SLT, 0x38) )
            {
                Notify (\_SB.PCI0.S38, EVT)
            }
            ElseIf ( LEqual(SLT, 0x39) )
            {
                Notify (\_SB.PCI0.S39, EVT)
            }
            ElseIf ( LEqual(SLT, 0x3a) )
            {
                Notify (\_SB.PCI0.S3A, EVT)
            }
            ElseIf ( LEqual(SLT, 0x3b) )
            {
                Notify (\_SB.PCI0.S3B, EVT)
            }
            ElseIf ( LEqual(SLT, 0x3c) )
            {
                Notify (\_SB.PCI0.S3C, EVT)
            }
            ElseIf ( LEqual(SLT, 0x3d) )
            {
                Notify (\_SB.PCI0.S3D, EVT)
            }
            ElseIf ( LEqual(SLT, 0x3e) )
            {
                Notify (\_SB.PCI0.S3E, EVT)
            }
            ElseIf ( LEqual(SLT, 0x3f) )
            {
                Notify (\_SB.PCI0.S3F, EVT)
            }
            ElseIf ( LEqual(SLT, 0x40) )
            {
                Notify (\_SB.PCI0.S40, EVT)
            }
            ElseIf ( LEqual(SLT, 0x41) )
            {
                Notify (\_SB.PCI0.S41, EVT)
            }
            ElseIf ( LEqual(SLT, 0x42) )
            {
                Notify (\_SB.PCI0.S42, EVT)
            }
            ElseIf ( LEqual(SLT, 0x43) )
            {
                Notify (\_SB.PCI0.S43, EVT)
            }
            ElseIf ( LEqual(SLT, 0x44) )
            {
                Notify (\_SB.PCI0.S44, EVT)
            }
            ElseIf ( LEqual(SLT, 0x45) )
            {
                Notify (\_SB.PCI0.S45, EVT)
            }
            ElseIf ( LEqual(SLT, 0x46) )
            {
                Notify (\_SB.PCI0.S46, EVT)
            }
            ElseIf ( LEqual(SLT, 0x47) )
            {
                Notify (\_SB.PCI0.S47, EVT)
            }
            ElseIf ( LEqual(SLT, 0x48) )
            {
                Notify (\_SB.PCI0.S48, EVT)
            }
            ElseIf ( LEqual(SLT, 0x49) )
            {
                Notify (\_SB.PCI0.S49, EVT)
            }
            ElseIf ( LEqual(SLT, 0x4a) )
            {
                Notify (\_SB.PCI0.S4A, EVT)
            }
            ElseIf ( LEqual(SLT, 0x4b) )
            {
                Notify (\_SB.PCI0.S4B, EVT)
            }
            ElseIf ( LEqual(SLT, 0x4c) )
            {
                Notify (\_SB.PCI0.S4C, EVT)
            }
            ElseIf ( LEqual(SLT, 0x4d) )
            {
                Notify (\_SB.PCI0.S4D, EVT)
            }
            ElseIf ( LEqual(SLT, 0x4e) )
            {
                Notify (\_SB.PCI0.S4E, EVT)
            }
            ElseIf ( LEqual(SLT, 0x4f) )
            {
                Notify (\_SB.PCI0.S4F, EVT)
            }
            ElseIf ( LEqual(SLT, 0x50) )
            {
                Notify (\_SB.PCI0.S50, EVT)
            }
            ElseIf ( LEqual(SLT, 0x51) )
            {
                Notify (\_SB.PCI0.S51, EVT)
            }
            ElseIf ( LEqual(SLT, 0x52) )
            {
                Notify (\_SB.PCI0.S52, EVT)
            }
            ElseIf ( LEqual(SLT, 0x53) )
            {
                Notify (\_SB.PCI0.S53, EVT)
            }
            ElseIf ( LEqual(SLT, 0x54) )
            {
                Notify (\_SB.PCI0.S54, EVT)
            }
            ElseIf ( LEqual(SLT, 0x55) )
            {
                Notify (\_SB.PCI0.S55, EVT)
            }
            ElseIf ( LEqual(SLT, 0x56) )
            {
                Notify (\_SB.PCI0.S56, EVT)
            }
            ElseIf ( LEqual(SLT, 0x57) )
            {
                Notify (\_SB.PCI0.S57, EVT)
            }
            ElseIf ( LEqual(SLT, 0x58) )
            {
                Notify (\_SB.PCI0.S58, EVT)
            }
            ElseIf ( LEqual(SLT, 0x59) )
            {
                Notify (\_SB.PCI0.S59, EVT)
            }
            ElseIf ( LEqual(SLT, 0x5a) )
            {
                Notify (\_SB.PCI0.S5A, EVT)
            }
            ElseIf ( LEqual(SLT, 0x5b) )
            {
                Notify (\_SB.PCI0.S5B, EVT)
            }
            ElseIf ( LEqual(SLT, 0x5c) )
            {
                Notify (\_SB.PCI0.S5C, EVT)
            }
            ElseIf ( LEqual(SLT, 0x5d) )
            {
                Notify (\_SB.PCI0.S5D, EVT)
            }
            ElseIf ( LEqual(SLT, 0x5e) )
            {
                Notify (\_SB.PCI0.S5E, EVT)
            }
            ElseIf ( LEqual(SLT, 0x5f) )
            {
                Notify (\_SB.PCI0.S5F, EVT)
            }
            ElseIf ( LEqual(SLT, 0x60) )
            {
                Notify (\_SB.PCI0.S60, EVT)
            }
            ElseIf ( LEqual(SLT, 0x61) )
            {
                Notify (\_SB.PCI0.S61, EVT)
            }
            ElseIf ( LEqual(SLT, 0x62) )
            {
                Notify (\_SB.PCI0.S62, EVT)
            }
            ElseIf ( LEqual(SLT, 0x63) )
            {
                Notify (\_SB.PCI0.S63, EVT)
            }
            ElseIf ( LEqual(SLT, 0x64) )
            {
                Notify (\_SB.PCI0.S64, EVT)
            }
            ElseIf ( LEqual(SLT, 0x65) )
            {
                Notify (\_SB.PCI0.S65, EVT)
            }
            ElseIf ( LEqual(SLT, 0x66) )
            {
                Notify (\_SB.PCI0.S66, EVT)
            }
            ElseIf ( LEqual(SLT, 0x67) )
            {
                Notify (\_SB.PCI0.S67, EVT)
            }
            ElseIf ( LEqual(SLT, 0x68) )
            {
                Notify (\_SB.PCI0.S68, EVT)
            }
            ElseIf ( LEqual(SLT, 0x69) )
            {
                Notify (\_SB.PCI0.S69, EVT)
            }
            ElseIf ( LEqual(SLT, 0x6a) )
            {
                Notify (\_SB.PCI0.S6A, EVT)
            }
            ElseIf ( LEqual(SLT, 0x6b) )
            {
                Notify (\_SB.PCI0.S6B, EVT)
            }
            ElseIf ( LEqual(SLT, 0x6c) )
            {
                Notify (\_SB.PCI0.S6C, EVT)
            }
            ElseIf ( LEqual(SLT, 0x6d) )
            {
                Notify (\_SB.PCI0.S6D, EVT)
            }
            ElseIf ( LEqual(SLT, 0x6e) )
            {
                Notify (\_SB.PCI0.S6E, EVT)
            }
            ElseIf ( LEqual(SLT, 0x6f) )
            {
                Notify (\_SB.PCI0.S6F, EVT)
            }
            ElseIf ( LEqual(SLT, 0x70) )
            {
                Notify (\_SB.PCI0.S70, EVT)
            }
            ElseIf ( LEqual(SLT, 0x71) )
            {
                Notify (\_SB.PCI0.S71, EVT)
            }
            ElseIf ( LEqual(SLT, 0x72) )
            {
                Notify (\_SB.PCI0.S72, EVT)
            }
            ElseIf ( LEqual(SLT, 0x73) )
            {
                Notify (\_SB.PCI0.S73, EVT)
            }
            ElseIf ( LEqual(SLT, 0x74) )
            {
                Notify (\_SB.PCI0.S74, EVT)
            }
            ElseIf ( LEqual(SLT, 0x75) )
            {
                Notify (\_SB.PCI0.S75, EVT)
            }
            ElseIf ( LEqual(SLT, 0x76) )
            {
                Notify (\_SB.PCI0.S76, EVT)
            }
            ElseIf ( LEqual(SLT, 0x77) )
            {
                Notify (\_SB.PCI0.S77, EVT)
            }
            ElseIf ( LEqual(SLT, 0x78) )
            {
                Notify (\_SB.PCI0.S78, EVT)
            }
            ElseIf ( LEqual(SLT, 0x79) )
            {
                Notify (\_SB.PCI0.S79, EVT)
            }
            ElseIf ( LEqual(SLT, 0x7a) )
            {
                Notify (\_SB.PCI0.S7A, EVT)
            }
            ElseIf ( LEqual(SLT, 0x7b) )
            {
                Notify (\_SB.PCI0.S7B, EVT)
            }
            ElseIf ( LEqual(SLT, 0x7c) )
            {
                Notify (\_SB.PCI0.S7C, EVT)
            }
            ElseIf ( LEqual(SLT, 0x7d) )
            {
                Notify (\_SB.PCI0.S7D, EVT)
            }
            ElseIf ( LEqual(SLT, 0x7e) )
            {
                Notify (\_SB.PCI0.S7E, EVT)
            }
            ElseIf ( LEqual(SLT, 0x7f) )
            {
                Notify (\_SB.PCI0.S7F, EVT)
            }
            ElseIf ( LEqual(SLT, 0x80) )
            {
                Notify (\_SB.PCI0.S80, EVT)
            }
            ElseIf ( LEqual(SLT, 0x81) )
            {
                Notify (\_SB.PCI0.S81, EVT)
            }
            ElseIf ( LEqual(SLT, 0x82) )
            {
                Notify (\_SB.PCI0.S82, EVT)
            }
            ElseIf ( LEqual(SLT, 0x83) )
            {
                Notify (\_SB.PCI0.S83, EVT)
            }
            ElseIf ( LEqual(SLT, 0x84) )
            {
                Notify (\_SB.PCI0.S84, EVT)
            }
            ElseIf ( LEqual(SLT, 0x85) )
            {
                Notify (\_SB.PCI0.S85, EVT)
            }
            ElseIf ( LEqual(SLT, 0x86) )
            {
                Notify (\_SB.PCI0.S86, EVT)
            }
            ElseIf ( LEqual(SLT, 0x87) )
            {
                Notify (\_SB.PCI0.S87, EVT)
            }
            ElseIf ( LEqual(SLT, 0x88) )
            {
                Notify (\_SB.PCI0.S88, EVT)
            }
            ElseIf ( LEqual(SLT, 0x89) )
            {
                Notify (\_SB.PCI0.S89, EVT)
            }
            ElseIf ( LEqual(SLT, 0x8a) )
            {
                Notify (\_SB.PCI0.S8A, EVT)
            }
            ElseIf ( LEqual(SLT, 0x8b) )
            {
                Notify (\_SB.PCI0.S8B, EVT)
            }
            ElseIf ( LEqual(SLT, 0x8c) )
            {
                Notify (\_SB.PCI0.S8C, EVT)
            }
            ElseIf ( LEqual(SLT, 0x8d) )
            {
                Notify (\_SB.PCI0.S8D, EVT)
            }
            ElseIf ( LEqual(SLT, 0x8e) )
            {
                Notify (\_SB.PCI0.S8E, EVT)
            }
            ElseIf ( LEqual(SLT, 0x8f) )
            {
                Notify (\_SB.PCI0.S8F, EVT)
            }
            ElseIf ( LEqual(SLT, 0x90) )
            {
                Notify (\_SB.PCI0.S90, EVT)
            }
            ElseIf ( LEqual(SLT, 0x91) )
            {
                Notify (\_SB.PCI0.S91, EVT)
            }
            ElseIf ( LEqual(SLT, 0x92) )
            {
                Notify (\_SB.PCI0.S92, EVT)
            }
            ElseIf ( LEqual(SLT, 0x93) )
            {
                Notify (\_SB.PCI0.S93, EVT)
            }
            ElseIf ( LEqual(SLT, 0x94) )
            {
                Notify (\_SB.PCI0.S94, EVT)
            }
            ElseIf ( LEqual(SLT, 0x95) )
            {
                Notify (\_SB.PCI0.S95, EVT)
            }
            ElseIf ( LEqual(SLT, 0x96) )
            {
                Notify (\_SB.PCI0.S96, EVT)
            }
            ElseIf ( LEqual(SLT, 0x97) )
            {
                Notify (\_SB.PCI0.S97, EVT)
            }
            ElseIf ( LEqual(SLT, 0x98) )
            {
                Notify (\_SB.PCI0.S98, EVT)
            }
            ElseIf ( LEqual(SLT, 0x99) )
            {
                Notify (\_SB.PCI0.S99, EVT)
            }
            ElseIf ( LEqual(SLT, 0x9a) )
            {
                Notify (\_SB.PCI0.S9A, EVT)
            }
            ElseIf ( LEqual(SLT, 0x9b) )
            {
                Notify (\_SB.PCI0.S9B, EVT)
            }
            ElseIf ( LEqual(SLT, 0x9c) )
            {
                Notify (\_SB.PCI0.S9C, EVT)
            }
            ElseIf ( LEqual(SLT, 0x9d) )
            {
                Notify (\_SB.PCI0.S9D, EVT)
            }
            ElseIf ( LEqual(SLT, 0x9e) )
            {
                Notify (\_SB.PCI0.S9E, EVT)
            }
            ElseIf ( LEqual(SLT, 0x9f) )
            {
                Notify (\_SB.PCI0.S9F, EVT)
            }
            ElseIf ( LEqual(SLT, 0xa0) )
            {
                Notify (\_SB.PCI0.SA0, EVT)
            }
            ElseIf ( LEqual(SLT, 0xa1) )
            {
                Notify (\_SB.PCI0.SA1, EVT)
            }
            ElseIf ( LEqual(SLT, 0xa2) )
            {
                Notify (\_SB.PCI0.SA2, EVT)
            }
            ElseIf ( LEqual(SLT, 0xa3) )
            {
                Notify (\_SB.PCI0.SA3, EVT)
            }
            ElseIf ( LEqual(SLT, 0xa4) )
            {
                Notify (\_SB.PCI0.SA4, EVT)
            }
            ElseIf ( LEqual(SLT, 0xa5) )
            {
                Notify (\_SB.PCI0.SA5, EVT)
            }
            ElseIf ( LEqual(SLT, 0xa6) )
            {
                Notify (\_SB.PCI0.SA6, EVT)
            }
            ElseIf ( LEqual(SLT, 0xa7) )
            {
                Notify (\_SB.PCI0.SA7, EVT)
            }
            ElseIf ( LEqual(SLT, 0xa8) )
            {
                Notify (\_SB.PCI0.SA8, EVT)
            }
            ElseIf ( LEqual(SLT, 0xa9) )
            {
                Notify (\_SB.PCI0.SA9, EVT)
            }
            ElseIf ( LEqual(SLT, 0xaa) )
            {
                Notify (\_SB.PCI0.SAA, EVT)
            }
            ElseIf ( LEqual(SLT, 0xab) )
            {
                Notify (\_SB.PCI0.SAB, EVT)
            }
            ElseIf ( LEqual(SLT, 0xac) )
            {
                Notify (\_SB.PCI0.SAC, EVT)
            }
            ElseIf ( LEqual(SLT, 0xad) )
            {
                Notify (\_SB.PCI0.SAD, EVT)
            }
            ElseIf ( LEqual(SLT, 0xae) )
            {
                Notify (\_SB.PCI0.SAE, EVT)
            }
            ElseIf ( LEqual(SLT, 0xaf) )
            {
                Notify (\_SB.PCI0.SAF, EVT)
            }
            ElseIf ( LEqual(SLT, 0xb0) )
            {
                Notify (\_SB.PCI0.SB0, EVT)
            }
            ElseIf ( LEqual(SLT, 0xb1) )
            {
                Notify (\_SB.PCI0.SB1, EVT)
            }
            ElseIf ( LEqual(SLT, 0xb2) )
            {
                Notify (\_SB.PCI0.SB2, EVT)
            }
            ElseIf ( LEqual(SLT, 0xb3) )
            {
                Notify (\_SB.PCI0.SB3, EVT)
            }
            ElseIf ( LEqual(SLT, 0xb4) )
            {
                Notify (\_SB.PCI0.SB4, EVT)
            }
            ElseIf ( LEqual(SLT, 0xb5) )
            {
                Notify (\_SB.PCI0.SB5, EVT)
            }
            ElseIf ( LEqual(SLT, 0xb6) )
            {
                Notify (\_SB.PCI0.SB6, EVT)
            }
            ElseIf ( LEqual(SLT, 0xb7) )
            {
                Notify (\_SB.PCI0.SB7, EVT)
            }
            ElseIf ( LEqual(SLT, 0xb8) )
            {
                Notify (\_SB.PCI0.SB8, EVT)
            }
            ElseIf ( LEqual(SLT, 0xb9) )
            {
                Notify (\_SB.PCI0.SB9, EVT)
            }
            ElseIf ( LEqual(SLT, 0xba) )
            {
                Notify (\_SB.PCI0.SBA, EVT)
            }
            ElseIf ( LEqual(SLT, 0xbb) )
            {
                Notify (\_SB.PCI0.SBB, EVT)
            }
            ElseIf ( LEqual(SLT, 0xbc) )
            {
                Notify (\_SB.PCI0.SBC, EVT)
            }
            ElseIf ( LEqual(SLT, 0xbd) )
            {
                Notify (\_SB.PCI0.SBD, EVT)
            }
            ElseIf ( LEqual(SLT, 0xbe) )
            {
                Notify (\_SB.PCI0.SBE, EVT)
            }
            ElseIf ( LEqual(SLT, 0xbf) )
            {
                Notify (\_SB.PCI0.SBF, EVT)
            }
            ElseIf ( LEqual(SLT, 0xc0) )
            {
                Notify (\_SB.PCI0.SC0, EVT)
            }
            ElseIf ( LEqual(SLT, 0xc1) )
            {
                Notify (\_SB.PCI0.SC1, EVT)
            }
            ElseIf ( LEqual(SLT, 0xc2) )
            {
                Notify (\_SB.PCI0.SC2, EVT)
            }
            ElseIf ( LEqual(SLT, 0xc3) )
            {
                Notify (\_SB.PCI0.SC3, EVT)
            }
            ElseIf ( LEqual(SLT, 0xc4) )
            {
                Notify (\_SB.PCI0.SC4, EVT)
            }
            ElseIf ( LEqual(SLT, 0xc5) )
            {
                Notify (\_SB.PCI0.SC5, EVT)
            }
            ElseIf ( LEqual(SLT, 0xc6) )
            {
                Notify (\_SB.PCI0.SC6, EVT)
            }
            ElseIf ( LEqual(SLT, 0xc7) )
            {
                Notify (\_SB.PCI0.SC7, EVT)
            }
            ElseIf ( LEqual(SLT, 0xc8) )
            {
                Notify (\_SB.PCI0.SC8, EVT)
            }
            ElseIf ( LEqual(SLT, 0xc9) )
            {
                Notify (\_SB.PCI0.SC9, EVT)
            }
            ElseIf ( LEqual(SLT, 0xca) )
            {
                Notify (\_SB.PCI0.SCA, EVT)
            }
            ElseIf ( LEqual(SLT, 0xcb) )
            {
                Notify (\_SB.PCI0.SCB, EVT)
            }
            ElseIf ( LEqual(SLT, 0xcc) )
            {
                Notify (\_SB.PCI0.SCC, EVT)
            }
            ElseIf ( LEqual(SLT, 0xcd) )
            {
                Notify (\_SB.PCI0.SCD, EVT)
            }
            ElseIf ( LEqual(SLT, 0xce) )
            {
                Notify (\_SB.PCI0.SCE, EVT)
            }
            ElseIf ( LEqual(SLT, 0xcf) )
            {
                Notify (\_SB.PCI0.SCF, EVT)
            }
            ElseIf ( LEqual(SLT, 0xd0) )
            {
                Notify (\_SB.PCI0.SD0, EVT)
            }
            ElseIf ( LEqual(SLT, 0xd1) )
            {
                Notify (\_SB.PCI0.SD1, EVT)
            }
            ElseIf ( LEqual(SLT, 0xd2) )
            {
                Notify (\_SB.PCI0.SD2, EVT)
            }
            ElseIf ( LEqual(SLT, 0xd3) )
            {
                Notify (\_SB.PCI0.SD3, EVT)
            }
            ElseIf ( LEqual(SLT, 0xd4) )
            {
                Notify (\_SB.PCI0.SD4, EVT)
            }
            ElseIf ( LEqual(SLT, 0xd5) )
            {
                Notify (\_SB.PCI0.SD5, EVT)
            }
            ElseIf ( LEqual(SLT, 0xd6) )
            {
                Notify (\_SB.PCI0.SD6, EVT)
            }
            ElseIf ( LEqual(SLT, 0xd7) )
            {
                Notify (\_SB.PCI0.SD7, EVT)
            }
            ElseIf ( LEqual(SLT, 0xd8) )
            {
                Notify (\_SB.PCI0.SD8, EVT)
            }
            ElseIf ( LEqual(SLT, 0xd9) )
            {
                Notify (\_SB.PCI0.SD9, EVT)
            }
            ElseIf ( LEqual(SLT, 0xda) )
            {
                Notify (\_SB.PCI0.SDA, EVT)
            }
            ElseIf ( LEqual(SLT, 0xdb) )
            {
                Notify (\_SB.PCI0.SDB, EVT)
            }
            ElseIf ( LEqual(SLT, 0xdc) )
            {
                Notify (\_SB.PCI0.SDC, EVT)
            }
            ElseIf ( LEqual(SLT, 0xdd) )
            {
                Notify (\_SB.PCI0.SDD, EVT)
            }
            ElseIf ( LEqual(SLT, 0xde) )
            {
                Notify (\_SB.PCI0.SDE, EVT)
            }
            ElseIf ( LEqual(SLT, 0xdf) )
            {
                Notify (\_SB.PCI0.SDF, EVT)
            }
            ElseIf ( LEqual(SLT, 0xe0) )
            {
                Notify (\_SB.PCI0.SE0, EVT)
            }
            ElseIf ( LEqual(SLT, 0xe1) )
            {
                Notify (\_SB.PCI0.SE1, EVT)
            }
            ElseIf ( LEqual(SLT, 0xe2) )
            {
                Notify (\_SB.PCI0.SE2, EVT)
            }
            ElseIf ( LEqual(SLT, 0xe3) )
            {
                Notify (\_SB.PCI0.SE3, EVT)
            }
            ElseIf ( LEqual(SLT, 0xe4) )
            {
                Notify (\_SB.PCI0.SE4, EVT)
            }
            ElseIf ( LEqual(SLT, 0xe5) )
            {
                Notify (\_SB.PCI0.SE5, EVT)
            }
            ElseIf ( LEqual(SLT, 0xe6) )
            {
                Notify (\_SB.PCI0.SE6, EVT)
            }
            ElseIf ( LEqual(SLT, 0xe7) )
            {
                Notify (\_SB.PCI0.SE7, EVT)
            }
            ElseIf ( LEqual(SLT, 0xe8) )
            {
                Notify (\_SB.PCI0.SE8, EVT)
            }
            ElseIf ( LEqual(SLT, 0xe9) )
            {
                Notify (\_SB.PCI0.SE9, EVT)
            }
            ElseIf ( LEqual(SLT, 0xea) )
            {
                Notify (\_SB.PCI0.SEA, EVT)
            }
            ElseIf ( LEqual(SLT, 0xeb) )
            {
                Notify (\_SB.PCI0.SEB, EVT)
            }
            ElseIf ( LEqual(SLT, 0xec) )
            {
                Notify (\_SB.PCI0.SEC, EVT)
            }
            ElseIf ( LEqual(SLT, 0xed) )
            {
                Notify (\_SB.PCI0.SED, EVT)
            }
            ElseIf ( LEqual(SLT, 0xee) )
            {
                Notify (\_SB.PCI0.SEE, EVT)
            }
            ElseIf ( LEqual(SLT, 0xef) )
            {
                Notify (\_SB.PCI0.SEF, EVT)
            }
            ElseIf ( LEqual(SLT, 0xf0) )
            {
                Notify (\_SB.PCI0.SF0, EVT)
            }
            ElseIf ( LEqual(SLT, 0xf1) )
            {
                Notify (\_SB.PCI0.SF1, EVT)
            }
            ElseIf ( LEqual(SLT, 0xf2) )
            {
                Notify (\_SB.PCI0.SF2, EVT)
            }
            ElseIf ( LEqual(SLT, 0xf3) )
            {
                Notify (\_SB.PCI0.SF3, EVT)
            }
            ElseIf ( LEqual(SLT, 0xf4) )
            {
                Notify (\_SB.PCI0.SF4, EVT)
            }
            ElseIf ( LEqual(SLT, 0xf5) )
            {
                Notify (\_SB.PCI0.SF5, EVT)
            }
            ElseIf ( LEqual(SLT, 0xf6) )
            {
                Notify (\_SB.PCI0.SF6, EVT)
            }
            ElseIf ( LEqual(SLT, 0xf7) )
            {
                Notify (\_SB.PCI0.SF7, EVT)
            }
            ElseIf ( LEqual(SLT, 0xf8) )
            {
                Notify (\_SB.PCI0.SF8, EVT)
            }
            ElseIf ( LEqual(SLT, 0xf9) )
            {
                Notify (\_SB.PCI0.SF9, EVT)
            }
            ElseIf ( LEqual(SLT, 0xfa) )
            {
                Notify (\_SB.PCI0.SFA, EVT)
            }
            ElseIf ( LEqual(SLT, 0xfb) )
            {
                Notify (\_SB.PCI0.SFB, EVT)
            }
            ElseIf ( LEqual(SLT, 0xfc) )
            {
                Notify (\_SB.PCI0.SFC, EVT)
            }
            ElseIf ( LEqual(SLT, 0xfd) )
            {
                Notify (\_SB.PCI0.SFD, EVT)
            }
            ElseIf ( LEqual(SLT, 0xfe) )
            {
                Notify (\_SB.PCI0.SFE, EVT)
            }
            ElseIf ( LEqual(SLT, 0xff) )
            {
                Notify (\_SB.PCI0.SFF, EVT)
            }
        }
    }
}
