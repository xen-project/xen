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
        }
    }
}
