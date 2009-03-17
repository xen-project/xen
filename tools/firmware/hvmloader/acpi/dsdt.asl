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
            * Reserve the IO port ranges [0x10c0, 0x10c2] and [0xb044, 0xb047].
            * Or else, for a hotplugged-in device, the port IO BAR assigned
            * by guest OS may conflict with the ranges here.
            */
           Device(HP0)
           {
               Name(_HID, EISAID("PNP0C02"))
               Name(_CRS, ResourceTemplate() {
                   IO (Decode16, 0x10c0, 0x10c0, 0x00, 0x03)
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
                Name (_ADR, 0x00000000) /* Dev 0, Func 0 */
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
                    Store (0x1, \_GPE.PH00) /* eject php slot 0x00 */
                }

                Method (_STA, 0)
                {
                    Store (0x00, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    Return (\_GPE.PH00) /* IN status as the _STA */
                }
            }

            Device(S01)
            {
                Name (_ADR, 0x00010000) /* Dev 1, Func 0 */
                Name (_SUN, 0x00000001)

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
                    Store (0x1, \_GPE.PH01) /* eject php slot 0x01 */
                }

                Method (_STA, 0)
                {
                    Store (0x01, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    Return (\_GPE.PH01) /* IN status as the _STA */
                }
            }

            Device(S02)
            {
                Name (_ADR, 0x00020000) /* Dev 2, Func 0 */
                Name (_SUN, 0x00000002)

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
                    Store (0x1, \_GPE.PH02) /* eject php slot 0x02 */
                }

                Method (_STA, 0)
                {
                    Store (0x02, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    Return (\_GPE.PH02) /* IN status as the _STA */
                }
            }

            Device(S03)
            {
                Name (_ADR, 0x00030000) /* Dev 3, Func 0 */
                Name (_SUN, 0x00000003)

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
                    Store (0x1, \_GPE.PH03) /* eject php slot 0x03 */
                }

                Method (_STA, 0)
                {
                    Store (0x03, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    Return (\_GPE.PH03) /* IN status as the _STA */
                }
            }

            Device(S04)
            {
                Name (_ADR, 0x00040000) /* Dev 4, Func 0 */
                Name (_SUN, 0x00000004)

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
                    Store (0x1, \_GPE.PH04) /* eject php slot 0x04 */
                }

                Method (_STA, 0)
                {
                    Store (0x04, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    Return (\_GPE.PH04) /* IN status as the _STA */
                }
            }

            Device(S05)
            {
                Name (_ADR, 0x00050000) /* Dev 5, Func 0 */
                Name (_SUN, 0x00000005)

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
                    Store (0x1, \_GPE.PH05) /* eject php slot 0x05 */
                }

                Method (_STA, 0)
                {
                    Store (0x05, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    Return (\_GPE.PH05) /* IN status as the _STA */
                }
            }

            Device(S06)
            {
                Name (_ADR, 0x00060000) /* Dev 6, Func 0 */
                Name (_SUN, 0x00000006)

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
                    Store (0x1, \_GPE.PH06) /* eject php slot 0x06 */
                }

                Method (_STA, 0)
                {
                    Store (0x06, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    Return (\_GPE.PH06) /* IN status as the _STA */
                }
            }

            Device(S07)
            {
                Name (_ADR, 0x00070000) /* Dev 7, Func 0 */
                Name (_SUN, 0x00000007)

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
                    Store (0x1, \_GPE.PH07) /* eject php slot 0x07 */
                }

                Method (_STA, 0)
                {
                    Store (0x07, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    Return (\_GPE.PH07) /* IN status as the _STA */
                }
            }

            Device(S08)
            {
                Name (_ADR, 0x00080000) /* Dev 8, Func 0 */
                Name (_SUN, 0x00000008)

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
                    Store (0x1, \_GPE.PH08) /* eject php slot 0x08 */
                }

                Method (_STA, 0)
                {
                    Store (0x08, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    Return (\_GPE.PH08) /* IN status as the _STA */
                }
            }

            Device(S09)
            {
                Name (_ADR, 0x00090000) /* Dev 9, Func 0 */
                Name (_SUN, 0x00000009)

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
                    Store (0x1, \_GPE.PH09) /* eject php slot 0x09 */
                }

                Method (_STA, 0)
                {
                    Store (0x09, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    Return (\_GPE.PH09) /* IN status as the _STA */
                }
            }

            Device(S0A)
            {
                Name (_ADR, 0x000a0000) /* Dev 10, Func 0 */
                Name (_SUN, 0x0000000a)

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
                    Store (0x1, \_GPE.PH0A) /* eject php slot 0x0a */
                }

                Method (_STA, 0)
                {
                    Store (0x0a, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    Return (\_GPE.PH0A) /* IN status as the _STA */
                }
            }

            Device(S0B)
            {
                Name (_ADR, 0x000b0000) /* Dev 11, Func 0 */
                Name (_SUN, 0x0000000b)

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
                    Store (0x1, \_GPE.PH0B) /* eject php slot 0x0b */
                }

                Method (_STA, 0)
                {
                    Store (0x0b, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    Return (\_GPE.PH0B) /* IN status as the _STA */
                }
            }

            Device(S0C)
            {
                Name (_ADR, 0x000c0000) /* Dev 12, Func 0 */
                Name (_SUN, 0x0000000c)

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
                    Store (0x1, \_GPE.PH0C) /* eject php slot 0x0c */
                }

                Method (_STA, 0)
                {
                    Store (0x0c, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    Return (\_GPE.PH0C) /* IN status as the _STA */
                }
            }

            Device(S0D)
            {
                Name (_ADR, 0x000d0000) /* Dev 13, Func 0 */
                Name (_SUN, 0x0000000d)

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
                    Store (0x1, \_GPE.PH0D) /* eject php slot 0x0d */
                }

                Method (_STA, 0)
                {
                    Store (0x0d, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    Return (\_GPE.PH0D) /* IN status as the _STA */
                }
            }

            Device(S0E)
            {
                Name (_ADR, 0x000e0000) /* Dev 14, Func 0 */
                Name (_SUN, 0x0000000e)

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
                    Store (0x1, \_GPE.PH0E) /* eject php slot 0x0e */
                }

                Method (_STA, 0)
                {
                    Store (0x0e, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    Return (\_GPE.PH0E) /* IN status as the _STA */
                }
            }

            Device(S0F)
            {
                Name (_ADR, 0x000f0000) /* Dev 15, Func 0 */
                Name (_SUN, 0x0000000f)

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
                    Store (0x1, \_GPE.PH0F) /* eject php slot 0x0f */
                }

                Method (_STA, 0)
                {
                    Store (0x0f, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    Return (\_GPE.PH0F) /* IN status as the _STA */
                }
            }

            Device(S10)
            {
                Name (_ADR, 0x00100000) /* Dev 16, Func 0 */
                Name (_SUN, 0x00000010)

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
                    Store (0x1, \_GPE.PH10) /* eject php slot 0x10 */
                }

                Method (_STA, 0)
                {
                    Store (0x10, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    Return (\_GPE.PH10) /* IN status as the _STA */
                }
            }

            Device(S11)
            {
                Name (_ADR, 0x00110000) /* Dev 17, Func 0 */
                Name (_SUN, 0x00000011)

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
                    Store (0x1, \_GPE.PH11) /* eject php slot 0x11 */
                }

                Method (_STA, 0)
                {
                    Store (0x11, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    Return (\_GPE.PH11) /* IN status as the _STA */
                }
            }

            Device(S12)
            {
                Name (_ADR, 0x00120000) /* Dev 18, Func 0 */
                Name (_SUN, 0x00000012)

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
                    Store (0x1, \_GPE.PH12) /* eject php slot 0x12 */
                }

                Method (_STA, 0)
                {
                    Store (0x12, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    Return (\_GPE.PH12) /* IN status as the _STA */
                }
            }

            Device(S13)
            {
                Name (_ADR, 0x00130000) /* Dev 19, Func 0 */
                Name (_SUN, 0x00000013)

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
                    Store (0x1, \_GPE.PH13) /* eject php slot 0x13 */
                }

                Method (_STA, 0)
                {
                    Store (0x13, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    Return (\_GPE.PH13) /* IN status as the _STA */
                }
            }

            Device(S14)
            {
                Name (_ADR, 0x00140000) /* Dev 20, Func 0 */
                Name (_SUN, 0x00000014)

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
                    Store (0x1, \_GPE.PH14) /* eject php slot 0x14 */
                }

                Method (_STA, 0)
                {
                    Store (0x14, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    Return (\_GPE.PH14) /* IN status as the _STA */
                }
            }

            Device(S15)
            {
                Name (_ADR, 0x00150000) /* Dev 21, Func 0 */
                Name (_SUN, 0x00000015)

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
                    Store (0x1, \_GPE.PH15) /* eject php slot 0x15 */
                }

                Method (_STA, 0)
                {
                    Store (0x15, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    Return (\_GPE.PH15) /* IN status as the _STA */
                }
            }

            Device(S16)
            {
                Name (_ADR, 0x00160000) /* Dev 22, Func 0 */
                Name (_SUN, 0x00000016)

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
                    Store (0x1, \_GPE.PH16) /* eject php slot 0x16 */
                }

                Method (_STA, 0)
                {
                    Store (0x16, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    Return (\_GPE.PH16) /* IN status as the _STA */
                }
            }

            Device(S17)
            {
                Name (_ADR, 0x00170000) /* Dev 23, Func 0 */
                Name (_SUN, 0x00000017)

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
                    Store (0x1, \_GPE.PH17) /* eject php slot 0x17 */
                }

                Method (_STA, 0)
                {
                    Store (0x17, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    Return (\_GPE.PH17) /* IN status as the _STA */
                }
            }

            Device(S18)
            {
                Name (_ADR, 0x00180000) /* Dev 24, Func 0 */
                Name (_SUN, 0x00000018)

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
                    Store (0x1, \_GPE.PH18) /* eject php slot 0x18 */
                }

                Method (_STA, 0)
                {
                    Store (0x18, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    Return (\_GPE.PH18) /* IN status as the _STA */
                }
            }

            Device(S19)
            {
                Name (_ADR, 0x00190000) /* Dev 25, Func 0 */
                Name (_SUN, 0x00000019)

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
                    Store (0x1, \_GPE.PH19) /* eject php slot 0x19 */
                }

                Method (_STA, 0)
                {
                    Store (0x19, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    Return (\_GPE.PH19) /* IN status as the _STA */
                }
            }

            Device(S1A)
            {
                Name (_ADR, 0x001a0000) /* Dev 26, Func 0 */
                Name (_SUN, 0x0000001a)

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
                    Store (0x1, \_GPE.PH1A) /* eject php slot 0x1a */
                }

                Method (_STA, 0)
                {
                    Store (0x1a, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    Return (\_GPE.PH1A) /* IN status as the _STA */
                }
            }

            Device(S1B)
            {
                Name (_ADR, 0x001b0000) /* Dev 27, Func 0 */
                Name (_SUN, 0x0000001b)

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
                    Store (0x1, \_GPE.PH1B) /* eject php slot 0x1b */
                }

                Method (_STA, 0)
                {
                    Store (0x1b, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    Return (\_GPE.PH1B) /* IN status as the _STA */
                }
            }

            Device(S1C)
            {
                Name (_ADR, 0x001c0000) /* Dev 28, Func 0 */
                Name (_SUN, 0x0000001c)

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
                    Store (0x1, \_GPE.PH1C) /* eject php slot 0x1c */
                }

                Method (_STA, 0)
                {
                    Store (0x1c, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    Return (\_GPE.PH1C) /* IN status as the _STA */
                }
            }

            Device(S1D)
            {
                Name (_ADR, 0x001d0000) /* Dev 29, Func 0 */
                Name (_SUN, 0x0000001d)

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
                    Store (0x1, \_GPE.PH1D) /* eject php slot 0x1d */
                }

                Method (_STA, 0)
                {
                    Store (0x1d, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    Return (\_GPE.PH1D) /* IN status as the _STA */
                }
            }

            Device(S1E)
            {
                Name (_ADR, 0x001e0000) /* Dev 30, Func 0 */
                Name (_SUN, 0x0000001e)

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
                    Store (0x1, \_GPE.PH1E) /* eject php slot 0x1e */
                }

                Method (_STA, 0)
                {
                    Store (0x1e, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    Return (\_GPE.PH1E) /* IN status as the _STA */
                }
            }

            Device(S1F)
            {
                Name (_ADR, 0x001f0000) /* Dev 31, Func 0 */
                Name (_SUN, 0x0000001f)

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
                    Store (0x1, \_GPE.PH1F) /* eject php slot 0x1f */
                }

                Method (_STA, 0)
                {
                    Store (0x1f, \_GPE.DPT1)
                    Store (0x89, \_GPE.DPT2)
                    Return (\_GPE.PH1F) /* IN status as the _STA */
                }
            }
        }
    }

    Scope (\_GPE)
    {
        OperationRegion (PHP, SystemIO, 0x10c0, 0x22)
        Field (PHP, ByteAcc, NoLock, Preserve)
        {
            PSTA,  8, /* hotplug controller event reg */
            PSTB,  8, /* hotplug controller slot  reg */
            PH00,  8, /* hotplug slot 0x00 control reg */
            PH01,  8, /* hotplug slot 0x01 control reg */
            PH02,  8, /* hotplug slot 0x02 control reg */
            PH03,  8, /* hotplug slot 0x03 control reg */
            PH04,  8, /* hotplug slot 0x04 control reg */
            PH05,  8, /* hotplug slot 0x05 control reg */
            PH06,  8, /* hotplug slot 0x06 control reg */
            PH07,  8, /* hotplug slot 0x07 control reg */
            PH08,  8, /* hotplug slot 0x08 control reg */
            PH09,  8, /* hotplug slot 0x09 control reg */
            PH0A,  8, /* hotplug slot 0x0a control reg */
            PH0B,  8, /* hotplug slot 0x0b control reg */
            PH0C,  8, /* hotplug slot 0x0c control reg */
            PH0D,  8, /* hotplug slot 0x0d control reg */
            PH0E,  8, /* hotplug slot 0x0e control reg */
            PH0F,  8, /* hotplug slot 0x0f control reg */
            PH10,  8, /* hotplug slot 0x10 control reg */
            PH11,  8, /* hotplug slot 0x11 control reg */
            PH12,  8, /* hotplug slot 0x12 control reg */
            PH13,  8, /* hotplug slot 0x13 control reg */
            PH14,  8, /* hotplug slot 0x14 control reg */
            PH15,  8, /* hotplug slot 0x15 control reg */
            PH16,  8, /* hotplug slot 0x16 control reg */
            PH17,  8, /* hotplug slot 0x17 control reg */
            PH18,  8, /* hotplug slot 0x18 control reg */
            PH19,  8, /* hotplug slot 0x19 control reg */
            PH1A,  8, /* hotplug slot 0x1a control reg */
            PH1B,  8, /* hotplug slot 0x1b control reg */
            PH1C,  8, /* hotplug slot 0x1c control reg */
            PH1D,  8, /* hotplug slot 0x1d control reg */
            PH1E,  8, /* hotplug slot 0x1e control reg */
            PH1F,  8  /* hotplug slot 0x1f control reg */
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

            Switch (SLT)
            {
                Case (0x00) {
                    Notify (\_SB.PCI0.S00, EVT)
                }
                Case (0x01) {
                    Notify (\_SB.PCI0.S01, EVT)
                }
                Case (0x02) {
                    Notify (\_SB.PCI0.S02, EVT)
                }
                Case (0x03) {
                    Notify (\_SB.PCI0.S03, EVT)
                }
                Case (0x04) {
                    Notify (\_SB.PCI0.S04, EVT)
                }
                Case (0x05) {
                    Notify (\_SB.PCI0.S05, EVT)
                }
                Case (0x06) {
                    Notify (\_SB.PCI0.S06, EVT)
                }
                Case (0x07) {
                    Notify (\_SB.PCI0.S07, EVT)
                }
                Case (0x08) {
                    Notify (\_SB.PCI0.S08, EVT)
                }
                Case (0x09) {
                    Notify (\_SB.PCI0.S09, EVT)
                }
                Case (0x0a) {
                    Notify (\_SB.PCI0.S0A, EVT)
                }
                Case (0x0b) {
                    Notify (\_SB.PCI0.S0B, EVT)
                }
                Case (0x0c) {
                    Notify (\_SB.PCI0.S0C, EVT)
                }
                Case (0x0d) {
                    Notify (\_SB.PCI0.S0D, EVT)
                }
                Case (0x0e) {
                    Notify (\_SB.PCI0.S0E, EVT)
                }
                Case (0x0f) {
                    Notify (\_SB.PCI0.S0F, EVT)
                }
                Case (0x10) {
                    Notify (\_SB.PCI0.S10, EVT)
                }
                Case (0x11) {
                    Notify (\_SB.PCI0.S11, EVT)
                }
                Case (0x12) {
                    Notify (\_SB.PCI0.S12, EVT)
                }
                Case (0x13) {
                    Notify (\_SB.PCI0.S13, EVT)
                }
                Case (0x14) {
                    Notify (\_SB.PCI0.S14, EVT)
                }
                Case (0x15) {
                    Notify (\_SB.PCI0.S15, EVT)
                }
                Case (0x16) {
                    Notify (\_SB.PCI0.S16, EVT)
                }
                Case (0x17) {
                    Notify (\_SB.PCI0.S17, EVT)
                }
                Case (0x18) {
                    Notify (\_SB.PCI0.S18, EVT)
                }
                Case (0x19) {
                    Notify (\_SB.PCI0.S19, EVT)
                }
                Case (0x1a) {
                    Notify (\_SB.PCI0.S1A, EVT)
                }
                Case (0x1b) {
                    Notify (\_SB.PCI0.S1B, EVT)
                }
                Case (0x1c) {
                    Notify (\_SB.PCI0.S1C, EVT)
                }
                Case (0x1d) {
                    Notify (\_SB.PCI0.S1D, EVT)
                }
                Case (0x1e) {
                    Notify (\_SB.PCI0.S1E, EVT)
                }
                Case (0x1f) {
                    Notify (\_SB.PCI0.S1F, EVT)
                }
            }
        }
    }
}
